package approver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/Mithweth/csr-approver/internal/machines"
	"github.com/Mithweth/csr-approver/internal/rules"
	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func discardLogger() logr.Logger {
	return logr.Discard()
}

func newRecorder() *events.FakeRecorder {
	return events.NewFakeRecorder(10)
}

func newCSR(name, signerName, username string, conditions ...certificatesv1.CertificateSigningRequestCondition) *certificatesv1.CertificateSigningRequest {
	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			SignerName: signerName,
			Username:   username,
		},
		Status: certificatesv1.CertificateSigningRequestStatus{Conditions: conditions},
	}
}

func setCSRCommonName(t *testing.T, csr *certificatesv1.CertificateSigningRequest, commonName string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}},
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	csr.Spec.Request = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})
}

func newFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(&certificatesv1.CertificateSigningRequest{}).
		Build()
}

type fakeMachineChecker struct {
	result machines.Result
	err    error
}

func (f fakeMachineChecker) Validate(context.Context, string) (machines.Result, error) {
	return f.result, f.err
}

func hasApprovedCondition(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certificatesv1.CertificateApproved {
			return true
		}
	}
	return false
}

func TestIsPending(t *testing.T) {
	tests := []struct {
		name string
		csr  *certificatesv1.CertificateSigningRequest
		want bool
	}{
		{name: "no conditions", csr: newCSR("csr", "example.com/foo", "alice"), want: true},
		{
			name: "approved",
			csr: newCSR("csr", "example.com/foo", "alice", certificatesv1.CertificateSigningRequestCondition{
				Type: certificatesv1.CertificateApproved,
			}),
		},
		{
			name: "denied",
			csr: newCSR("csr", "example.com/foo", "alice", certificatesv1.CertificateSigningRequestCondition{
				Type: certificatesv1.CertificateDenied,
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPending(tt.csr); got != tt.want {
				t.Errorf("isPending() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestApprover_MatchingRule(t *testing.T) {
	rule1 := rules.ApprovalRule{SignerName: "example.com/foo", MachineValidation: rules.ValidationValueDisabled}
	rule2 := rules.ApprovalRule{SignerName: "example.com/bar", Username: "alice", MachineValidation: rules.ValidationValueDisabled}
	a := New(newFakeClient(t), nil, []rules.ApprovalRule{rule1, rule2}, newRecorder(), discardLogger())

	tests := []struct {
		name      string
		csr       *certificatesv1.CertificateSigningRequest
		wantRule  rules.ApprovalRule
		wantFound bool
	}{
		{name: "matches first rule", csr: newCSR("csr", "example.com/foo", "anyone"), wantRule: rule1, wantFound: true},
		{name: "matches second rule", csr: newCSR("csr", "example.com/bar", "alice"), wantRule: rule2, wantFound: true},
		{name: "no match", csr: newCSR("csr", "example.com/baz", "alice")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRule, gotFound, gotWaiting := a.matchingRule(context.Background(), tt.csr)
			if gotFound != tt.wantFound {
				t.Fatalf("matchingRule() found = %v; want %v", gotFound, tt.wantFound)
			}
			if gotWaiting {
				t.Fatalf("matchingRule() waiting = true; want false")
			}
			if gotFound && gotRule != tt.wantRule {
				t.Fatalf("matchingRule() rule = %+v; want %+v", gotRule, tt.wantRule)
			}
		})
	}
}

// Regression test for a reported bug: ValidationValue's zero value ("")
// is not equal to ValidationValueDisabled ("disabled"), so a rule that
// never sets MachineValidation/CommonNameValidation must still behave as
// if both were disabled, rather than requiring validation.
func TestApprover_MatchingRule_UnsetValidationDefaultsToDisabled(t *testing.T) {
	rule := rules.ApprovalRule{SignerName: "example.com/foo"}
	a := New(newFakeClient(t), nil, []rules.ApprovalRule{rule}, newRecorder(), discardLogger())

	csr := newCSR("csr", "example.com/foo", "anyone")

	gotRule, gotFound, gotWaiting := a.matchingRule(context.Background(), csr)
	if !gotFound {
		t.Fatalf("matchingRule() found = false; want true (unset validation should behave like %q)", rules.ValidationValueDisabled)
	}
	if gotWaiting {
		t.Fatalf("matchingRule() waiting = true; want false")
	}
	if gotRule != rule {
		t.Fatalf("matchingRule() rule = %+v; want %+v", gotRule, rule)
	}
}

func TestApprover_Process(t *testing.T) {
	rule := rules.ApprovalRule{SignerName: "example.com/foo", MachineValidation: rules.ValidationValueDisabled}

	t.Run("approves a pending matching CSR", func(t *testing.T) {
		csr := newCSR("csr-1", "example.com/foo", "alice")
		kubeClient := newFakeClient(t, csr)
		recorder := newRecorder()
		a := New(kubeClient, nil, []rules.ApprovalRule{rule}, recorder, discardLogger())

		result, err := a.Process(context.Background(), csr)
		if err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}
		if result != ProcessDone {
			t.Fatalf("Process() result = %v; want ProcessDone", result)
		}

		var updated certificatesv1.CertificateSigningRequest
		if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: csr.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if !hasApprovedCondition(&updated) {
			t.Fatalf("CSR %q was not approved", updated.Name)
		}

		select {
		case event := <-recorder.Events:
			if !strings.Contains(event, "Approved") {
				t.Fatalf("recorded event = %q; want it to mention Approved", event)
			}
		default:
			t.Fatal("expected an Approved event to be recorded")
		}
	})

	t.Run("ignores a CSR that does not match", func(t *testing.T) {
		csr := newCSR("csr-2", "example.com/other", "alice")
		kubeClient := newFakeClient(t, csr)
		a := New(kubeClient, nil, []rules.ApprovalRule{rule}, newRecorder(), discardLogger())

		result, err := a.Process(context.Background(), csr)
		if err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}
		if result != ProcessDone {
			t.Fatalf("Process() result = %v; want ProcessDone", result)
		}

		var updated certificatesv1.CertificateSigningRequest
		if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: csr.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if hasApprovedCondition(&updated) {
			t.Fatalf("CSR %q was unexpectedly approved", updated.Name)
		}
	})

	t.Run("approves when the required Machine is ready", func(t *testing.T) {
		machineRule := rules.ApprovalRule{SignerName: "example.com/foo", MachineValidation: rules.ValidationValueRequired}
		csr := newCSR("csr-machine", "example.com/foo", "alice")
		setCSRCommonName(t, csr, "system:node:worker-1")
		kubeClient := newFakeClient(t, csr)
		a := New(
			kubeClient,
			fakeMachineChecker{result: machines.ResultReady},
			[]rules.ApprovalRule{machineRule},
			newRecorder(),
			discardLogger(),
		)

		result, err := a.Process(context.Background(), csr)
		if err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}
		if result != ProcessDone {
			t.Fatalf("Process() result = %v; want ProcessDone", result)
		}

		var updated certificatesv1.CertificateSigningRequest
		if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: csr.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if !hasApprovedCondition(&updated) {
			t.Fatal("CSR was not approved")
		}
	})

	t.Run("waits when the required Machine is absent", func(t *testing.T) {
		machineRule := rules.ApprovalRule{SignerName: "example.com/foo", MachineValidation: rules.ValidationValueRequired}
		csr := newCSR("csr-no-machine", "example.com/foo", "alice")
		setCSRCommonName(t, csr, "system:node:worker-1")
		kubeClient := newFakeClient(t, csr)
		a := New(
			kubeClient,
			fakeMachineChecker{result: machines.ResultNotFound},
			[]rules.ApprovalRule{machineRule},
			newRecorder(),
			discardLogger(),
		)

		result, err := a.Process(context.Background(), csr)
		if err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}
		if result != ProcessWaiting {
			t.Fatalf("Process() result = %v; want ProcessWaiting", result)
		}

		var updated certificatesv1.CertificateSigningRequest
		if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: csr.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if hasApprovedCondition(&updated) {
			t.Fatal("CSR was unexpectedly approved")
		}
	})

	t.Run("approves when the common name matches the username", func(t *testing.T) {
		commonNameRule := rules.ApprovalRule{SignerName: "example.com/foo", CommonNameValidation: rules.ValidationValueRequired}
		csr := newCSR("csr-cn-match", "example.com/foo", "system:node:worker-1")
		setCSRCommonName(t, csr, "system:node:worker-1")
		kubeClient := newFakeClient(t, csr)
		a := New(kubeClient, nil, []rules.ApprovalRule{commonNameRule}, newRecorder(), discardLogger())

		result, err := a.Process(context.Background(), csr)
		if err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}
		if result != ProcessDone {
			t.Fatalf("Process() result = %v; want ProcessDone", result)
		}

		var updated certificatesv1.CertificateSigningRequest
		if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: csr.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if !hasApprovedCondition(&updated) {
			t.Fatal("CSR was not approved")
		}
	})

	t.Run("rejects when the common name does not match the username", func(t *testing.T) {
		commonNameRule := rules.ApprovalRule{SignerName: "example.com/foo", CommonNameValidation: rules.ValidationValueRequired}
		csr := newCSR("csr-cn-mismatch", "example.com/foo", "alice")
		setCSRCommonName(t, csr, "system:node:worker-1")
		kubeClient := newFakeClient(t, csr)
		a := New(kubeClient, nil, []rules.ApprovalRule{commonNameRule}, newRecorder(), discardLogger())

		result, err := a.Process(context.Background(), csr)
		if err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}
		if result != ProcessDone {
			t.Fatalf("Process() result = %v; want ProcessDone", result)
		}

		var updated certificatesv1.CertificateSigningRequest
		if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: csr.Name}, &updated); err != nil {
			t.Fatal(err)
		}
		if hasApprovedCondition(&updated) {
			t.Fatal("CSR was unexpectedly approved")
		}
	})
}

func TestApprover_Reconcile(t *testing.T) {
	rule := rules.ApprovalRule{SignerName: "example.com/foo", MachineValidation: rules.ValidationValueDisabled}
	csr := newCSR("csr-reconcile", "example.com/foo", "alice")
	kubeClient := newFakeClient(t, csr)
	a := New(kubeClient, nil, []rules.ApprovalRule{rule}, newRecorder(), discardLogger())

	_, err := a.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: csr.Name},
	})
	if err != nil {
		t.Fatalf("Reconcile() unexpected error: %v", err)
	}

	var updated certificatesv1.CertificateSigningRequest
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: csr.Name}, &updated); err != nil {
		t.Fatal(err)
	}
	if !hasApprovedCondition(&updated) {
		t.Fatalf("CSR %q was not approved", updated.Name)
	}

	_, err = a.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing"},
	})
	if err != nil {
		t.Fatalf("Reconcile() missing object error = %v; want nil", err)
	}
}
