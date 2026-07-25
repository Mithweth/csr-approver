package approver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/Mithweth/csr-approver/internal/rules"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCSR(name, signerName, username string, conditions ...certificatesv1.CertificateSigningRequestCondition) *certificatesv1.CertificateSigningRequest {
	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			SignerName: signerName,
			Username:   username,
		},
		Status: certificatesv1.CertificateSigningRequestStatus{
			Conditions: conditions,
		},
	}
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
		{
			name: "no conditions",
			csr:  newCSR("csr", "example.com/foo", "alice"),
			want: true,
		},
		{
			name: "approved",
			csr: newCSR("csr", "example.com/foo", "alice", certificatesv1.CertificateSigningRequestCondition{
				Type: certificatesv1.CertificateApproved,
			}),
			want: false,
		},
		{
			name: "denied",
			csr: newCSR("csr", "example.com/foo", "alice", certificatesv1.CertificateSigningRequestCondition{
				Type: certificatesv1.CertificateDenied,
			}),
			want: false,
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
	rule1 := rules.ApprovalRule{SignerName: "example.com/foo"}
	rule2 := rules.ApprovalRule{SignerName: "example.com/bar", Username: "alice"}
	a := New(fake.NewSimpleClientset(), []rules.ApprovalRule{rule1, rule2}, discardLogger())

	tests := []struct {
		name      string
		csr       *certificatesv1.CertificateSigningRequest
		wantRule  rules.ApprovalRule
		wantFound bool
	}{
		{
			name:      "matches first rule",
			csr:       newCSR("csr", "example.com/foo", "anyone"),
			wantRule:  rule1,
			wantFound: true,
		},
		{
			name:      "matches second rule",
			csr:       newCSR("csr", "example.com/bar", "alice"),
			wantRule:  rule2,
			wantFound: true,
		},
		{
			name:      "no match",
			csr:       newCSR("csr", "example.com/baz", "alice"),
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRule, gotFound := a.matchingRule(tt.csr)
			if gotFound != tt.wantFound {
				t.Fatalf("matchingRule() found = %v; want %v", gotFound, tt.wantFound)
			}
			if gotFound && gotRule != tt.wantRule {
				t.Fatalf("matchingRule() rule = %+v; want %+v", gotRule, tt.wantRule)
			}
		})
	}
}

func TestApprover_Process(t *testing.T) {
	rule := rules.ApprovalRule{SignerName: "example.com/foo"}

	t.Run("approves a pending, matching CSR", func(t *testing.T) {
		csr := newCSR("csr-1", "example.com/foo", "alice")
		client := fake.NewSimpleClientset(csr)
		a := New(client, []rules.ApprovalRule{rule}, discardLogger())

		if err := a.Process(context.Background(), csr); err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}

		updated, err := client.CertificatesV1().CertificateSigningRequests().Get(context.Background(), "csr-1", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if !hasApprovedCondition(updated) {
			t.Errorf("CSR %q was not approved: %+v", updated.Name, updated.Status.Conditions)
		}
	})

	t.Run("ignores a CSR that does not match any rule", func(t *testing.T) {
		csr := newCSR("csr-2", "example.com/other", "alice")
		client := fake.NewSimpleClientset(csr)
		a := New(client, []rules.ApprovalRule{rule}, discardLogger())

		if err := a.Process(context.Background(), csr); err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}

		updated, err := client.CertificatesV1().CertificateSigningRequests().Get(context.Background(), "csr-2", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if hasApprovedCondition(updated) {
			t.Errorf("CSR %q was unexpectedly approved", updated.Name)
		}
	})

	t.Run("ignores a CSR that is already approved", func(t *testing.T) {
		csr := newCSR("csr-3", "example.com/foo", "alice", certificatesv1.CertificateSigningRequestCondition{
			Type: certificatesv1.CertificateApproved,
		})
		client := fake.NewSimpleClientset(csr)
		client.PrependReactor("update", "certificatesigningrequests", func(clienttesting.Action) (bool, runtime.Object, error) {
			t.Fatal("unexpected update call for an already-approved CSR")
			return false, nil, nil
		})
		a := New(client, []rules.ApprovalRule{rule}, discardLogger())

		if err := a.Process(context.Background(), csr); err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}
	})

	t.Run("ignores a CSR that is already denied", func(t *testing.T) {
		csr := newCSR("csr-4", "example.com/foo", "alice", certificatesv1.CertificateSigningRequestCondition{
			Type: certificatesv1.CertificateDenied,
		})
		client := fake.NewSimpleClientset(csr)
		a := New(client, []rules.ApprovalRule{rule}, discardLogger())

		if err := a.Process(context.Background(), csr); err != nil {
			t.Fatalf("Process() unexpected error: %v", err)
		}

		updated, err := client.CertificatesV1().CertificateSigningRequests().Get(context.Background(), "csr-4", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Get() unexpected error: %v", err)
		}
		if hasApprovedCondition(updated) {
			t.Errorf("CSR %q was unexpectedly approved", updated.Name)
		}
	})

	t.Run("propagates the error when approval fails", func(t *testing.T) {
		csr := newCSR("csr-5", "example.com/foo", "alice")
		client := fake.NewSimpleClientset(csr)
		client.PrependReactor("update", "certificatesigningrequests", func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("boom")
		})
		a := New(client, []rules.ApprovalRule{rule}, discardLogger())

		err := a.Process(context.Background(), csr)
		if err == nil {
			t.Fatal("Process() = nil error; want error")
		}
	})
}
