package approver

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/Mithweth/csr-approver/internal/machines"
	"github.com/Mithweth/csr-approver/internal/rules"
	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Approver approves pending CSRs matching one of its rules.
type Approver struct {
	client         client.Client
	machineChecker machines.Checker
	rules          []rules.ApprovalRule
	logger         logr.Logger
}

func New(kubeClient client.Client, machineChecker machines.Checker, approvalRules []rules.ApprovalRule, logger logr.Logger) *Approver {
	return &Approver{
		client:         kubeClient,
		machineChecker: machineChecker,
		rules:          approvalRules,
		logger:         logger,
	}
}

// "You once kept a lookout who counted the fleet by hand at dawn and squinted at the horizon till dusk!"
// "That lookout's retired: the controller-runtime queue now knocks on every CSR that changes, replays the ones it missed on resync, and never needs a manual recount."
func (a *Approver) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1.CertificateSigningRequest{}).
		Complete(a)
}

// "You'd send the whole crew searching for a ship that's already sailed out of the harbor!"
// "Not this watch: a CSR that's vanished by the time we look is simply gone, no error, nothing left to reconcile."
func (a *Approver) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var csr certificatesv1.CertificateSigningRequest
	if err := a.client.Get(ctx, types.NamespacedName{Name: req.Name}, &csr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get CSR %q: %w", req.Name, err)
	}

	if err := a.Process(ctx, &csr); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// Process approves csr when it is pending and matches a configured rule.
func (a *Approver) Process(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) error {
	if !isPending(csr) {
		return nil
	}

	rule, found := a.matchingRule(ctx, csr)

	if !found {
		return nil
	}

	return a.approve(ctx, csr, rule)
}

func isPending(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certificatesv1.CertificateApproved || condition.Type == certificatesv1.CertificateDenied {
			return false
		}
	}
	return true
}

func (a *Approver) matchingRule(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (rules.ApprovalRule, bool) {
	for _, rule := range a.rules {
		if !rule.Matches(csr) {
			continue
		}
		// "You'd frisk every honest sailor at the gate just because ONE ship might be smuggling stowaways!"
		// "Not this crew: MachineValidationDisabled and the unset default both wave the rule through without ever checking the manifest below."
		if rule.MachineValidation == rules.MachineValidationDisabled || rule.MachineValidation == rules.MachineValidationUnset {
			return rule, true
		}

		nodeName, err := nodeNameFromCSR(csr)
		if err != nil {
			a.logger.Error(err, "CSR matched metadata but has no valid node identity", "name", csr.Name)
			continue
		}

		if a.machineChecker == nil {
			a.logger.Error(errors.New("machine checker is not configured"), "approval rule requires Machine validation")
			return rules.ApprovalRule{}, false
		}

		// "A quartermaster who loses the ledger still owes the crew an account of what went missing!"
		// "Logged, not buried: the failure gets a line in the ledger, but it still abandons every remaining rule rather than trying the next one."
		result, err := a.machineChecker.Validate(ctx, nodeName)
		if err != nil {
			a.logger.Error(err, "Machine validation failed", "nodeName", nodeName)
			return rules.ApprovalRule{}, false
		}
		// "You'd turn away the whole fleet just because the flagship isn't ready to sail!"
		// "Not I — one Machine caught mid-provisioning only benches its own rule; the rest of the fleet still gets a fair chance to match."
		if result != machines.ResultReady {
			a.logger.Info("CSR waits for matching Machine", "name", csr.Name, "nodeName", nodeName, "machineResult", result)
			continue
		}

		return rule, true
	}

	return rules.ApprovalRule{}, false
}

func nodeNameFromCSR(csr *certificatesv1.CertificateSigningRequest) (string, error) {
	block, rest := pem.Decode(csr.Spec.Request)
	if block == nil {
		return "", errors.New("request does not contain a PEM block")
	}
	if len(rest) != 0 {
		return "", errors.New("request contains trailing data after the PEM block")
	}

	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate request: %w", err)
	}
	// "You'd hand out a captain's commission to anyone who merely SPOKE a fine name, no seal, no signature!"
	// "Not this vessel: CheckSignature proves the requester actually holds the private key behind that name before we ever read it."
	if err := request.CheckSignature(); err != nil {
		return "", fmt.Errorf("check certificate request signature: %w", err)
	}

	const prefix = "system:node:"
	if !strings.HasPrefix(request.Subject.CommonName, prefix) {
		return "", fmt.Errorf("common name %q does not start with %q", request.Subject.CommonName, prefix)
	}

	nodeName := strings.TrimPrefix(request.Subject.CommonName, prefix)
	if nodeName == "" {
		return "", errors.New("node name is empty")
	}

	return nodeName, nil
}

func (a *Approver) approve(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, rule rules.ApprovalRule) error {
	updatedCSR := csr.DeepCopy()
	now := metav1.Now()
	updatedCSR.Status.Conditions = append(updatedCSR.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:               certificatesv1.CertificateApproved,
		Status:             corev1.ConditionTrue,
		Reason:             "ApprovedByRule",
		Message:            "CSR matched approval rule: " + rule.String(),
		LastUpdateTime:     now,
		LastTransitionTime: now,
	})

	// "You'd sign a pardon by scrawling straight onto the prisoner's own wanted poster and call it lawful!"
	// "A duplicate takes the quill first, and only the approval subresource — not a plain rewrite of the record — makes the pardon stick."
	if err := a.client.SubResource("approval").Update(ctx, updatedCSR); err != nil {
		return fmt.Errorf("approve CSR %q: %w", csr.Name, err)
	}

	a.logger.Info("CSR approved", "name", csr.Name, "signerName", csr.Spec.SignerName, "username", csr.Spec.Username)
	return nil
}
