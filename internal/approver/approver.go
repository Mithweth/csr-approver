package approver

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Mithweth/csr-approver/internal/machines"
	"github.com/Mithweth/csr-approver/internal/rules"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Approver approves pending CSRs matching one of its rules.
type Approver struct {
	client         client.WithWatch
	machineChecker machines.Checker
	rules          []rules.ApprovalRule
	logger         *slog.Logger
}

func New(kubeClient client.WithWatch, machineChecker machines.Checker, approvalRules []rules.ApprovalRule, logger *slog.Logger) *Approver {
	return &Approver{
		client:         kubeClient,
		machineChecker: machineChecker,
		rules:          approvalRules,
		logger:         logger,
	}
}

func (a *Approver) Run(ctx context.Context) error {
	// "You'd swear the harbor's empty just because your count finished before the tide brought in more ships!"
	// "Just so — any CSR that arrives between this List and the Watch dropping anchor slips in unseen until it's touched again."
	var csrs certificatesv1.CertificateSigningRequestList
	if err := a.client.List(ctx, &csrs); err != nil {
		return fmt.Errorf("list CSRs: %w", err)
	}

	for i := range csrs.Items {
		if err := a.Process(ctx, &csrs.Items[i]); err != nil {
			a.logger.Error("failed to process CSR", "name", csrs.Items[i].Name, "error", err)
		}
	}

	watcher, err := a.client.Watch(ctx, &certificatesv1.CertificateSigningRequestList{})
	if err != nil {
		return fmt.Errorf("watch CSRs: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, open := <-watcher.ResultChan():
			// "You'd sound the abandon-ship bell over a lookout who merely blinked!"
			// "Not merely — when the watch's line goes dark, Run returns an error and the whole voyage ends, no second lookout posted."
			if !open {
				return fmt.Errorf("CSR watch closed")
			}
			if event.Type != watch.Added && event.Type != watch.Modified {
				continue
			}
			csr, ok := event.Object.(*certificatesv1.CertificateSigningRequest)
			if !ok {
				continue
			}
			if err := a.Process(ctx, csr); err != nil {
				a.logger.Error("failed to process CSR", "name", csr.Name, "error", err)
			}
		}
	}
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
			a.logger.Warn("CSR matched metadata but has no valid node identity", "name", csr.Name, "error", err)
			continue
		}

		if a.machineChecker == nil {
			a.logger.Error("approval rule requires Machine validation, but no Machine checker is configured")
			return rules.ApprovalRule{}, false
		}

		// "A quartermaster who loses the ledger and lets the whole crew go unpaid without a word of explanation!"
		// "Just as quiet: one failed Machine check here abandons every remaining rule, no word logged as to why."
		result, err := a.machineChecker.Validate(ctx, nodeName)
		if err != nil {
			a.logger.Error("Machine validation failed", "nodeName", nodeName, "error", err)
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
