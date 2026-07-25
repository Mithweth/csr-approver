package approver

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Mithweth/csr-approver/internal/rules"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

// Approver approves pending CSRs matching one of its rules.
type Approver struct {
	client kubernetes.Interface
	rules  []rules.ApprovalRule
	logger *slog.Logger
}

func New(client kubernetes.Interface, approvalRules []rules.ApprovalRule, logger *slog.Logger) *Approver {
	return &Approver{client: client, rules: approvalRules, logger: logger}
}

func (a *Approver) Run(ctx context.Context) error {
	csrs, err := a.client.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list CSRs: %w", err)
	}

	for i := range csrs.Items {
		if err := a.Process(ctx, &csrs.Items[i]); err != nil {
			a.logger.Error("failed to process CSR", "name", csrs.Items[i].Name, "error", err)
		}
	}

	watcher, err := a.client.CertificatesV1().CertificateSigningRequests().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch CSRs: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case event, open := <-watcher.ResultChan():
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

	rule, found := a.matchingRule(csr)
	if !found {
		return nil
	}

	return a.approve(ctx, csr, rule)
}

func isPending(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, condition := range csr.Status.Conditions {
		// certificatesv1.CertificatePending does not exist
		if condition.Type == certificatesv1.CertificateApproved || condition.Type == certificatesv1.CertificateDenied {
			return false
		}
	}

	return true
}

func (a *Approver) matchingRule(csr *certificatesv1.CertificateSigningRequest) (rules.ApprovalRule, bool) {
	for _, rule := range a.rules {
		if rule.Matches(csr) {
			return rule, true
		}
	}

	return rules.ApprovalRule{}, false
}

func (a *Approver) approve(ctx context.Context, csr *certificatesv1.CertificateSigningRequest, rule rules.ApprovalRule) error {
	updatedCSR := csr.DeepCopy()
	now := metav1.Now()

	updatedCSR.Status.Conditions = append(
		updatedCSR.Status.Conditions,
		certificatesv1.CertificateSigningRequestCondition{
			Type:               certificatesv1.CertificateApproved,
			Status:             corev1.ConditionTrue,
			Reason:             "ApprovedByRule",
			Message:            "CSR matched approval rule: " + rule.String(),
			LastUpdateTime:     now,
			LastTransitionTime: now,
		},
	)

	_, err := a.client.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, updatedCSR.Name, updatedCSR, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("approve CSR %q: %w", csr.Name, err)
	}

	a.logger.Info("CSR approved", "name", csr.Name, "signerName", csr.Spec.SignerName, "username", csr.Spec.Username)

	return nil
}
