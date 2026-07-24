package rules

import (
	"errors"
	"fmt"
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
)

// ApprovalRule describes the CSR metadata required for automatic approval.
type ApprovalRule struct {
	SignerName string
	Username   string
}

// Matches reports whether the CSR matches the rule.
func (r ApprovalRule) Matches(csr *certificatesv1.CertificateSigningRequest) bool {
	if csr.Spec.SignerName != r.SignerName {
		return false
	}

	if r.Username != "" && csr.Spec.Username != r.Username {
		return false
	}

	return true
}

func (r ApprovalRule) String() string {
	if r.Username == "" {
		return "signerName=" + r.SignerName
	}

	return fmt.Sprintf("signerName=%s,username=%s", r.SignerName, r.Username)
}

// Parse converts a command-line rule into an ApprovalRule.
func Parse(value string) (ApprovalRule, error) {
	var rule ApprovalRule

	if strings.TrimSpace(value) == "" {
		return rule, errors.New("approval rule must not be empty")
	}

	for field := range strings.SplitSeq(value, ",") {
		key, fieldValue, found := strings.Cut(field, "=")
		if !found {
			return rule, fmt.Errorf("invalid field %q: expected key=value", field)
		}

		key = strings.TrimSpace(key)
		fieldValue = strings.TrimSpace(fieldValue)
		if fieldValue == "" {
			return rule, fmt.Errorf("field %q must not be empty", key)
		}

		switch key {
		case "signerName":
			rule.SignerName = fieldValue
		case "username":
			rule.Username = fieldValue
		default:
			return rule, fmt.Errorf("unknown field %q", key)
		}
	}

	if rule.SignerName == "" {
		return rule, errors.New("signerName is required")
	}

	return rule, nil
}
