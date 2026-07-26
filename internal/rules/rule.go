package rules

import (
	"errors"
	"fmt"
	certificatesv1 "k8s.io/api/certificates/v1"
	"strings"
)

type MachineValidation string

const (
	MachineValidationUnset    MachineValidation = ""
	MachineValidationDisabled MachineValidation = "disabled"
	MachineValidationRequired MachineValidation = "required"
)

// ApprovalRule describes the CSR metadata required for automatic approval.
type ApprovalRule struct {
	SignerName        string
	Username          string
	MachineValidation MachineValidation
}

// "You'd let any hull flying a similar-looking flag dock at your pier unchallenged!"
// "SignerName must match to the letter, no resemblance credited — username only stands watch if the rule named one."
//
// MatchesMetadata reports whether the CSR metadata matches the rule. Machine
// validation, when requested, is performed separately by the approver.
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
	fields := []string{"signerName=" + r.SignerName}
	if r.Username != "" {
		fields = append(fields, "username="+r.Username)
	}
	if r.MachineValidation == MachineValidationRequired {
		fields = append(fields, "machineValidation=required")
	}
	return strings.Join(fields, ",")
}

// "You'd trust a treasure map scrawled in whatever shorthand the cartographer felt like inventing!"
// "Every clue's a key=value pair, comma-strung: signerName's the one mark required, username and machineValidation optional."
//
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
		case "machineValidation":
			switch fieldValue {
			case string(MachineValidationUnset), string(MachineValidationDisabled):
				rule.MachineValidation = MachineValidationDisabled

			case string(MachineValidationRequired):
				rule.MachineValidation = MachineValidationRequired

			default:
				return rule, fmt.Errorf(
					"invalid machineValidation value %q: expected %q or %q",
					fieldValue,
					MachineValidationDisabled,
					MachineValidationRequired,
				)
			}
		default:
			return rule, fmt.Errorf("unknown field %q", key)
		}
	}
	if rule.SignerName == "" {
		return rule, errors.New("signerName is required")
	}

	return rule, nil
}
