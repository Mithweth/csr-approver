package config

import (
	"errors"
	"github.com/spf13/pflag"
	"io"

	"github.com/Mithweth/csr-approver/internal/rules"
)

// Config contains the application command-line configuration.
type Config struct {
	Kubeconfig    string
	ApprovalRules []rules.ApprovalRule
}

// Parse reads the application's command-line flags.
func Parse(args []string, output io.Writer) (Config, error) {
	var (
		config             Config
		approvalRules      []rules.ApprovalRule
		approvalRuleValues []string
	)
	flags := pflag.NewFlagSet("csr-approver", pflag.ContinueOnError)
	flags.SetOutput(output)

	flags.StringVar(
		&config.Kubeconfig,
		"kubeconfig",
		"",
		"path to a kubeconfig file; defaults to KUBECONFIG, then ~/.kube/config, then in-cluster configuration",
	)
	flags.StringArrayVar(
		&approvalRuleValues,
		"approval-rule",
		nil,
		"CSR approval rule; repeatable; format: signerName=<name>[,username=<name>]",
	)

	if err := flags.Parse(args); err != nil {
		return config, err
	}
	for _, value := range approvalRuleValues {
		rule, err := rules.Parse(value)
		if err != nil {
			return config, err
		}
		approvalRules = append(approvalRules, rule)
	}
	if len(approvalRules) == 0 {
		return config, errors.New("at least one --approval-rule is required")
	}

	config.ApprovalRules = approvalRules
	return config, nil
}
