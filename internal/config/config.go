package config

import (
	"errors"
	"github.com/Mithweth/csr-approver/internal/rules"
	"github.com/spf13/pflag"
	"os"
)

// Config contains the application command-line configuration.
type Config struct {
	Kubeconfig              string
	ApprovalRules           []rules.ApprovalRule
	LeaderElectionNamespace string
	LeaderElection          bool
	LeaderElectionLeaseName string
}

// Parse reads the application's command-line flags.
func Parse() (Config, error) {
	var (
		config             Config
		approvalRules      []rules.ApprovalRule
		approvalRuleValues []string
	)
	flags := pflag.NewFlagSet("csr-approver", pflag.ContinueOnError)
	flags.SetOutput(os.Stderr)

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
	flags.BoolVar(
		&config.LeaderElection,
		"leader-elect",
		false,
		"Enable leader election",
	)
	flags.StringVar(
		&config.LeaderElectionNamespace,
		"leader-election-namespace",
		"",
		"Namespace where runs the leader election",
	)
	flags.StringVar(
		&config.LeaderElectionLeaseName,
		"leader-election-lease-name",
		"csr-approver",
		"Lease name for the leader election",
	)
	if err := flags.Parse(os.Args[1:]); err != nil {
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
	if config.LeaderElection && config.LeaderElectionNamespace == "" {
		return config, errors.New("leader-election-namespace is mandatory when leader-elect is true")
	}

	config.ApprovalRules = approvalRules
	return config, nil
}
