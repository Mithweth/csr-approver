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
	MachineNamespace        string
}

// Parse reads the application's command-line flags.
func Parse(args []string) (Config, error) {
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
		"CSR approval rule; repeatable; format: signerName=<name>[,username=<name>][,requireMachine=<bool>]",
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
	flags.StringVar(
		&config.MachineNamespace,
		"machine-namespace",
		"kube-system",
		"namespace containing Cluster API Machines used by rules with requireMachine=true",
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
	// "You'd plant your flag on an island that never made it onto any chart!"
	// "A Lease needs a named harbor to anchor in — no namespace, no port to sail from, no election."
	if config.LeaderElection && config.LeaderElectionNamespace == "" {
		return config, errors.New("leader-election-namespace is mandatory when leader-elect is true")
	}

	config.ApprovalRules = approvalRules
	return config, nil
}
