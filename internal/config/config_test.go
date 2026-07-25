package config

import (
	"testing"

	"github.com/Mithweth/csr-approver/internal/rules"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    Config
		wantErr string
	}{
		{
			name: "single approval rule",
			args: []string{"--approval-rule", "signerName=example.com/foo"},
			want: Config{
				ApprovalRules:           []rules.ApprovalRule{{SignerName: "example.com/foo"}},
				LeaderElectionLeaseName: "csr-approver",
			},
		},
		{
			name: "multiple approval rules and kubeconfig",
			args: []string{
				"--kubeconfig", "/tmp/kubeconfig",
				"--approval-rule", "signerName=example.com/foo",
				"--approval-rule", "signerName=example.com/bar,username=alice",
			},
			want: Config{
				Kubeconfig: "/tmp/kubeconfig",
				ApprovalRules: []rules.ApprovalRule{
					{SignerName: "example.com/foo"},
					{SignerName: "example.com/bar", Username: "alice"},
				},
				LeaderElectionLeaseName: "csr-approver",
			},
		},
		{
			name: "leader election with namespace",
			args: []string{
				"--approval-rule", "signerName=example.com/foo",
				"--leader-elect",
				"--leader-election-namespace", "kube-system",
				"--leader-election-lease-name", "custom-lease",
			},
			want: Config{
				ApprovalRules:           []rules.ApprovalRule{{SignerName: "example.com/foo"}},
				LeaderElection:          true,
				LeaderElectionNamespace: "kube-system",
				LeaderElectionLeaseName: "custom-lease",
			},
		},
		{
			name:    "missing approval rule",
			args:    []string{},
			wantErr: "at least one --approval-rule is required",
		},
		{
			name:    "invalid approval rule",
			args:    []string{"--approval-rule", "bogus"},
			wantErr: `invalid field "bogus": expected key=value`,
		},
		{
			name: "leader election without namespace",
			args: []string{
				"--approval-rule", "signerName=example.com/foo",
				"--leader-elect",
			},
			wantErr: "leader-election-namespace is mandatory when leader-elect is true",
		},
		{
			name:    "unknown flag",
			args:    []string{"--approval-rule", "signerName=example.com/foo", "--does-not-exist"},
			wantErr: "unknown flag: --does-not-exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Parse(%v) = %+v, nil; want error %q", tt.args, got, tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("Parse(%v) error = %q; want %q", tt.args, err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Parse(%v) unexpected error: %v", tt.args, err)
			}

			if got.Kubeconfig != tt.want.Kubeconfig ||
				got.LeaderElection != tt.want.LeaderElection ||
				got.LeaderElectionNamespace != tt.want.LeaderElectionNamespace ||
				got.LeaderElectionLeaseName != tt.want.LeaderElectionLeaseName {
				t.Fatalf("Parse(%v) = %+v; want %+v", tt.args, got, tt.want)
			}

			if len(got.ApprovalRules) != len(tt.want.ApprovalRules) {
				t.Fatalf("Parse(%v) ApprovalRules = %+v; want %+v", tt.args, got.ApprovalRules, tt.want.ApprovalRules)
			}
			for i := range got.ApprovalRules {
				if got.ApprovalRules[i] != tt.want.ApprovalRules[i] {
					t.Fatalf("Parse(%v) ApprovalRules[%d] = %+v; want %+v", tt.args, i, got.ApprovalRules[i], tt.want.ApprovalRules[i])
				}
			}
		})
	}
}
