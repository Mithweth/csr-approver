package rules

import (
	"testing"

	certificatesv1 "k8s.io/api/certificates/v1"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    ApprovalRule
		wantErr string
	}{
		{
			name:  "signerName only",
			value: "signerName=example.com/foo",
			want:  ApprovalRule{SignerName: "example.com/foo"},
		},
		{
			name:  "signerName and username",
			value: "signerName=example.com/foo,username=alice",
			want:  ApprovalRule{SignerName: "example.com/foo", Username: "alice"},
		},
		{
			name:  "surrounding whitespace is trimmed",
			value: " signerName = example.com/foo , username = alice ",
			want:  ApprovalRule{SignerName: "example.com/foo", Username: "alice"},
		},
		{
			name:    "empty value",
			value:   "",
			wantErr: "approval rule must not be empty",
		},
		{
			name:    "blank value",
			value:   "   ",
			wantErr: "approval rule must not be empty",
		},
		{
			name:    "missing equals sign",
			value:   "signerName",
			wantErr: `invalid field "signerName": expected key=value`,
		},
		{
			name:    "empty field value",
			value:   "signerName=",
			wantErr: `field "signerName" must not be empty`,
		},
		{
			name:    "unknown field",
			value:   "signerName=example.com/foo,role=admin",
			wantErr: `unknown field "role"`,
		},
		{
			name:    "missing signerName",
			value:   "username=alice",
			wantErr: "signerName is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.value)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Parse(%q) = %v, nil; want error %q", tt.value, got, tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("Parse(%q) error = %q; want %q", tt.value, err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("Parse(%q) = %+v; want %+v", tt.value, got, tt.want)
			}
		})
	}
}

func TestApprovalRule_Matches(t *testing.T) {
	tests := []struct {
		name string
		rule ApprovalRule
		csr  certificatesv1.CertificateSigningRequestSpec
		want bool
	}{
		{
			name: "signerName only, matching",
			rule: ApprovalRule{SignerName: "example.com/foo"},
			csr:  certificatesv1.CertificateSigningRequestSpec{SignerName: "example.com/foo", Username: "anyone"},
			want: true,
		},
		{
			name: "signerName mismatch",
			rule: ApprovalRule{SignerName: "example.com/foo"},
			csr:  certificatesv1.CertificateSigningRequestSpec{SignerName: "example.com/bar", Username: "anyone"},
			want: false,
		},
		{
			name: "signerName and username, matching",
			rule: ApprovalRule{SignerName: "example.com/foo", Username: "alice"},
			csr:  certificatesv1.CertificateSigningRequestSpec{SignerName: "example.com/foo", Username: "alice"},
			want: true,
		},
		{
			name: "signerName matches but username mismatch",
			rule: ApprovalRule{SignerName: "example.com/foo", Username: "alice"},
			csr:  certificatesv1.CertificateSigningRequestSpec{SignerName: "example.com/foo", Username: "bob"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csr := &certificatesv1.CertificateSigningRequest{Spec: tt.csr}
			if got := tt.rule.Matches(csr); got != tt.want {
				t.Errorf("Matches() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestApprovalRule_String(t *testing.T) {
	tests := []struct {
		name string
		rule ApprovalRule
		want string
	}{
		{
			name: "signerName only",
			rule: ApprovalRule{SignerName: "example.com/foo"},
			want: "signerName=example.com/foo",
		},
		{
			name: "signerName and username",
			rule: ApprovalRule{SignerName: "example.com/foo", Username: "alice"},
			want: "signerName=example.com/foo,username=alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.String(); got != tt.want {
				t.Errorf("String() = %q; want %q", got, tt.want)
			}
		})
	}
}
