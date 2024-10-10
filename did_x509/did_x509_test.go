package did_x509

import (
	"crypto/x509"
	"encoding/base64"
	"headease-nuts-pki-overheid-issuer/x509_cert"
	"strings"
	"testing"
)

// TestDefaultDidCreator_CreateDid tests the CreateDid function of DefaultDidProcessor by providing different certificate chains.
// It checks for correct DID generation and appropriate error messages.
func TestDefaultDidCreator_CreateDid(t *testing.T) {
	type fields struct {
	}
	type args struct {
		chain *[]x509.Certificate
	}
	chain, _, rootCert, _, _, err := x509_cert.BuildCertChain("A BIG STRING")
	if err != nil {
		t.Fatal(err)
	}

	alg := "sha512"
	hash, err := x509_cert.Hash(rootCert.Raw, alg)
	if err != nil {
		t.Fatal(err)
	}
	rootHashString := base64.RawURLEncoding.EncodeToString(hash)
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
		errMsg string
	}{
		{
			name:   "Test case 1",
			fields: fields{},
			args:   args{chain: &[]x509.Certificate{}},
			want:   "",
			errMsg: "no certificates provided",
		},
		{
			name:   "Test case 2",
			fields: fields{},
			args: args{chain: &[]x509.Certificate{
				{},
			}},
			want:   "",
			errMsg: "no certificate found in the SAN attributes, please check if the certificate is an UZI Server Certificate",
		},
		{
			name:   "Happy path",
			fields: fields{},
			args:   args{chain: chain},
			want:   strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "otherName", "A BIG STRING"}, ":"),
			errMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DefaultDidProcessor{}
			got, err := d.CreateDid(tt.args.chain)
			wantErr := tt.errMsg != ""
			if (err != nil) != wantErr {
				t.Errorf("DefaultDidProcessor.CreateDid() error = %v, errMsg %v", err, tt.errMsg)
				return
			} else if wantErr {
				if err.Error() != tt.errMsg {
					t.Errorf("DefaultDidProcessor.CreateDid() expected = \"%v\", got: \"%v\"", tt.errMsg, err.Error())
				}
			}

			if got != tt.want {
				t.Errorf("DefaultDidProcessor.CreateDid() = \n%v\n, want: \n%v\n", got, tt.want)
			}
		})
	}
}
