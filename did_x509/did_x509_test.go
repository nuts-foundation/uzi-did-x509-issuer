package did_x509

import (
	"crypto/x509"
	"encoding/base64"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"reflect"
	"strings"
	"testing"
)

// TestDefaultDidCreator_CreateDid tests the CreateDid function of DefaultDidProcessor by providing different certificate chains.
// It checks for correct DID generation and appropriate error messages.
func TestDefaultDidCreator_CreateDidSingle(t *testing.T) {
	type fields struct {
	}
	type args struct {
		chain []*x509.Certificate
	}
	chain, _, rootCert, _, _, err := x509_cert.BuildSelfSignedCertChain("A_BIG_STRING", "")
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
			name:   "Happy path",
			fields: fields{},
			args:   args{chain: chain},
			want:   strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "otherName", "A_BIG_STRING"}, ":"),
			errMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateDid(tt.args.chain[0], tt.args.chain[len(tt.args.chain)-1])
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
func TestDefaultDidCreator_CreateDidDouble(t *testing.T) {
	type fields struct {
	}
	type args struct {
		chain []*x509.Certificate
	}
	chain, _, rootCert, _, _, err := x509_cert.BuildSelfSignedCertChain("A_BIG_STRING", "A_SMALL_STRING")
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
			name:   "Happy path",
			fields: fields{},
			args:   args{chain: chain},
			want:   strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "otherName", "A_BIG_STRING", "", "san", "permanentIdentifier.value", "A_SMALL_STRING", "", "san", "permanentIdentifier.assigner", "2.16.528.1.1007.3.3"}, ":"),
			errMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateDid(tt.args.chain[0], tt.args.chain[len(tt.args.chain)-1])
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

// TestDefaultDidCreator_ParseDid tests the ParseDid function of DefaultDidProcessor by providing different DID strings.
// It checks for correct X509Did parsing and appropriate error messages.
func TestDefaultDidCreator_ParseDid(t *testing.T) {
	policies := []*x509_cert.OtherNameValue{
		{
			PolicyType: "san",
			Type:       "otherName",
			Value:      "A_BIG_STRING",
		},
	}
	type fields struct {
	}
	type args struct {
		didString string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *X509Did
		errMsg string
	}{
		{
			name:   "Invalid DID method",
			fields: fields{},
			args:   args{didString: "did:abc:0:sha512:hash::san:otherName:A_BIG_STRING"},
			want:   nil,
			errMsg: "invalid didString method",
		},
		{
			name:   "Invalid DID format",
			fields: fields{},
			args:   args{didString: "did:x509:0:sha512::san:otherName:A_BIG_STRING"},
			want:   nil,
			errMsg: "invalid didString format, expected didString:x509:0:alg:hash::san:type:ura",
		},
		{
			name:   "Happy path",
			fields: fields{},
			args:   args{didString: "did:x509:0:sha512:hash::san:otherName:A_BIG_STRING"},
			want:   &X509Did{Version: "0", RootCertificateHashAlg: "sha512", RootCertificateHash: "hash", Policies: policies},
			errMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDid(tt.args.didString)
			wantErr := tt.errMsg != ""
			if (err != nil) != wantErr {
				t.Errorf("DefaultDidProcessor.ParseDid() error = %v, expected error = %v", err, tt.errMsg)
				return
			} else if wantErr {
				if err.Error() != tt.errMsg {
					t.Errorf("DefaultDidProcessor.ParseDid() expected = \"%v\", got = \"%v\"", tt.errMsg, err.Error())
				}
			}

			if tt.want != nil && got != nil &&
				(tt.want.Version != got.Version ||
					tt.want.RootCertificateHashAlg != got.RootCertificateHashAlg ||
					tt.want.RootCertificateHash != got.RootCertificateHash ||
					!reflect.DeepEqual(tt.want.Policies, got.Policies)) {
				t.Errorf("DefaultDidProcessor.ParseDid() = %v, want = %v", got, tt.want)
			}
		})
	}
}
