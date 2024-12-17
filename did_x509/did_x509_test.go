package did_x509

import (
	"crypto/x509"
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"net/url"
	"strings"
	"testing"

	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"github.com/stretchr/testify/assert"
)

func TestPercentEncode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello world", "hello%20world"},
		{"foo@bar.com", "foo%40bar.com"},
		{"100%", "100%25"},
		{"a+b=c", "a%2Bb%3Dc"},
		{"~!@#$%^&*()_+", "%7E%21%40%23%24%25%5E%26%2A%28%29_%2B"},
		{"FauxCare & Co", "FauxCare%20%26%20Co"},
		{"FåúxCaré & Có", "F%C3%A5%C3%BAxCar%C3%A9%20%26%20C%C3%B3"},
		{"💩", "%F0%9F%92%A9"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := PercentEncode(test.input)
			require.Equal(t, test.expected, result)
			unescaped, err := url.PathUnescape(result)
			require.NoError(t, err)
			require.Equal(t, test.input, unescaped)
		})
	}
}

// TestCreateDid tests the CreateDid function of DefaultDidProcessor by providing different certificate chains.
// It checks for correct DID generation and appropriate error messages.
func TestCreateDidSingle(t *testing.T) {
	type fields struct {
	}
	type args struct {
		chain []*x509.Certificate
	}
	chain, _, rootCert, _, _, err := x509_cert.BuildSelfSignedCertChain("A_BIG_STRING", "A_PERMANENT_STRING")
	if err != nil {
		t.Fatal(err)
	}

	alg := "sha512"
	hash, err := x509_cert.Hash(rootCert.Raw, alg)
	if err != nil {
		t.Fatal(err)
	}
	rootHashString := base64.RawURLEncoding.EncodeToString(hash)
	types := []x509_cert.SanTypeName{x509_cert.SanTypeOtherName, x509_cert.SanTypePermanentIdentifierValue, x509_cert.SanTypePermanentIdentifierAssigner}

	tests := []struct {
		name         string
		fields       fields
		args         args
		want         string
		errMsg       string
		sanTypes     []x509_cert.SanTypeName
		subjectTypes []x509_cert.SubjectTypeName
	}{
		{
			name:     "Happy path",
			fields:   fields{},
			args:     args{chain: chain},
			want:     strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "otherName", "A_BIG_STRING", "", "san", "permanentIdentifier.value", "A_PERMANENT_STRING", "", "san", "permanentIdentifier.assigner", "2.16.528.1.1007.3.3"}, ":"),
			sanTypes: types,
			errMsg:   "",
		},
		{
			name:     "Happy path",
			fields:   fields{},
			args:     args{chain: chain},
			want:     strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "otherName", "A_BIG_STRING", "", "san", "permanentIdentifier.value", "A_PERMANENT_STRING"}, ":"),
			sanTypes: []x509_cert.SanTypeName{x509_cert.SanTypeOtherName, x509_cert.SanTypePermanentIdentifierValue},
			errMsg:   "",
		},
		{
			name:     "Happy path",
			fields:   fields{},
			args:     args{chain: chain},
			want:     strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "otherName", "A_BIG_STRING"}, ":"),
			sanTypes: []x509_cert.SanTypeName{x509_cert.SanTypeOtherName},
			errMsg:   "",
		},
		{
			name:     "Happy path",
			fields:   fields{},
			args:     args{chain: chain},
			want:     strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "permanentIdentifier.value", "A_PERMANENT_STRING"}, ":"),
			sanTypes: []x509_cert.SanTypeName{x509_cert.SanTypePermanentIdentifierValue},
			errMsg:   "",
		},
		{
			name:     "Happy path",
			fields:   fields{},
			args:     args{chain: chain},
			want:     strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "permanentIdentifier.assigner", "2.16.528.1.1007.3.3"}, ":"),
			sanTypes: []x509_cert.SanTypeName{x509_cert.SanTypePermanentIdentifierAssigner},
			errMsg:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateDid(tt.args.chain[0], tt.args.chain[len(tt.args.chain)-1], tt.subjectTypes, tt.sanTypes...)
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
func TestCreateDidDouble(t *testing.T) {
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
	sanTypeNames := []x509_cert.SanTypeName{x509_cert.SanTypeOtherName, x509_cert.SanTypePermanentIdentifierValue, x509_cert.SanTypePermanentIdentifierAssigner}
	sanTypeNamesShort := []x509_cert.SanTypeName{x509_cert.SanTypeOtherName}
	subjectTypeNamesShort := []x509_cert.SubjectTypeName{x509_cert.SubjectTypeOrganization}

	tests := []struct {
		name         string
		fields       fields
		args         args
		want         string
		errMsg       string
		sanTypes     []x509_cert.SanTypeName
		subjectTypes []x509_cert.SubjectTypeName
	}{
		{
			name:     "Happy path san",
			fields:   fields{},
			args:     args{chain: chain},
			want:     strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "otherName", "A_BIG_STRING", "", "san", "permanentIdentifier.value", "A_SMALL_STRING", "", "san", "permanentIdentifier.assigner", "2.16.528.1.1007.3.3"}, ":"),
			sanTypes: sanTypeNames,
			errMsg:   "",
		},
		{
			name:     "Happy path short san",
			fields:   fields{},
			args:     args{chain: chain},
			want:     strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "otherName", "A_BIG_STRING"}, ":"),
			sanTypes: sanTypeNamesShort,
			errMsg:   "",
		},
		{
			name:         "Happy path short san",
			fields:       fields{},
			args:         args{chain: chain},
			want:         strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "subject", "O", "FauxCare"}, ":"),
			subjectTypes: subjectTypeNamesShort,
			errMsg:       "",
		},
		{
			name:         "Happy path mixed",
			fields:       fields{},
			args:         args{chain: chain},
			want:         strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "otherName", "A_BIG_STRING", "", "subject", "O", "FauxCare"}, ":"),
			sanTypes:     sanTypeNamesShort,
			subjectTypes: subjectTypeNamesShort,
			errMsg:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateDid(tt.args.chain[0], tt.args.chain[len(tt.args.chain)-1], tt.subjectTypes, tt.sanTypes...)
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

// TestParseDid tests the ParseDid function of DefaultDidProcessor by providing different DID strings.
// It checks for correct X509Did parsing and appropriate error messages.
func TestParseDid(t *testing.T) {
	policies := []*x509_cert.GenericNameValue{
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
			name:   "ok - happy path",
			fields: fields{},
			args:   args{didString: "did:x509:0:sha512:hash::san:otherName:A_BIG_STRING"},
			want:   &X509Did{Version: "0", RootCertificateHashAlg: "sha512", RootCertificateHash: "hash", Policies: policies},
			errMsg: "",
		},
		{
			name:   "nok - invalid DID method",
			fields: fields{},
			args:   args{didString: "did:abc:0:sha512:hash::san:otherName:A_BIG_STRING"},
			want:   nil,
			errMsg: "invalid didString method",
		},
		{
			name:   "nok - invalid DID format",
			fields: fields{},
			args:   args{didString: "did:x509:0:sha512::san:otherName:A_BIG_STRING"},
			want:   nil,
			errMsg: "invalid didString format, expected didString:x509:0:alg:hash::san:type:ura",
		},
		{name: "ok - correct unescaping",
			fields: fields{},
			args:   args{didString: "did:x509:0:sha512:hash::san:otherName:hello%20world%20from%20FauxCare%20%26%20Co"},
			want:   &X509Did{Version: "0", RootCertificateHashAlg: "sha512", RootCertificateHash: "hash", Policies: []*x509_cert.GenericNameValue{{PolicyType: "san", Type: "otherName", Value: "hello world from FauxCare & Co"}}},
			errMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDid(tt.args.didString)
			wantErr := tt.errMsg != ""
			if (err != nil) != wantErr {
				t.Errorf("ParseDid() error = %v, expected error = %v", err, tt.errMsg)
				return
			} else if wantErr {
				if err.Error() != tt.errMsg {
					t.Errorf("ParseDid() expected = \"%v\", got = \"%v\"", tt.errMsg, err.Error())
				}
			}

			if tt.want != nil && got != nil {
				assert.Equal(t, tt.want.Policies, got.Policies)
			}
		})
	}
}
