package uzi_vc_issuer

import (
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	clo "github.com/huandu/go-clone"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"os"
	"slices"
	"testing"
)

func TestBuildUraVerifiableCredential(t *testing.T) {

	_certs, _, _, privateKey, signingCert, err := x509_cert.BuildSelfSignedCertChain("2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344", "90000380")
	failError(t, err)

	tests := []struct {
		name      string
		in        func(certs []*x509.Certificate) ([]*x509.Certificate, *rsa.PrivateKey, string)
		errorText string
	}{
		{
			name: "empty chain",
			in: func(certs []*x509.Certificate) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				return []*x509.Certificate{}, privateKey, "did:example:123"
			},
			errorText: "empty certificate chain",
		},
		{
			name: "invalid signing certificate 1",
			in: func(certs []*x509.Certificate) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				signingTmpl, err := x509_cert.SigningCertTemplate(nil, "2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344", "90000380")
				signingTmpl.Subject.SerialNumber = "KAAS"
				failError(t, err)
				cert, _, err := x509_cert.CreateCert(signingTmpl, signingCert, signingCert.PublicKey, privateKey)
				failError(t, err)
				certs[0] = cert
				return certs, privateKey, "did:example:123"
			},
			errorText: "serial number does not match UZI number",
		},
		{
			name: "invalid signing certificate 2",
			in: func(certs []*x509.Certificate) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				signingTmpl, err := x509_cert.SigningCertTemplate(nil, "2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344", "90000380")
				signingTmpl.ExtraExtensions = make([]pkix.Extension, 0)
				failError(t, err)
				cert, _, err := x509_cert.CreateCert(signingTmpl, signingCert, signingCert.PublicKey, privateKey)
				failError(t, err)
				certs[0] = cert
				return certs, privateKey, "did:example:123"
			},
			errorText: "no values found in the SAN attributes, please check if the certificate is an UZI Server Certificate",
		},
		{
			name: "invalid serial number",
			in: func(certs []*x509.Certificate) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certificate := clo.Clone(certs[0]).(*x509.Certificate)
				certificate.Subject.SerialNumber = ""
				certs[0] = certificate
				return certs, privateKey, "did:example:123"
			},
			errorText: "serialNumber not found in signing certificate",
		},
		{
			name: "broken cert",
			in: func(certs []*x509.Certificate) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certs[0] = &x509.Certificate{}
				return certs, privateKey, "did:example:123"
			},
			errorText: "no values found in the SAN attributes, please check if the certificate is an UZI Server Certificate",
		},
		{
			name: "broken signing key",
			in: func(certs []*x509.Certificate) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				return certs, nil, "did:example:123"
			},
			errorText: "signing key is nil",
		},
		{
			name: "happy path",
			in: func(certs []*x509.Certificate) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				return certs, privateKey, "did:example:123"
			},
			errorText: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certificates := clo.Clone(_certs).([]*x509.Certificate)
			certificates, signingKey, subjectDID := tt.in(certificates)
			_, err := BuildUraVerifiableCredential(certificates, signingKey, subjectDID)
			if err != nil {
				if err.Error() != tt.errorText {
					t.Errorf("BuildUraVerifiableCredential() error = '%v', wantErr '%v'", err.Error(), tt.errorText)
				}
			} else if err == nil && tt.errorText != "" {
				t.Errorf("BuildUraVerifiableCredential() unexpected success, want error")
			}
		})
	}
}

func TestBuildCertificateChain(t *testing.T) {
	certs, _, _, _, _, err := x509_cert.BuildSelfSignedCertChain("2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344", "90000380")
	failError(t, err)
	tests := []struct {
		name      string
		errorText string
		in        func(certs []*x509.Certificate) []*x509.Certificate
		out       func(certs []*x509.Certificate) []*x509.Certificate
	}{
		{
			name: "happy flow",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				return certs
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return certs
			},
			errorText: "",
		},
		{
			name: "no signing certificate",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				certs = certs[1:]
				return certs
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return nil
			},
			errorText: "failed to find signing certificate",
		},
		{
			name: "no root CA certificate",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				certs = certs[:3]
				return certs
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return nil
			},
			errorText: "failed to find path from signingCert to root",
		},
		{
			name: "no intermediate CA certificate type 1",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				certs = []*x509.Certificate{certs[0], certs[2], certs[3]}
				return certs
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return nil
			},
			errorText: "failed to find path from signingCert to root",
		},
		{
			name: "no intermediate CA certificate type 2",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				certs = []*x509.Certificate{certs[0], certs[1], certs[3]}
				return certs
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return nil
			},
			errorText: "failed to find path from signingCert to root",
		},
		{
			name: "no intermediate CA certificate type 3",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				certs = []*x509.Certificate{certs[0], nil, certs[2], certs[3]}
				return certs
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return nil
			},
			errorText: "failed to find path from signingCert to root",
		},
		{
			name: "reverse certificate order",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				rv := make([]*x509.Certificate, 0)
				for i := len(certs) - 1; i >= 0; i-- {
					rv = append(rv, certs[i])
				}
				return rv
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return certs
			},
			errorText: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputCerts := tt.in(clo.Clone(certs).([]*x509.Certificate))
			expectedCerts := tt.out(clo.Clone(certs).([]*x509.Certificate))
			resultCerts, err := BuildCertificateChain(inputCerts)
			if err != nil {
				if err.Error() != tt.errorText {
					t.Errorf("BuildCertificateChain() error = '%v', wantErr '%v'", err.Error(), tt.errorText)
				}
			} else if err == nil && tt.errorText != "" {
				t.Errorf("BuildCertificateChain() unexpected success, want error")
			}
			if len(resultCerts) != len(expectedCerts) {
				t.Errorf("BuildCertificateChain() expected %d certificates, got %d", len(expectedCerts), len(resultCerts))
				return
			}
			for i := range resultCerts {
				if !resultCerts[i].Equal(expectedCerts[i]) {
					t.Errorf("BuildCertificateChain() at index %d expected %v, got %v", i, expectedCerts[i], resultCerts[i])
				}
			}
		})
	}
}

func TestIssue(t *testing.T) {

	brokenChain, _, _, _, _, err := x509_cert.BuildSelfSignedCertChain("KAAS", "HAM")
	failError(t, err)
	identifier := "2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344"
	ura := "90000380"
	chain, _, rootCert, privKey, _, err := x509_cert.BuildSelfSignedCertChain(identifier, ura)
	bytesRootHash := sha512.Sum512(rootCert.Raw)
	rootHash := base64.RawURLEncoding.EncodeToString(bytesRootHash[:])
	failError(t, err)

	chainPems, err := x509_cert.EncodeCertificates(chain...)
	failError(t, err)
	siglePem, err := x509_cert.EncodeCertificates(chain[0])
	failError(t, err)
	brokenPem, err := x509_cert.EncodeCertificates(brokenChain...)
	failError(t, err)
	signingKeyPem, err := x509_cert.EncodeRSAPrivateKey(privKey)
	failError(t, err)

	pemFile, err := os.CreateTemp(t.TempDir(), "chain.pem")
	failError(t, err)
	err = os.WriteFile(pemFile.Name(), chainPems, 0644)
	failError(t, err)

	brokenPemFile, err := os.CreateTemp(t.TempDir(), "broken_chain.pem")
	failError(t, err)
	err = os.WriteFile(brokenPemFile.Name(), brokenPem, 0644)
	failError(t, err)

	signlePemFile, err := os.CreateTemp(t.TempDir(), "single_chain.pem")
	failError(t, err)
	err = os.WriteFile(signlePemFile.Name(), siglePem, 0644)
	failError(t, err)

	keyFile, err := os.CreateTemp(t.TempDir(), "signing_key.pem")
	failError(t, err)
	err = os.WriteFile(keyFile.Name(), signingKeyPem, 0644)
	failError(t, err)

	emptyFile, err := os.CreateTemp(t.TempDir(), "empty.pem")
	failError(t, err)
	err = os.WriteFile(emptyFile.Name(), []byte{}, 0644)
	failError(t, err)

	tests := []struct {
		name       string
		certFile   string
		keyFile    string
		subjectDID string
		allowTest  bool
		out        *vc.VerifiableCredential
		errorText  string
	}{
		{
			name:       "happy path",
			certFile:   pemFile.Name(),
			keyFile:    keyFile.Name(),
			subjectDID: "did:example:123",
			allowTest:  true,
			out: &vc.VerifiableCredential{
				Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
				Issuer:  did.MustParseDID(fmt.Sprintf("did:x509:0:sha512:%s::san:otherName:%s::san:permanentIdentifier.value:%s::san:permanentIdentifier.assigner:%s", rootHash, identifier, ura, x509_cert.UraAssigner.String())).URI(),
				Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("UziServerCertificateCredential")},
			},
			errorText: "",
		},
		{
			name:       "no signing keys found",
			certFile:   pemFile.Name(),
			keyFile:    emptyFile.Name(),
			subjectDID: "did:example:123",
			allowTest:  true,
			out:        nil,
			errorText:  "no signing keys found",
		},
		{
			name:       "invalid signing cert",
			certFile:   signlePemFile.Name(),
			keyFile:    keyFile.Name(),
			subjectDID: "did:example:123",
			allowTest:  true,
			out:        nil,
			errorText:  "failed to find path from signingCert to root",
		},
		{
			name:       "invalid otherName",
			certFile:   brokenPemFile.Name(),
			keyFile:    keyFile.Name(),
			subjectDID: "did:example:123",
			allowTest:  true,
			out:        nil,
			errorText:  "failed to parse URA from OtherNameValue",
		},
		/* more test cases */
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Issue(tt.certFile, tt.keyFile, tt.subjectDID, tt.allowTest)
			if err != nil {
				if err.Error() != tt.errorText {
					t.Errorf("Issue() error = '%v', wantErr '%v'", err.Error(), tt.errorText)
				}
			} else if err == nil && tt.errorText != "" {
				t.Errorf("Issue() unexpected success, want error")
			} else if err == nil {
				found := vc.VerifiableCredential{}
				err = json.Unmarshal([]byte("\""+result+"\""), &found)
				failError(t, err)
				if !compare(tt.out, &found) {
					t.Errorf("Issue() expected %v, got %v", tt.out, found)
				}
			}
		})
	}
}

func failError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("an error occured: %v", err.Error())
		t.Fatal(err)
	}
}

func compare(expected *vc.VerifiableCredential, found *vc.VerifiableCredential) bool {
	if expected.Issuer.String() != found.Issuer.String() {
		return false
	}
	if !slices.Equal(expected.Type, found.Type) {
		return false
	}
	return true
}
