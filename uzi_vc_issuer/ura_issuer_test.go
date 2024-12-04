package uzi_vc_issuer

import (
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"github.com/stretchr/testify/require"
)

// parsePEMCertificates parses bytes containing PEM encoded certificates and returns a list of certificates.
func parsePEMCertificates(t *testing.T, pemBytes []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Error("invalid PEM block type")
			return nil

		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Error(err)
			return nil
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		t.Error(errors.New("no certificates found"))
		return nil
	}
	return certs
}

// parsePemPrivateKey parses bytes containing PEM encoded private key and returns the private key.
func parsePemPrivateKey(t *testing.T, pemBytes []byte) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Error(errors.New("no PEM block found"))
		return nil
	}
	rv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Error(err)
		return nil
	}
	return rv
}

func TestBuildUraVerifiableCredential(t *testing.T) {

	chainBytes, err := os.ReadFile("testdata/valid_chain.pem")
	require.NoError(t, err, "failed to read chain")

	keyBytes, err := os.ReadFile("testdata/signing_key.pem")
	require.NoError(t, err, "failed to read signing key")

	type inFn = func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string)

	defaultIn := func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
		chain := parsePEMCertificates(t, chainBytes)
		privKey := parsePemPrivateKey(t, keyBytes)
		return chain, privKey, "did:example:123"
	}

	tests := []struct {
		name      string
		in        inFn
		errorText string
	}{
		{
			name:      "ok - valid chain",
			in:        defaultIn,
			errorText: "",
		},
		{
			name: "nok - empty chain",
			in: func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				_, privKey, didStr := defaultIn(t)
				return []*x509.Certificate{}, privKey, didStr
			},
			errorText: "empty certificate chain",
		},
		{
			name: "nok - empty serial number",
			in: func(*testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certs, privKey, didStr := defaultIn(t)
				certs[0].Subject.SerialNumber = ""
				return certs, privKey, didStr
			},
			errorText: "serialNumber not found in signing certificate",
		},
		{
			name: "nok - invalid signing serial in signing cert",
			in: func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certs, privKey, didStr := defaultIn(t)

				certs[0].Subject.SerialNumber = "invalid-serial-number"
				return certs, privKey, didStr
			},
			errorText: "serial number does not match UZI number",
		},
		{
			name: "nok - invalid signing certificate 2",
			in: func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certs, privKey, didStr := defaultIn(t)

				certs[0].ExtraExtensions = make([]pkix.Extension, 0)
				certs[0].Extensions = make([]pkix.Extension, 0)
				return certs, privKey, didStr
			},
			errorText: "no values found in the SAN attributes, please check if the certificate is an UZI Server Certificate",
		},
		{
			name: "nok - empty cert in chain",
			in: func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certs, privKey, didStr := defaultIn(t)
				certs[0] = &x509.Certificate{}
				return certs, privKey, didStr
			},
			errorText: "no values found in the SAN attributes, please check if the certificate is an UZI Server Certificate",
		},
		{
			name: "nok - nil signing key",
			in: func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
				certs, _, didStr := defaultIn(t)
				return certs, nil, didStr
			},
			errorText: "signing key is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certificates, signingKey, subjectDID := tt.in(t)
			_, err := BuildUraVerifiableCredential(certificates, signingKey, subjectDID, []x509_cert.SubjectTypeName{})
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
	chainBytes, err := os.ReadFile("testdata/valid_chain.pem")
	require.NoError(t, err, "failed to read chain")

	certs := parsePEMCertificates(t, chainBytes)

	tests := []struct {
		name      string
		errorText string
		in        func(certs []*x509.Certificate) []*x509.Certificate
		out       func(certs []*x509.Certificate) []*x509.Certificate
	}{
		{
			name: "ok - valid cert input",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				return certs
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return certs
			},
			errorText: "",
		},
		{
			name: "ok - it handles out of order certificates",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				certs = []*x509.Certificate{certs[2], certs[0], certs[3], certs[1]}
				return certs
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return certs
			},
			errorText: "",
		},
		{
			name: "nok - missing signing certificate",
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
			name: "nok - missing root CA certificate",
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
			name: "nok - missing first intermediate CA certificate",
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
			name: "nok - missing second intermediate CA certificate",
			in: func(certs []*x509.Certificate) []*x509.Certificate {
				certs = []*x509.Certificate{certs[0], certs[1], certs[3]}
				return certs
			},
			out: func(certs []*x509.Certificate) []*x509.Certificate {
				return nil
			},
			errorText: "failed to find path from signingCert to root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputCerts := tt.in(certs)
			expectedCerts := tt.out(certs)
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
	chain, _, rootCert, privKey, signingCert, err := x509_cert.BuildSelfSignedCertChain(identifier, ura)

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
			name:       "ok - happy path",
			certFile:   pemFile.Name(),
			keyFile:    keyFile.Name(),
			subjectDID: "did:example:123",
			allowTest:  true,
			out: &vc.VerifiableCredential{
				Context:        []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
				Issuer:         did.MustParseDID(fmt.Sprintf("did:x509:0:sha512:%s::san:otherName:%s::san:permanentIdentifier.value:%s::san:permanentIdentifier.assigner:%s", rootHash, identifier, ura, x509_cert.UraAssigner.String())).URI(),
				Type:           []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("UziServerCertificateCredential")},
				ExpirationDate: toPtr(signingCert.NotAfter),
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
			result, err := Issue(tt.certFile, tt.keyFile, tt.subjectDID, tt.allowTest, true, make([]x509_cert.SubjectTypeName, 0))
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
				compare(t, tt.out, &found)
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

func compare(t *testing.T, expected *vc.VerifiableCredential, found *vc.VerifiableCredential) {
	require.True(t, strings.HasPrefix(found.ID.String(), found.Issuer.String()+"#"), "credential ID must be in form <issuer DID>#<uuid>")
	require.Equal(t, expected.Issuer.String(), found.Issuer.String(), "credential issuer mismatch")
	require.Equal(t, expected.Type, found.Type, "credential type mismatch")
	require.Equal(t, expected.ExpirationDate, found.ExpirationDate, "credential expiration date mismatch")
}

func toPtr[T any](v T) *T {
	return &v
}
