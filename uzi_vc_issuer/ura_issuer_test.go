package uzi_vc_issuer

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildUraVerifiableCredential(t *testing.T) {

	chainBytes, err := os.ReadFile("testdata/valid_chain.pem")
	require.NoError(t, err, "failed to read chain")

	type inFn = func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string)

	defaultIn := func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
		pemBlocks, err := parsePemBytes(chainBytes)
		require.NoError(t, err, "failed to parse pem blocks")

		certs, err := parseCertificatesFromPemBlocks(pemBlocks)
		require.NoError(t, err, "failed to parse certificates from pem blocks")

		privKey, err := NewPrivateKey("testdata/signing_key.pem")
		require.NoError(t, err, "failed to read signing key")

		return certs, privKey, "did:example:123"
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
		// {
		// 	name: "nok - empty chain",
		// 	in: func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
		// 		_, privKey, didStr := defaultIn(t)
		// 		return []*x509.Certificate{}, privKey, didStr
		// 	},
		// 	errorText: "empty certificate chain",
		// },
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
		// {
		// 	name: "nok - nil signing key",
		// 	in: func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {
		// 		certs, _, didStr := defaultIn(t)
		// 		return certs, nil, didStr
		// 	},
		// 	errorText: "signing key is nil",
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certificates, signingKey, subject := tt.in(t)
			_, err := Issue(certificates, signingKey, subjectDID(subject))
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

func TestNewFileName(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	tests := []struct {
		name      string
		fileName  string
		expectErr bool
	}{
		{"ValidFile", tmpFile.Name(), false},
		{"InvalidFile", "nonexistentfile", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newFileName(tt.fileName)
			if (err != nil) != tt.expectErr {
				t.Errorf("newFileName() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestReadFile(t *testing.T) {
	// Create a temporary file
	tmpfile, err := os.CreateTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	content := []byte("Hello, World!")
	if _, err := tmpfile.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Call readFile function
	fileName := fileName(tmpfile.Name())
	readContent, err := readFile(fileName)
	if err != nil {
		t.Fatalf("readFile() error = %v", err)
	}

	// Assert the content matches
	if string(readContent) != string(content) {
		t.Errorf("readFile() = %v, want %v", string(readContent), string(content))
	}
}

func TestIssue(t *testing.T) {
	validChain, err := NewValidCertificateChain("testdata/valid_chain.pem")
	require.NoError(t, err, "failed to read chain")

	validKey, err := NewPrivateKey("testdata/signing_key.pem")
	require.NoError(t, err, "failed to read signing key")

	t.Run("ok - happy path", func(t *testing.T) {
		vc, err := Issue(validChain, validKey, "did:example:123", SubjectAttributes(x509_cert.SubjectTypeCountry, x509_cert.SubjectTypeOrganization))

		require.NoError(t, err, "failed to issue verifiable credential")
		require.NotNil(t, vc, "verifiable credential is nil")

		assert.Equal(t, "https://www.w3.org/2018/credentials/v1", vc.Context[0].String())
		assert.True(t, vc.IsType(ssi.MustParseURI("VerifiableCredential")))
		assert.True(t, vc.IsType(ssi.MustParseURI("X509Credential")))
		assert.Equal(t, "did:x509:0:sha512:0OXDVLevEnf_sE-Ayopm0Yof_gmBwxwKZmzbDhKeAwj9vcsI_Q14TBArYsCftQTABLM-Vx9BB6zI05Me2aksaA::san:otherName:2.16.528.1.1007.99.2110-1-1111111-S-2222222-00.000-333333::subject:O:FauxCare", vc.Issuer.String())

		expectedCredentialSubject := []interface{}([]interface{}{map[string]interface{}{
			"id":                           "did:example:123",
			"O":                            "FauxCare",
			"otherName":                    "2.16.528.1.1007.99.2110-1-1111111-S-2222222-00.000-333333",
			"permanentIdentifier.assigner": "2.16.528.1.1007.3.3",
			"permanentIdentifier.value":    "2222222",
		}})

		assert.Equal(t, expectedCredentialSubject, vc.CredentialSubject)

		assert.Equal(t, validChain[0].NotAfter, *vc.ExpirationDate, "expiration date of VC must match signing certificate")
	})
}

func TestParsePemBytes(t *testing.T) {
	chainBytes, err := os.ReadFile("testdata/valid_chain.pem")
	require.NoError(t, err, "failed to read chain")

	tests := []struct {
		name            string
		pemBytes        []byte
		expectNumBlocks int
		expectErr       bool
	}{
		{"ValidChain", chainBytes, 4, false},
		{"InvalidChain", []byte("invalid pem"), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks, err := parsePemBytes(tt.pemBytes)
			if (err != nil) != tt.expectErr {
				t.Errorf("parsePemBytes() error = %v, expectErr %v", err, tt.expectErr)
			}

			if len(blocks) != tt.expectNumBlocks {
				t.Errorf("parsePemBytes() = %v, want %v", len(blocks), tt.expectNumBlocks)
			}
		})
	}
}

func TestNewCertificateChain(t *testing.T) {
	chainBytes, err := os.ReadFile("testdata/valid_chain.pem")
	require.NoError(t, err, "failed to read chain")

	pemBlocks, err := parsePemBytes(chainBytes)
	require.NoError(t, err, "failed to parse pem blocks")

	certs, err := parseCertificatesFromPemBlocks(pemBlocks)
	require.NoError(t, err, "failed to parse certificates from pem blocks")

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
			resultCerts, err := newCertificateChain(inputCerts)
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
