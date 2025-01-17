package credential_issuer

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/nuts-foundation/uzi-did-x509-issuer/internal"
	"github.com/nuts-foundation/uzi-did-x509-issuer/internal/test"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildX509Credential(t *testing.T) {
	allCerts, err := internal.ParseCertificatesFromPEM([]byte(test.TestCertificateChain))
	require.NoError(t, err)
	chain, err := internal.ParseCertificateChain(allCerts)
	require.NoError(t, err)

	privKey, err := internal.ParseRSAPrivateKeyFromPEM([]byte(test.TestSigningKey))
	require.NoError(t, err, "failed to read signing key")

	type inFn = func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string)

	defaultIn := func(t *testing.T) ([]*x509.Certificate, *rsa.PrivateKey, string) {

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
			_, err := Issue(certificates, signingKey, subject)
			if err != nil {
				if err.Error() != tt.errorText {
					t.Errorf("TestBuildX509Credential() error = '%v', wantErr '%v'", err.Error(), tt.errorText)
				}
			} else if err == nil && tt.errorText != "" {
				t.Errorf("TestBuildX509Credential() unexpected success, want error")
			}
		})
	}
}

func TestIssue(t *testing.T) {
	validKey, err := internal.ParseRSAPrivateKeyFromPEM([]byte(test.TestSigningKey))
	require.NoError(t, err, "failed to parse signing key")
	t.Run("ok - happy path", func(t *testing.T) {
		validChain, err := internal.ParseCertificatesFromPEM([]byte(test.TestCertificateChain))
		require.NoError(t, err, "failed to parse chain")

		vc, err := Issue(validChain, validKey, "did:example:123", SubjectAttributes(x509_cert.SubjectTypeCountry, x509_cert.SubjectTypeOrganization))

		require.NoError(t, err, "failed to issue verifiable credential")
		require.NotNil(t, vc, "verifiable credential is nil")

		assert.Equal(t, "https://www.w3.org/2018/credentials/v1", vc.Context[0].String())
		assert.True(t, vc.IsType(ssi.MustParseURI("VerifiableCredential")))
		assert.True(t, vc.IsType(ssi.MustParseURI("X509Credential")))
		assert.Equal(t, "did:x509:0:sha256:IzvPueXLRjJtLtIicMzV3icpiLQPemu8lBv6oRGjm-o::san:otherName:2.16.528.1.1007.99.2110-1-1111111-S-2222222-00.000-333333::subject:O:FauxCare", vc.Issuer.String())

		expectedCredentialSubject := []interface{}{map[string]interface{}{
			"id": "did:example:123",
			"subject": map[string]interface{}{
				"O": "FauxCare",
			},
			"san": map[string]interface{}{
				"otherName":                    "2.16.528.1.1007.99.2110-1-1111111-S-2222222-00.000-333333",
				"permanentIdentifier.assigner": "2.16.528.1.1007.3.3",
				"permanentIdentifier.value":    "2222222",
			},
		}}

		assert.Equal(t, expectedCredentialSubject, vc.CredentialSubject)
		assert.Equal(t, validChain[0].NotAfter, *vc.ExpirationDate, "expiration date of VC must match signing certificate")
	})

	t.Run("ok - correct escaping of special characters", func(t *testing.T) {
		validChain, err := internal.ParseCertificatesFromPEM([]byte(test.TestCertificateChain))
		require.NoError(t, err)

		validChain[0].Subject.Organization = []string{"FauxCare & Co"}

		vc, err := Issue(validChain, validKey, "did:example:123", SubjectAttributes(x509_cert.SubjectTypeCountry, x509_cert.SubjectTypeOrganization))

		assert.Equal(t, "did:x509:0:sha256:IzvPueXLRjJtLtIicMzV3icpiLQPemu8lBv6oRGjm-o::san:otherName:2.16.528.1.1007.99.2110-1-1111111-S-2222222-00.000-333333::subject:O:FauxCare%20%26%20Co", vc.Issuer.String())
	})
}
