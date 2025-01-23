package internal

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParsePemBytes(t *testing.T) {
	tests := []struct {
		name            string
		pemBytes        []byte
		expectNumBlocks int
		expectErr       bool
	}{
		{"ValidChain", []byte(TestCertificateChain), 4, false},
		{"InvalidChain", []byte("invalid pem"), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks, err := parsePemBytes(tt.pemBytes)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, blocks, tt.expectNumBlocks)
			}
		})
	}
}

func TestParseCertificateChain(t *testing.T) {
	certs, err := ParseCertificatesFromPEM([]byte(TestCertificateChain))
	require.NoError(t, err)

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
			resultCerts, err := ParseCertificateChain(inputCerts)
			if tt.errorText == "" {
				require.NoError(t, err)
				require.Len(t, resultCerts, len(expectedCerts))
				for i := range resultCerts {
					if !resultCerts[i].Equal(expectedCerts[i]) {
						t.Errorf("BuildCertificateChain() at index %d expected %v, got %v", i, expectedCerts[i], resultCerts[i])
					}
				}
			} else {
				require.EqualError(t, err, tt.errorText)
				require.Nil(t, expectedCerts)
			}
		})
	}
}
