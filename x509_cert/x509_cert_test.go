package x509_cert

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseChain(t *testing.T) {
	_, chainPem, _, _, _, err := BuildSelfSignedCertChain("2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344", "900030787")
	failError(t, err)
	derChains := make([][]byte, chainPem.Len())
	for i := 0; i < chainPem.Len(); i++ {
		certBlock, ok := chainPem.Get(i)
		certBlock = []byte(strings.ReplaceAll(string(certBlock), "\\n", "\n"))
		block, _ := pem.Decode(certBlock)
		assert.NotNil(t, block)
		if ok {
			derChains[i] = block.Bytes
		} else {
			t.Fail()
		}
	}

	testCases := []struct {
		name     string
		derChain [][]byte
		errMsg   string
	}{
		{
			name:     "Valid Certificates",
			derChain: derChains,
		},
		{
			name:     "Nil ChainPem",
			derChain: nil,
			errMsg:   "derChain is nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCertificates(tc.derChain)
			if err != nil {
				if err.Error() != tc.errMsg {
					t.Errorf("got error %v, want %v", err, tc.errMsg)
				}
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	_, _, _, privateKey, _, err := BuildSelfSignedCertChain("2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344", "900030787")
	failError(t, err)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	failError(t, err)

	pkcs1PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	testCases := []struct {
		name   string
		der    []byte
		errMsg string
	}{
		{
			name: "ValidPrivateKey",
			der:  privateKeyBytes,
		},
		{
			name:   "InvalidPrivateKey",
			der:    pkcs1PrivateKey,
			errMsg: "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)",
		},
		{
			name:   "NilDER",
			der:    nil,
			errMsg: "der is nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePrivateKey(tc.der)
			if err != nil {
				if err.Error() != tc.errMsg {
					t.Errorf("got error %v, want %v", err, tc.errMsg)
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
