package x509_cert

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	sha1sum := sha1.Sum([]byte("test"))
	sha256sum := sha256.Sum256([]byte("test"))
	sha384sum := sha3.Sum384([]byte("test"))
	sha512sum := sha512.Sum512([]byte("test"))
	testCases := []struct {
		name  string
		data  []byte
		alg   string
		hash  []byte
		error error
	}{
		{
			name: "SHA1",
			data: []byte("test"),
			alg:  "sha1",
			hash: sha1sum[:],
		},
		{
			name: "SHA256",
			data: []byte("test"),
			alg:  "sha256",
			hash: sha256sum[:],
		},
		{
			name: "SHA384",
			data: []byte("test"),
			alg:  "sha384",
			hash: sha384sum[:],
		},
		{
			name: "SHA512",
			data: []byte("test"),
			alg:  "sha512",
			hash: sha512sum[:],
		},
		{
			name:  "Unsupported",
			data:  []byte("test"),
			alg:   "unsupported",
			hash:  nil,
			error: fmt.Errorf("unsupported hash algorithm: %s", "unsupported"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := Hash(tc.data, tc.alg)
			if tc.error != nil {
				if err.Error() != tc.error.Error() {
					t.Errorf("unexpected error %v, want %v", err, tc.error)
				}
			}
			if !bytes.Equal(hash, tc.hash) {
				t.Errorf("unexpected hash %x, want %x", hash, tc.hash)
			}
		})
	}
}
func TestParseChain(t *testing.T) {
	_, chainPem, _, _, _, err := BuildCertChain("9907878")
	assert.NoError(t, err)
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
	_, _, _, privateKey, _, err := BuildCertChain("9907878")
	assert.NoError(t, err)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	assert.NoError(t, err)

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
