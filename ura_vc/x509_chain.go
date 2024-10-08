package ura_vc

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"golang.org/x/crypto/sha3"
)

// Hash computes the hash of the input data using the specified algorithm.
// Supported algorithms include "sha1", "sha256", "sha384", and "sha512".
// Returns the computed hash as a byte slice or an error if the algorithm is not supported.
func Hash(data []byte, alg string) ([]byte, error) {
	switch alg {
	case "sha1":
		sum := sha1.Sum(data)
		return sum[:], nil
	case "sha256":
		sum := sha256.Sum256(data)
		return sum[:], nil
	case "sha384":
		sum := sha3.Sum384(data)
		return sum[:], nil
	case "sha512":
		sum := sha512.Sum512(data)
		return sum[:], nil
	}
	return nil, fmt.Errorf("unsupported hash algorithm: %s", alg)
}

// ChainParser defines an interface for parsing certificate chains from PEM encoded string slices.
type ChainParser interface {
	ParseChain(chainPem []string) ([]*x509.Certificate, error)
}

// DefaultChainParser handles the parsing of certificate chains and private keys.
type DefaultChainParser struct{}

// NewDefaultChainParser creates a new instance of DefaultChainParser.
func NewDefaultChainParser() *DefaultChainParser {
	return &DefaultChainParser{}
}

// ParseChain takes a pointer to a slice of DER-encoded certificates and returns a slice of x509.Certificate objects.
func (c DefaultChainParser) ParseChain(derChain *[][]byte) (*[]x509.Certificate, error) {
	if derChain == nil {
		return nil, fmt.Errorf("derChain is nil")
	}
	chain := make([]x509.Certificate, len(*derChain))

	for i, certBytes := range *derChain {
		certificate, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		chain[i] = *certificate
	}

	return &chain, nil
}

// ParsePrivateKey parses a DER-encoded private key into an *rsa.PrivateKey.
// It returns an error if the key is not in PKCS8 format or not an RSA key.
func (c DefaultChainParser) ParsePrivateKey(der *[]byte) (*rsa.PrivateKey, error) {
	if der == nil {
		return nil, fmt.Errorf("der is nil")
	}
	key, err := x509.ParsePKCS8PrivateKey(*der)
	if err != nil {
		return nil, err
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return key.(*rsa.PrivateKey), err
}
