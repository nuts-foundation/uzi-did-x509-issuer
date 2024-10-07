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

type ChainParser interface {
	ParseChain(chainPem []string) ([]*x509.Certificate, error)
}

type DefaultChainParser struct{}

func NewDefaultChainParser() *DefaultChainParser {
	return &DefaultChainParser{}
}

func (c DefaultChainParser) ParseChain(chainPem *[][]byte) (*[]x509.Certificate, error) {
	if chainPem == nil {
		return nil, fmt.Errorf("chainPem is nil")
	}
	chain := make([]x509.Certificate, len(*chainPem))

	for i, certBytes := range *chainPem {
		certificate, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		chain[i] = *certificate
	}

	return &chain, nil
}
func (c DefaultChainParser) ParsePrivateKey(der *[]byte) (*rsa.PrivateKey, error) {
	if der == nil {
		return nil, fmt.Errorf("der is nil")
	}
	key, err := x509.ParsePKCS8PrivateKey(*der)
	return key.(*rsa.PrivateKey), err
}
