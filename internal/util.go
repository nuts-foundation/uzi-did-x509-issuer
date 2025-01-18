package internal

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"strings"
)

// FixChainHeaders replaces newline characters in the certificate chain headers with escaped newline sequences.
// It processes each certificate in the provided chain and returns a new chain with the modified headers or an error if any occurs.
func FixChainHeaders(chain *cert.Chain) (*cert.Chain, error) {
	rv := &cert.Chain{}
	for i := 0; i < chain.Len(); i++ {
		value, _ := chain.Get(i)
		der := strings.ReplaceAll(string(value), "\n", "\\n")
		err := rv.AddString(der)
		if err != nil {
			return nil, err
		}
	}
	return rv, nil
}

// ParseCertificatesFromPEM reads a list of certificates from the given data.
func ParseCertificatesFromPEM(data []byte) ([]*x509.Certificate, error) {
	pemBlocks, err := parsePemBytes(data)
	if err != nil {
		return nil, err
	}

	certs := make([]*x509.Certificate, 0)
	for _, block := range pemBlocks {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// ParseCertificateChain constructs a valid certificate chain from a given list of certificates and a starting signing certificate.
// It recursively finds parent certificates for non-root CAs and appends them to the chain.
// It assumes the list might not be in order.
// The returning chain contains the signing cert at the start and the root cert at the end.
func ParseCertificateChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	var signingCert *x509.Certificate
	for _, c := range certs {
		if c != nil && !c.IsCA {
			signingCert = c
			break
		}
	}
	if signingCert == nil {
		return nil, errors.New("failed to find signing certificate")
	}

	var chain []*x509.Certificate
	chain = append(chain, signingCert)

	certToCheck := signingCert
	for !isRootCa(certToCheck) {
		found := false
		for _, c := range certs {
			if c == nil || c.Equal(signingCert) {
				continue
			}
			err := certToCheck.CheckSignatureFrom(c)
			if err == nil {
				chain = append(chain, c)
				certToCheck = c
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("failed to find path from signingCert to root")
		}
	}
	return chain, nil
}

// ParseRSAPrivateKeyFromPEM reads a RSA private key from the given data.
// It returns an error if the key cannot be parsed.
func ParseRSAPrivateKeyFromPEM(data []byte) (*rsa.PrivateKey, error) {
	pemBlocks, err := parsePemBytes(data)
	if err != nil {
		return nil, err
	}
	if len(pemBlocks) != 1 {
		return nil, errors.New("expected exactly one PEM block")
	}
	return newRSAPrivateKey(pemBlocks[0])
}

// newRSAPrivateKey parses a DER-encoded private key into an *rsa.PrivateKey.
// It returns an error if the key is not in PKCS8 format or not an RSA key.
func newRSAPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("expected PEM block type to be PRIVATE KEY or RSA PRIVATE KEY")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return key.(*rsa.PrivateKey), err
}

// parsePemBytes parses a nonEmptyBytes slice into a pemBlocks
// it returns an error if the input does not contain any PEM blocks.
func parsePemBytes(f []byte) ([]*pem.Block, error) {
	blocks := make([]*pem.Block, 0)
	for {
		block, rest := pem.Decode(f)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
		f = rest
	}

	if len(blocks) == 0 {
		return nil, errors.New("no PEM blocks found")
	}

	return blocks, nil
}

func isRootCa(signingCert *x509.Certificate) bool {
	return signingCert.IsCA && bytes.Equal(signingCert.RawIssuer, signingCert.RawSubject)
}
