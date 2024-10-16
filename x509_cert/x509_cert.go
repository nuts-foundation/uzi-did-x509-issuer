package x509_cert

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"golang.org/x/crypto/sha3"
	"regexp"
	"strings"
)

// SubjectAlternativeNameType represents the ASN.1 Object Identifier for Subject Alternative Name.
var (
	SubjectAlternativeNameType = asn1.ObjectIdentifier{2, 5, 29, 17}
	PermanentIdentifierType    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	OtherNameType              = asn1.ObjectIdentifier{2, 5, 5, 5}
	UraAssigner                = asn1.ObjectIdentifier{2, 16, 528, 1, 1007, 3, 3}
)

// RegexOtherNameValue matches thee OtherName field: <versie-nr>-<UZI-nr>-<pastype>-<Abonnee-nr>-<rol>-<AGB-code>
// e.g.: 1-123456789-S-88888801-00.000-12345678
// var RegexOtherNameValue = regexp.MustCompile(`2\.16\.528\.1\.1007.\d+\.\d+-\d+-\d+-S-(\d+)-00\.000-\d+`)
var RegexOtherNameValue = regexp.MustCompile(`^[0-9.]+-\d+-(\d+)-S-(\d+)-00\.000-(\d+)$`)

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

// ParseCertificates parses a slice of DER-encoded byte arrays into a slice of x509.Certificate.
// It returns an error if any of the certificates cannot be parsed.
func ParseCertificates(derChain [][]byte) ([]*x509.Certificate, error) {
	if derChain == nil {
		return nil, fmt.Errorf("derChain is nil")
	}
	chain := make([]*x509.Certificate, len(derChain))

	for i, certBytes := range derChain {
		certificate, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		chain[i] = certificate
	}

	return chain, nil
}

// ParsePrivateKey parses a DER-encoded private key into an *rsa.PrivateKey.
// It returns an error if the key is not in PKCS8 format or not an RSA key.
func ParsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if der == nil {
		return nil, fmt.Errorf("der is nil")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, err
		}
	}

	if _, ok := key.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return key.(*rsa.PrivateKey), err
}

// fixChainHeaders replaces newline characters in the certificate chain headers with escaped newline sequences.
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

func ParseUraFromOtherNameValue(value string) (uzi string, ura string, agb string, err error) {
	submatch := RegexOtherNameValue.FindStringSubmatch(value)
	if len(submatch) < 4 {
		return "", "", "", errors.New("failed to parse URA from OtherNameValue")
	}
	return submatch[1], submatch[2], submatch[3], nil
}
