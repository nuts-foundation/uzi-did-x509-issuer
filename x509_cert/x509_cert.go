package x509_cert

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lestrrat-go/jwx/v2/cert"
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

func ParseUraFromOtherNameValue(stringValue string) (uzi string, ura string, agb string, err error) {
	submatch := RegexOtherNameValue.FindStringSubmatch(stringValue)
	if len(submatch) < 4 {
		return "", "", "", errors.New("failed to parse URA from OtherNameValue")
	}
	return submatch[1], submatch[2], submatch[3], nil
}
