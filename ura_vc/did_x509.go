package ura_vc

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"
)

type DidCreator interface {
	CreateDid(chain *[]x509.Certificate) (string, error)
}

var (
	SubjectAlternativeNameType = asn1.ObjectIdentifier{2, 5, 29, 17}
	PermanentIdentifierType    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	UraAssigner                = asn1.ObjectIdentifier{2, 16, 528, 1, 1007, 3, 3}
)

type DefaultDidCreator struct {
}

func NewDidCreator() *DefaultDidCreator {
	return &DefaultDidCreator{}
}

func FormatDid(chain *[]x509.Certificate, policy string) (string, error) {
	root, err := FindRootCertificate(chain)
	if err != nil {
		return "", err
	}
	alg := "sha512"
	rootHash, err := Hash(root.Raw, alg)
	if err != nil {
		return "", err
	}
	encodeToString := base64.RawURLEncoding.EncodeToString(rootHash)
	fragments := []string{"did", "x509", "0", alg, encodeToString}
	if policy != "" {
		return strings.Join([]string{strings.Join(fragments, ":"), policy}, "::"), nil
	}
	return strings.Join(fragments, ":"), nil
}

// CreateDid generates a DID (Decentralized Identifier) based on a certificate chain and associated policy.
// It extracts the required policy from the chain and formats the DID accordingly.
// It returns the generated DID string and an error if any step in the process fails.
func (d *DefaultDidCreator) CreateDid(chain *[]x509.Certificate) (string, error) {
	ura, err := FindUra(chain)
	if err != nil {
		return "", err
	}
	policy := CreatePolicy(ura)
	did, err := FormatDid(chain, policy)
	return did, err
}

func CreatePolicy(ura string) string {
	fragments := []string{"san", "permanentIdentifier", ura}
	policy := strings.Join(fragments, ":")
	return policy
}

func FindRootCertificate(chain *[]x509.Certificate) (*x509.Certificate, error) {
	for _, cert := range *chain {
		if cert.IsCA {
			return &cert, nil
		}
	}
	return nil, fmt.Errorf("cannot find root certificate")
}
