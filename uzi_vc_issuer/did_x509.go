package uzi_vc_issuer

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"
)

// DidCreator is an interface for creating a DID (Decentralized Identifier) given a chain of x509 certificates.
// The CreateDid method takes a slice of x509.Certificate and returns a DID as a string and an error if any.
type DidCreator interface {
	CreateDid(chain *[]x509.Certificate) (string, error)
}

// SubjectAlternativeNameType represents the ASN.1 Object Identifier for Subject Alternative Name.
var (
	SubjectAlternativeNameType = asn1.ObjectIdentifier{2, 5, 29, 17}
	PermanentIdentifierType    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	UraAssigner                = asn1.ObjectIdentifier{2, 16, 528, 1, 1007, 3, 3}
)

// DefaultDidCreator is responsible for creating Decentralized Identifiers (DIDs) based on certificate chain information.
type DefaultDidCreator struct {
}

// NewDidCreator initializes and returns a new instance of DefaultDidCreator.
func NewDidCreator() *DefaultDidCreator {
	return &DefaultDidCreator{}
}

// FormatDid constructs a decentralized identifier (DID) from a certificate chain and an optional policy.
// It returns the formatted DID string or an error if the root certificate or hash calculation fails.
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

// CreateDid generates a Decentralized Identifier (DID) from a given certificate chain.
// It extracts the Unique Registration Address (URA) from the chain, creates a policy with it, and formats the DID.
// Returns the generated DID or an error if any step fails.
func (d *DefaultDidCreator) CreateDid(chain *[]x509.Certificate) (string, error) {
	ura, err := FindUra(chain)
	if err != nil {
		return "", err
	}
	policy := CreatePolicy(ura)
	did, err := FormatDid(chain, policy)
	return did, err
}

// CreatePolicy constructs a policy string using the provided URA, fixed string "san", and "permanentIdentifier".
// It joins these components with colons and returns the resulting policy string.
func CreatePolicy(ura string) string {
	fragments := []string{"san", "permanentIdentifier", ura}
	policy := strings.Join(fragments, ":")
	return policy
}

// FindRootCertificate traverses a chain of x509 certificates and returns the first certificate that is a CA.
func FindRootCertificate(chain *[]x509.Certificate) (*x509.Certificate, error) {
	for _, cert := range *chain {
		if cert.IsCA {
			return &cert, nil
		}
	}
	return nil, fmt.Errorf("cannot find root certificate")
}
