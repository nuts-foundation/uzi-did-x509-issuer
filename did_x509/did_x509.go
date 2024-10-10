package did_x509

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"headease-nuts-pki-overheid-issuer/x509_cert"
	"regexp"
	"strings"
)

type X509Did struct {
	Version                string
	RootCertificateHash    string
	RootCertificateHashAlg string
	Ura                    string
	SanType                x509_cert.SanTypeName
}

// DidCreator is an interface for creating a DID (Decentralized Identifier) given a chain of x509 certificates.
// The CreateDid method takes a slice of x509.Certificate and returns a DID as a string and an error if any.
type DidCreator interface {
	CreateDid(chain *[]x509.Certificate) (string, error)
}

type DidParser interface {
	ParseDid(did string) (*X509Did, error)
}

// DefaultDidProcessor is responsible for creating Decentralized Identifiers (DIDs) based on certificate chain information.
type DefaultDidProcessor struct {
}

// NewDidCreator initializes and returns a new instance of DefaultDidProcessor.
func NewDidCreator() *DefaultDidProcessor {
	return &DefaultDidProcessor{}
}
func NewDidParser() *DefaultDidProcessor {
	return &DefaultDidProcessor{}
}

// FormatDid constructs a decentralized identifier (DID) from a certificate chain and an optional policy.
// It returns the formatted DID string or an error if the root certificate or hash calculation fails.
func FormatDid(chain *[]x509.Certificate, policy string) (string, error) {
	root, err := FindRootCertificate(chain)
	if err != nil {
		return "", err
	}
	alg := "sha512"
	rootHash, err := x509_cert.Hash(root.Raw, alg)
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
func (d *DefaultDidProcessor) CreateDid(chain *[]x509.Certificate) (string, error) {
	certificate, _, err := x509_cert.FindSigningCertificate(chain)
	if err != nil || certificate == nil {
		return "", err
	}
	ura, sanType, err := x509_cert.FindUra(certificate)
	if err != nil {
		return "", err
	}
	policy := CreatePolicy(ura, sanType)
	did, err := FormatDid(chain, policy)
	return did, err
}
func (d *DefaultDidProcessor) ParseDid(didString string) (*X509Did, error) {
	x509Did := X509Did{}
	didObj := did.MustParseDID(didString)
	if didObj.Method != "x509" {
		return nil, errors.New("invalid didString method")
	}
	regex := regexp.MustCompile(`0:(\w+):([^:]+)::san:([^:]+):(.+)`)
	submatch := regex.FindStringSubmatch(didObj.ID)
	if len(submatch) != 5 {
		return nil, errors.New("invalid didString format, expected didString:x509:0:alg:hash::san:type:ura")
	}
	x509Did.Version = "0"
	x509Did.RootCertificateHashAlg = submatch[1]
	x509Did.RootCertificateHash = submatch[2]
	x509Did.SanType = x509_cert.SanTypeName(submatch[3])
	x509Did.Ura = submatch[4]
	return &x509Did, nil
}

// CreatePolicy constructs a policy string using the provided URA, fixed string "san", and "permanentIdentifier".
// It joins these components with colons and returns the resulting policy string.
func CreatePolicy(ura string, sanType x509_cert.SanTypeName) string {
	fragments := []string{"san", string(sanType), ura}
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
