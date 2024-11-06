package did_x509

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"regexp"
	"slices"
	"strings"
)

type X509Did struct {
	Version                string
	RootCertificateHash    string
	RootCertificateHashAlg string
	Policies               []*x509_cert.OtherNameValue
}

// FormatDid constructs a decentralized identifier (DID) from a certificate chain and an optional policy.
// It returns the formatted DID string or an error if the root certificate or hash calculation fails.
func FormatDid(caCert *x509.Certificate, policy ...string) (string, error) {
	alg := "sha512"
	rootHash, err := x509_cert.Hash(caCert.Raw, alg)
	if err != nil {
		return "", err
	}
	encodeToString := base64.RawURLEncoding.EncodeToString(rootHash)
	fragments := []string{"did", "x509", "0", alg, encodeToString}
	return strings.Join([]string{strings.Join(fragments, ":"), strings.Join(policy, "::")}, "::"), nil
}

// CreateDid generates a Decentralized Identifier (DID) from a given certificate chain.
// It extracts the Unique Registration Address (URA) from the chain, creates a policy with it, and formats the DID.
// Returns the generated DID or an error if any step fails.
func CreateDid(signingCert, caCert *x509.Certificate, types ...x509_cert.SanTypeName) (string, error) {
	otherNames, err := x509_cert.FindSanTypes(signingCert)
	if err != nil {
		return "", err
	}
	var selectedOtherNames []*x509_cert.OtherNameValue
	for _, otherName := range otherNames {
		if slices.Contains(types, otherName.Type) {
			selectedOtherNames = append(selectedOtherNames, otherName)
		}
	}
	policies := CreatePolicies(selectedOtherNames)
	formattedDid, err := FormatDid(caCert, policies...)
	return formattedDid, err
}
func ParseDid(didString string) (*X509Did, error) {
	x509Did := X509Did{}
	didObj := did.MustParseDID(didString)
	if didObj.Method != "x509" {
		return nil, errors.New("invalid didString method")
	}
	fullIdString := didObj.ID
	idParts := strings.Split(fullIdString, "::")
	if len(idParts) < 2 {
		return nil, errors.New("invalid didString format, expected did:x509:0:alg:hash::(san:type:ura)+")
	}
	rootIdString := idParts[0]
	policyParsString := idParts[1:]
	regex := regexp.MustCompile(`0:(\w+):([^:]+)`)
	submatch := regex.FindStringSubmatch(rootIdString)
	if len(submatch) != 3 {
		return nil, errors.New("invalid didString format, expected didString:x509:0:alg:hash::san:type:ura")
	}
	x509Did.Version = "0"
	x509Did.RootCertificateHashAlg = submatch[1]
	x509Did.RootCertificateHash = submatch[2]

	for _, policyString := range policyParsString {
		regex := regexp.MustCompile(`(\w+):([^:]+):([^:]+)`)
		submatch := regex.FindStringSubmatch(policyString)
		if len(submatch) != 4 {
			return nil, errors.New("invalid didString format, expected didString:x509:0:alg:hash::san:type:ura")
		}
		x509Did.Policies = append(x509Did.Policies, &x509_cert.OtherNameValue{
			PolicyType: x509_cert.PolicyType(submatch[1]),
			Type:       x509_cert.SanTypeName(submatch[2]),
			Value:      submatch[3],
		})
	}

	return &x509Did, nil
}

// CreatePolicies constructs a policy string using the provided URA, fixed string "san", and "permanentIdentifier".
// It joins these components with colons and returns the resulting policy string.
func CreatePolicies(otherNames []*x509_cert.OtherNameValue) []string {
	var policies []string
	for _, otherName := range otherNames {
		fragments := []string{string(otherName.PolicyType), string(otherName.Type), otherName.Value}
		policy := strings.Join(fragments, ":")
		policies = append(policies, policy)
	}
	return policies
}

// FindRootCertificate traverses a chain of x509 certificates and returns the first certificate that is a CA.
func FindRootCertificate(chain []*x509.Certificate) (*x509.Certificate, error) {
	for _, cert := range chain {
		if x509_cert.IsRootCa(cert) {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("cannot find root certificate")
}
