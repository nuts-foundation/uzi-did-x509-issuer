package did_x509

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"golang.org/x/crypto/sha3"
)

type HashAlg string

const (
	Sha1   HashAlg = "sha1"
	Sha256 HashAlg = "sha256"
	Sha384 HashAlg = "sha384"
	Sha512 HashAlg = "sha512"
)

// Hash computes the hash of the input data using the specified algorithm.
// Supported algorithms include "sha1", "sha256", "sha384", and "sha512".
// Returns the computed hash as a byte slice or an error if the algorithm is not supported.
func Hash(data []byte, alg HashAlg) ([]byte, error) {
	switch alg {
	case Sha1:
		sum := sha1.Sum(data)
		return sum[:], nil
	case Sha256:
		sum := sha256.Sum256(data)
		return sum[:], nil
	case Sha384:
		sum := sha3.Sum384(data)
		return sum[:], nil
	case Sha512:
		sum := sha512.Sum512(data)
		return sum[:], nil
	}
	return nil, fmt.Errorf("unsupported hash algorithm: %s", alg)
}

type X509Did struct {
	Version                string
	RootCertificateHash    string
	RootCertificateHashAlg string
	Policies               []*x509_cert.GenericNameValue
}

// FormatDid constructs a decentralized identifier (DID) from a certificate chain and an optional policy.
// It returns the formatted DID string or an error if the root certificate or hash calculation fails.
func FormatDid(issuerCert *x509.Certificate, hashAlg HashAlg, policy ...string) (*did.DID, error) {
	issuerCertHash, err := Hash(issuerCert.Raw, hashAlg)
	if err != nil {
		return nil, err
	}

	encodeToString := base64.RawURLEncoding.EncodeToString(issuerCertHash)
	fragments := []string{"did", "x509", "0", string(hashAlg), encodeToString}
	didString := strings.Join([]string{strings.Join(fragments, ":"), strings.Join(policy, "::")}, "::")
	return did.ParseDID(didString)
}

// CreateDid generates a Decentralized Identifier (DID) from a given certificate chain.
// It extracts the Unique Registration Address (URA) from the chain, creates a policy with it, and formats the DID.
// Returns the generated DID or an error if any step fails.
func CreateDid(signingCert, caCert *x509.Certificate, subjectAttributes []x509_cert.SubjectTypeName, types ...x509_cert.SanTypeName) (*did.DID, error) {
	otherNames, err := x509_cert.SelectSanTypes(signingCert, types...)
	if err != nil {
		return nil, err
	}
	policies := CreateOtherNamePolicies(otherNames)

	subjectTypes, err := x509_cert.SelectSubjectTypes(signingCert, subjectAttributes...)
	if err != nil {
		return nil, err
	}

	policies = append(policies, CreateSubjectPolicies(subjectTypes)...)

	formattedDid, err := FormatDid(caCert, Sha256, policies...)
	return formattedDid, err
}

// PercentEncode encodes a string using percent encoding.
// we can not use url.PathEscape because it does not escape : $ & + = : @ characters.
// See https://github.com/golang/go/issues/27559#issuecomment-449652574
func PercentEncode(input string) string {
	var encoded strings.Builder
	for _, r := range input {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			encoded.WriteRune(r)
		} else {
			encoded.WriteString(fmt.Sprintf("%%%02X", r))
		}
	}
	return encoded.String()
}

func ParseDid(didString string) (*X509Did, error) {
	x509Did := X509Did{}
	didObj, err := did.ParseDID(didString)
	if err != nil {
		return nil, err
	}
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
		value, err := url.PathUnescape(submatch[3])
		if err != nil {
			return nil, err
		}
		x509Did.Policies = append(x509Did.Policies, &x509_cert.GenericNameValue{
			PolicyType: x509_cert.PolicyType(submatch[1]),
			Type:       submatch[2],
			Value:      value,
		})
	}

	return &x509Did, nil
}

// CreateOtherNamePolicies constructs a policy string using the provided URA, fixed string "san", and "permanentIdentifier".
// It joins these components with colons and returns the resulting policy string.
func CreateOtherNamePolicies(otherNames []*x509_cert.OtherNameValue) []string {
	var policies []string
	for _, otherName := range otherNames {
		value := PercentEncode(otherName.Value)
		fragments := []string{string(otherName.PolicyType), string(otherName.Type), value}
		policy := strings.Join(fragments, ":")
		policies = append(policies, policy)
	}
	return policies
}

func CreateSubjectPolicies(subjectValues []*x509_cert.SubjectValue) []string {
	var policies []string
	for _, subjectValue := range subjectValues {
		value := PercentEncode(subjectValue.Value)
		fragments := []string{string(subjectValue.PolicyType), string(subjectValue.Type), value}
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
