package did_x509

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-didx509-toolkit/x509_cert"
	"net/url"
	"regexp"
	"strings"
)

// hashAlg is the default hash algorithm used for hashing issuerCertificate
const hashAlg = "sha256"

// newHashFn is the default hash function used for hashing issuerCertificate
var newHashFn = sha256.New

type X509Did struct {
	Version                string
	RootCertificateHash    string
	RootCertificateHashAlg string
	Policies               []*x509_cert.GenericNameValue
}

// FormatDid constructs a decentralized identifier (DID) from a certificate chain and an optional policy.
// It returns the formatted DID string or an error if the root certificate or hash calculation fails.
func FormatDid(issuerCert *x509.Certificate, policy ...string) (*did.DID, error) {
	hasher := newHashFn()
	hasher.Write(issuerCert.Raw)
	sum := hasher.Sum(nil)

	b64EncodedHash := base64.RawURLEncoding.EncodeToString(sum[:])
	fragments := []string{"did", "x509", "0", hashAlg, b64EncodedHash}
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

	formattedDid, err := FormatDid(caCert, policies...)
	return formattedDid, err
}

// PercentEncode encodes a string using percent encoding.
// we can not use url.PathEscape because it does not escape : $ & + = : @ characters.
// See https://github.com/golang/go/issues/27559#issuecomment-449652574
func PercentEncode(input string) string {
	var encoded strings.Builder
	// Unicode characters might consist of multiple bytes, so first we encode the string using url.PathEscape (which supports multi-byte characters),
	// then we encode the characters that weren't encoded by url.PathEscape, but need to be encoded according to the DID specification.
	preEscaped := url.PathEscape(input)
	encoded.Grow(len(preEscaped))
	for _, r := range preEscaped {
		if r == '%' ||
			(r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '.' || r == '_' {
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
