package credential_verifier

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-didx509-toolkit/credential_issuer"
	"github.com/nuts-foundation/go-didx509-toolkit/did_x509"
	"github.com/nuts-foundation/go-didx509-toolkit/internal"
	"github.com/nuts-foundation/go-didx509-toolkit/x509_cert"
)

type JwtHeaderValues struct {
	X509CertThumbprint     string
	X509CertChain          *cert.Chain
	X509CertThumbprintS256 string
	Algorithm              jwa.SignatureAlgorithm
}

// Verify parses the given Verifiable Credential and checks whether it's a valid X509Credential:
// - It checks if the credential is of type X509Credential.
// - It checks whether the credential issuer is a valid did:x509 DID.
// - It checks whether the credential proof if valid.
// - It verifies the did:x509 policies.
// Note: it does NOT check whether the Verifiable Credential subject only contains fields from the did:x509 policies!
func Verify(jwtString string) error {
	credential, err := vc.ParseVerifiableCredential(jwtString)
	if err != nil {
		return err
	}
	if !credential.IsType(credential_issuer.CredentialType) {
		return fmt.Errorf("credential is not of type %s", credential_issuer.CredentialType)
	}
	parseDid, err := did_x509.ParseDid(credential.Issuer.String())
	if err != nil {
		return err
	}
	headerValues, err := parseJwtHeaderValues(jwtString)
	if err != nil {
		return err
	}

	chainCertificates, err := parseCertificate(headerValues.X509CertChain)
	if err != nil {
		return err
	}

	signingCert, err := findSigningCertificate(chainCertificates, headerValues.X509CertThumbprint)
	if err != nil {
		return err
	}

	err = validateChain(signingCert, chainCertificates)
	if err != nil {
		return err
	}

	var options []jwt.ParseOption
	options = append(options, jwt.WithKey(headerValues.Algorithm, signingCert.PublicKey))
	options = append(options, jwt.WithVerify(true))

	_, err = jwt.ParseString(jwtString, options...)
	if err != nil {
		return err
	}
	otherNames, err := x509_cert.FindSanTypes(signingCert)
	if err != nil {
		return err
	}
	subjectTypes, err := x509_cert.FindSubjectTypes(signingCert)
	if err != nil {
		return err
	}
	for _, policy := range parseDid.Policies {
		found, err := checkForPolicy(policy, otherNames, subjectTypes)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("unable to locate a value for %s of policy %s", policy.Type, policy.PolicyType)
		}
	}
	return nil
}

func checkForPolicy(policy *x509_cert.GenericNameValue, otherNames []*x509_cert.OtherNameValue, subjectTypes []*x509_cert.SubjectValue) (bool, error) {
	switch policy.PolicyType {
	case x509_cert.PolicyTypeSan:
		found, err := checkForOtherNamePolicy(otherNames, policy)
		if err != nil {
			return false, err
		}
		return found, nil
	case x509_cert.PolicyTypeSubject:
		found, err := checkForSubjectPolicy(subjectTypes, policy)
		if err != nil {
			return false, err
		}
		return found, nil
	default:
		return false, fmt.Errorf("unknown policy type %s", policy.PolicyType)
	}
}

func checkForSubjectPolicy(subjectTypes []*x509_cert.SubjectValue, policy *x509_cert.GenericNameValue) (bool, error) {
	for _, subjectType := range subjectTypes {
		if string(subjectType.Type) == policy.Type && subjectType.PolicyType == policy.PolicyType {
			if policy.Value != subjectType.Value {
				return false, fmt.Errorf("%s value %s of policy %s in credential does not match according value in signing certificate", subjectType.Type, subjectType.Type, subjectType.PolicyType)
			} else {
				return true, nil
			}
		}
	}
	return false, nil
}

func checkForOtherNamePolicy(otherNames []*x509_cert.OtherNameValue, policy *x509_cert.GenericNameValue) (bool, error) {
	for _, otherName := range otherNames {
		if string(otherName.Type) == policy.Type && otherName.PolicyType == policy.PolicyType {
			if policy.Value != otherName.Value {
				return false, fmt.Errorf("%s value %s of policy %s in credential does not match according value in signing certificate", otherName.Type, otherName.Type, otherName.PolicyType)
			} else {
				return true, nil
			}
		}
	}
	return false, nil
}

func validateChain(signingCert *x509.Certificate, chain []*x509.Certificate) error {
	parsedChain, err := internal.ParseCertificateChain(chain)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsedChain[len(parsedChain)-1])
	intermediates := x509.NewCertPool()
	for i := 1; i < len(parsedChain)-1; i++ {
		intermediates.AddCert(parsedChain[i])
	}
	return validate(signingCert, roots, intermediates)
}

func validate(signingCert *x509.Certificate, roots *x509.CertPool, intermediates *x509.CertPool) error {
	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       "",
		Intermediates: intermediates,
	}
	if _, err := signingCert.Verify(opts); err != nil {
		return err
	}
	return nil
}

func findSigningCertificate(certificates []*x509.Certificate, thumbprint string) (*x509.Certificate, error) {
	for _, c := range certificates {
		hashSha1 := sha1.Sum(c.Raw)
		hashedCert := base64.RawURLEncoding.EncodeToString(hashSha1[:])
		if hashedCert == thumbprint {
			return c, nil
		}
	}
	return nil, fmt.Errorf("Could not find certificate with thumbprint %s", thumbprint)
}

func parseCertificate(chain *cert.Chain) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for i := 0; i < chain.Len(); i++ {
		bytes, _ := chain.Get(i)
		der, err := base64.StdEncoding.DecodeString(string(bytes))
		if err != nil {
			return nil, err
		}
		found, err := x509.ParseCertificates(der)
		if err != nil {
			return nil, err
		}
		for _, c := range found {
			if c != nil {
				certificates = append(certificates, c)
			}
		}
	}
	return certificates, nil
}

func parseJwtHeaderValues(jwtString string) (*JwtHeaderValues, error) {
	message, err := jws.ParseString(jwtString)
	if err != nil {
		return nil, err
	}
	metadata := &JwtHeaderValues{}
	if message != nil && len(message.Signatures()) > 0 {
		headers := message.Signatures()[0].ProtectedHeaders()
		metadata.X509CertThumbprint = headers.X509CertThumbprint()
		metadata.X509CertChain = headers.X509CertChain()
		metadata.X509CertThumbprintS256 = headers.X509CertThumbprintS256()
		metadata.Algorithm = headers.Algorithm()
	}
	return metadata, nil
}
