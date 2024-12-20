package uzi_vc_validator

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
	"github.com/nuts-foundation/uzi-did-x509-issuer/ca_certs"
	"github.com/nuts-foundation/uzi-did-x509-issuer/did_x509"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
)

type UraValidator interface {
	Validate(jwtString []byte) bool
}

type UraValidatorImpl struct {
	allowUziTestCa    bool
	allowSelfSignedCa bool
}

func NewUraValidator(allowUziTestCa bool, allowSelfSignedCa bool) *UraValidatorImpl {
	return &UraValidatorImpl{allowUziTestCa, allowSelfSignedCa}
}

type JwtHeaderValues struct {
	X509CertThumbprint     string
	X509CertChain          *cert.Chain
	X509CertThumbprintS256 string
	Algorithm              jwa.SignatureAlgorithm
}

func (u UraValidatorImpl) Validate(jwtString string) error {
	credential, err := vc.ParseVerifiableCredential(jwtString)
	if err != nil {
		return err
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

	err = validateChain(signingCert, chainCertificates, u.allowUziTestCa, u.allowSelfSignedCa)
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

// func validateChain(signingCert *x509.Certificate, certificates []*x509.Certificate, includeTest bool) error {
func validateChain(signingCert *x509.Certificate, chain []*x509.Certificate, allowUziTestCa bool, allowSelfSignedCa bool) error {

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	var err error

	if allowSelfSignedCa {
		roots.AddCert(chain[len(chain)-1])
		for i := 1; i < len(chain)-1; i++ {
			intermediates.AddCert(chain[i])
		}
	} else {
		roots, intermediates, err = ca_certs.GetCertPools(allowUziTestCa)
		if err != nil {
			return err
		}
	}
	err = validate(signingCert, roots, intermediates)
	if err != nil {
		err = fmt.Errorf("could not validate against the CA pool. %s", err.Error())
		return err
	}
	return nil
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
