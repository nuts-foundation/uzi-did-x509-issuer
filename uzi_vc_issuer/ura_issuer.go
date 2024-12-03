package uzi_vc_issuer

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/uzi-did-x509-issuer/ca_certs"
	"github.com/nuts-foundation/uzi-did-x509-issuer/did_x509"
	pem2 "github.com/nuts-foundation/uzi-did-x509-issuer/pem"
	"github.com/nuts-foundation/uzi-did-x509-issuer/uzi_vc_validator"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
)

// Issue generates a URA Verifiable Credential using provided certificate, signing key, subject DID, and subject name.
func Issue(certificateFile string, signingKeyFile string, subjectDID string, allowTestUraCa bool, includePermanentIdentifier bool, subjectAttributes []x509_cert.SubjectTypeName) (string, error) {
	pemBlocks, err := pem2.ParseFileOrPath(certificateFile, "CERTIFICATE")
	if err != nil {
		return "", err
	}
	allowSelfSignedCa := len(pemBlocks) > 1
	if len(pemBlocks) == 1 {
		certificate := pemBlocks[0]
		pemBlocks, err = ca_certs.GetDERs(allowTestUraCa)
		if err != nil {
			return "", err
		}
		pemBlocks = append(pemBlocks, certificate)
	}

	signingKeys, err := pem2.ParseFileOrPath(signingKeyFile, "PRIVATE KEY")
	if err != nil {
		return "", err
	}
	if len(signingKeys) == 0 {
		err := fmt.Errorf("no signing keys found")
		return "", err
	}
	privateKey, err := x509_cert.ParsePrivateKey(signingKeys[0])
	if err != nil {
		return "", err
	}

	certs, err := x509_cert.ParseCertificates(pemBlocks)
	if err != nil {
		return "", err
	}

	chain, err := BuildCertificateChain(certs)
	if err != nil {
		return "", err
	}
	err = validateChain(chain)
	if err != nil {
		return "", err
	}
	types := []x509_cert.SanTypeName{x509_cert.SanTypeOtherName}
	if includePermanentIdentifier {
		types = append(types, x509_cert.SanTypePermanentIdentifierValue)
		types = append(types, x509_cert.SanTypePermanentIdentifierAssigner)
	}
	credential, err := BuildUraVerifiableCredential(chain, privateKey, subjectDID, subjectAttributes, types...)
	if err != nil {
		return "", err
	}
	jwtString := credential.Raw()
	validator := uzi_vc_validator.NewUraValidator(allowTestUraCa, allowSelfSignedCa)
	err = validator.Validate(jwtString)
	if err != nil {
		return "", err
	}
	return jwtString, nil
}

// BuildUraVerifiableCredential constructs a verifiable credential with specified certificates, signing key, subject DID.
func BuildUraVerifiableCredential(chain []*x509.Certificate, signingKey *rsa.PrivateKey, subjectDID string, subjectAttributes []x509_cert.SubjectTypeName, types ...x509_cert.SanTypeName) (*vc.VerifiableCredential, error) {
	if len(chain) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	if signingKey == nil {
		return nil, errors.New("signing key is nil")
	}
	did, err := did_x509.CreateDid(chain[0], chain[len(chain)-1], subjectAttributes, types...)
	if err != nil {
		return nil, err
	}
	// signing cert is at the start of the chain
	signingCert := chain[0]
	serialNumber := signingCert.Subject.SerialNumber
	if serialNumber == "" {
		return nil, errors.New("serialNumber not found in signing certificate")
	}
	otherNameValues, err := x509_cert.FindSanTypes(signingCert)
	if err != nil {
		return nil, err
	}
	subjectTypes, err := x509_cert.SelectSubjectTypes(signingCert, subjectAttributes...)
	if err != nil {
		return nil, err
	}
	stringValue, err := x509_cert.FindOtherNameValue(otherNameValues, x509_cert.PolicyTypeSan, x509_cert.SanTypeOtherName)
	uzi, _, _, err := x509_cert.ParseUraFromOtherNameValue(stringValue)
	if err != nil {
		return nil, err
	}
	if uzi != serialNumber {
		return nil, errors.New("serial number does not match UZI number")
	}
	template, err := uraCredential(did, signingCert.NotAfter, otherNameValues, subjectTypes, subjectDID)
	if err != nil {
		return nil, err
	}
	credential, err := vc.CreateJWTVerifiableCredential(context.Background(), *template, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
		token, err := convertClaims(claims)
		if err != nil {
			return "", err
		}
		hdrs, err := convertHeaders(headers)
		if err != nil {
			return "", err
		}

		if hdrs.KeyID() == "" {
			err := hdrs.Set("kid", did+"#0")
			if err != nil {
				return "", err
			}
		}

		// x5c
		serializedCert, err := marshalChain(chain...)
		if err != nil {
			return "", err
		}
		err = hdrs.Set("x5c", serializedCert)
		if err != nil {
			return "", err
		}

		// x5t
		hashSha1 := sha1.Sum(signingCert.Raw)
		err = hdrs.Set("x5t", base64.RawURLEncoding.EncodeToString(hashSha1[:]))
		if err != nil {
			return "", err
		}

		sign, err := jwt.Sign(token, jwt.WithKey(jwa.PS512, signingKey, jws.WithProtectedHeaders(hdrs)))
		return string(sign), err
	})
	if err != nil {
		return nil, err
	}
	return credential, nil
}

// marshalChain converts a slice of x509.Certificate instances to a cert.Chain, encoding each certificate as PEM.
// It returns the PEM-encoded cert.Chain and an error if the encoding or header fixation fails.
func marshalChain(certificates ...*x509.Certificate) (*cert.Chain, error) {
	chainPems := &cert.Chain{}
	for _, certificate := range certificates {
		err := chainPems.Add([]byte(base64.StdEncoding.EncodeToString(certificate.Raw)))
		if err != nil {
			return nil, err
		}
	}
	headers, err := x509_cert.FixChainHeaders(chainPems)
	return headers, err
}

func validateChain(certs []*x509.Certificate) error {
	var prev *x509.Certificate = nil
	for i := range certs {
		certificate := certs[len(certs)-i-1]
		if prev != nil {
			err := prev.CheckSignatureFrom(certificate)
			if err != nil {
				return err
			}
		}
		if x509_cert.IsRootCa(certificate) {
			return nil
		}
		prev = certificate
	}
	return errors.New("failed to find a path to the root certificate in the chain, are you using a (Test) URA server certificate (Hint: the --test mode is required for Test URA server certificates)")
}

// BuildCertificateChain constructs a certificate chain from a given list of certificates and a starting signing certificate.
// It recursively finds parent certificates for non-root CAs and appends them to the chain.
// It assumes the list might not be in order.
// The returning chain contains the signing cert at the start and the root cert at the end.
func BuildCertificateChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	var signingCert *x509.Certificate
	for _, c := range certs {
		if c != nil && !c.IsCA {
			signingCert = c
			break
		}
	}
	if signingCert == nil {
		return nil, errors.New("failed to find signing certificate")
	}

	var chain []*x509.Certificate
	chain = append(chain, signingCert)

	certToCheck := signingCert
	for !x509_cert.IsRootCa(certToCheck) {
		found := false
		for _, c := range certs {
			if c == nil || c.Equal(signingCert) {
				continue
			}
			err := certToCheck.CheckSignatureFrom(c)
			if err == nil {
				chain = append(chain, c)
				certToCheck = c
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("failed to find path from signingCert to root")
		}
	}
	return chain, nil
}

// convertClaims converts a map of claims to a JWT token.
func convertClaims(claims map[string]interface{}) (jwt.Token, error) {
	t := jwt.New()
	for k, v := range claims {
		if err := t.Set(k, v); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// convertHeaders converts a map of headers to jws.Headers, returning an error if any header fails to set.
func convertHeaders(headers map[string]interface{}) (jws.Headers, error) {
	hdr := jws.NewHeaders()

	for k, v := range headers {
		if err := hdr.Set(k, v); err != nil {
			return nil, err
		}
	}
	return hdr, nil
}

// uraCredential generates a VerifiableCredential for a given URA and UZI number, including the subject's DID.
// It sets a 1-year expiration period from the current issuance date.
func uraCredential(issuer string, expirationDate time.Time, otherNameValues []*x509_cert.OtherNameValue, subjectTypes []*x509_cert.SubjectValue, subjectDID string) (*vc.VerifiableCredential, error) {
	iat := time.Now()
	subject := map[string]interface{}{
		"id": subjectDID,
	}
	for _, otherNameValue := range otherNameValues {
		subject[string(otherNameValue.Type)] = otherNameValue.Value
	}

	for _, subjectType := range subjectTypes {
		subject[string(subjectType.Type)] = subjectType.Value
	}

	id := did.DIDURL{
		DID:      did.MustParseDID(issuer),
		Fragment: uuid.NewString(),
	}.URI()
	return &vc.VerifiableCredential{
		Issuer:            ssi.MustParseURI(issuer),
		Context:           []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
		Type:              []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("UziServerCertificateCredential")},
		ID:                &id,
		IssuanceDate:      iat,
		ExpirationDate:    &expirationDate,
		CredentialSubject: []interface{}{subject},
	}, nil
}
