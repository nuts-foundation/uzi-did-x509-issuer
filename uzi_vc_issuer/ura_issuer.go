package uzi_vc_issuer

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nuts-foundation/go-did/did"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/uzi-did-x509-issuer/did_x509"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
)

// filename represents a valid file name. The file must exist.
type fileName string

// nonEmptyBytes represents a non-empty byte slice.
type nonEmptyBytes []byte

// newFileName creates a new fileName from a string. It returns an error if the file does not exist.
func newFileName(name string) (fileName, error) {
	if _, err := os.Stat(name); err != nil {
		return fileName(""), err
	}

	return fileName(name), nil
}

// readFile reads a file and returns its content as nonEmptyBytes. It returns an error if the file does not exist or is empty.
func readFile(name fileName) (nonEmptyBytes, error) {
	bytes, err := os.ReadFile(string(name))
	if err != nil {
		return nil, err
	}
	if len(bytes) == 0 {
		return nil, errors.New("file is empty")
	}
	return nonEmptyBytes(bytes), nil
}

// pemBlocks represents a list of one or more PEM blocks.
type pemBlocks []*pem.Block

// parsePemBytes parses a nonEmptyBytes slice into a pemBlocks
// it returns an error if the input does not contain any PEM blocks.
func parsePemBytes(f nonEmptyBytes) (pemBlocks, error) {
	blocks := make([]*pem.Block, 0)
	for {
		block, rest := pem.Decode(f)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
		f = rest
	}

	if len(blocks) == 0 {
		return nil, errors.New("no PEM blocks found")
	}

	return blocks, nil
}

// parseCertificatesFromPemBlocks parses a list of PEM blocks into a list of x509.Certificate instances.
// It returns an error if any of the blocks cannot be parsed into a certificate.
func parseCertificatesFromPemBlocks(blocks pemBlocks) (certificateList, error) {
	certs := make([]*x509.Certificate, 0)
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// certificateList represents a non empty slice of x509.Certificate instances.
type certificateList []*x509.Certificate

// validCertificateChain represents a valid certificate chain.
type validCertificateChain certificateList
type privateKey *rsa.PrivateKey
type subjectDID string

// issueOptions contains values for options for issuing a UZI VC.
type issueOptions struct {
	allowTestUraCa             bool
	includePermanentIdentifier bool
	subjectAttributes          []x509_cert.SubjectTypeName
}

// Option is an interface for a function in the options pattern.
type Option = func(*issueOptions)

// X509Credential represents a JWT encoded X.509 credential.
type X509Credential string

var defaultIssueOptions = &issueOptions{
	allowTestUraCa:             false,
	includePermanentIdentifier: false,
	subjectAttributes:          []x509_cert.SubjectTypeName{},
}

func NewValidCertificateChain(fileName string) (validCertificateChain, error) {
	certFileName, err := newFileName(fileName)

	if err != nil {
		return nil, err
	}

	fileBytes, err := readFile(certFileName)
	if err != nil {
		return nil, err
	}
	pemBlocks, err := parsePemBytes(fileBytes)
	if err != nil {
		return nil, err
	}

	certs, err := parseCertificatesFromPemBlocks(pemBlocks)
	if err != nil {
		return nil, err
	}

	chain, err := newCertificateChain(certs)
	if err != nil {
		return nil, err
	}

	return chain, nil
}

func NewPrivateKey(fileName string) (privateKey, error) {
	keyFileName, err := newFileName(fileName)
	if err != nil {
		return nil, err
	}

	keyFileBytes, err := readFile(keyFileName)
	if err != nil {
		return nil, err
	}

	keyBlocks, err := parsePemBytes(keyFileBytes)
	if err != nil {
		return nil, err
	}

	key, err := newRSAPrivateKey(keyBlocks)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func NewSubjectDID(did string) (subjectDID, error) {
	return subjectDID(did), nil
}

// newRSAPrivateKey parses a DER-encoded private key into an *rsa.PrivateKey.
// It returns an error if the key is not in PKCS8 format or not an RSA key.
func newRSAPrivateKey(pemBlocks pemBlocks) (privateKey, error) {
	if len(pemBlocks) != 1 || pemBlocks[0].Type != "PRIVATE KEY" {
		return nil, errors.New("expected exactly one private key block")
	}
	block := pemBlocks[0]

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	if _, ok := key.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return key.(*rsa.PrivateKey), err
}

func Issue(chain validCertificateChain, key privateKey, subject subjectDID, optionFns ...Option) (*vc.VerifiableCredential, error) {
	options := defaultIssueOptions
	for _, fn := range optionFns {
		fn(options)
	}

	types := []x509_cert.SanTypeName{x509_cert.SanTypeOtherName}
	if options.includePermanentIdentifier {
		types = append(types, x509_cert.SanTypePermanentIdentifierValue)
		types = append(types, x509_cert.SanTypePermanentIdentifierAssigner)
	}

	did, err := did_x509.CreateDid(chain[0], chain[len(chain)-1], options.subjectAttributes, types...)
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
	subjectTypes, err := x509_cert.SelectSubjectTypes(signingCert, options.subjectAttributes...)
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
	template, err := uraCredential(did, signingCert.NotAfter, otherNameValues, subjectTypes, subject)
	if err != nil {
		return nil, err
	}
	return vc.CreateJWTVerifiableCredential(context.Background(), *template, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
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

		sign, err := jwt.Sign(token, jwt.WithKey(jwa.PS512, rsa.PrivateKey(*key), jws.WithProtectedHeaders(hdrs)))
		return string(sign), err
	})
}

// AllowTestUraCa allows the use of Test URA server certificates.
func AllowTestUraCa(allow bool) Option {
	return func(o *issueOptions) {
		o.allowTestUraCa = allow
	}
}

// IncludePermanentIdentifier includes the permanent identifier in the UZI VC.
func IncludePermanentIdentifier(include bool) Option {
	return func(o *issueOptions) {
		o.includePermanentIdentifier = include
	}
}

// SubjectAttributes sets the subject attributes to include in the UZI VC.
func SubjectAttributes(attributes ...x509_cert.SubjectTypeName) Option {
	return func(o *issueOptions) {
		o.subjectAttributes = attributes
	}
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

// newCertificateChain constructs a valid certificate chain from a given list of certificates and a starting signing certificate.
// It recursively finds parent certificates for non-root CAs and appends them to the chain.
// It assumes the list might not be in order.
// The returning chain contains the signing cert at the start and the root cert at the end.
func newCertificateChain(certs certificateList) (validCertificateChain, error) {
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
func uraCredential(issuer string, expirationDate time.Time, otherNameValues []*x509_cert.OtherNameValue, subjectTypes []*x509_cert.SubjectValue, subjectDID subjectDID) (*vc.VerifiableCredential, error) {
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
