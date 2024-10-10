package uzi_vc_issuer

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"headease-nuts-pki-overheid-issuer/ca_certs"
	"headease-nuts-pki-overheid-issuer/did_x509"
	pem2 "headease-nuts-pki-overheid-issuer/pem"
	"headease-nuts-pki-overheid-issuer/uzi_vc_validator"
	"headease-nuts-pki-overheid-issuer/x509_cert"
	"time"
)
import "github.com/nuts-foundation/go-did/vc"

type UraIssuer interface {

	// Issue generates a digital certificate from the given certificate file and signing key file for the subject.
	Issue(certificateFile string, signingKeyFile string, subjectDID string, subjectName string) (string, error)
}

// DefaultUraIssuer is responsible for building URA (UZI-register abonneenummer) Verifiable Credentials.
// It utilizes a DidCreator to generate Decentralized Identifiers (DIDs) given a chain of x509 certificates.
type DefaultUraIssuer struct {
	didCreator  did_x509.DidCreator
	chainParser x509_cert.ChainParser
}

// NewUraVcBuilder initializes and returns a new instance of DefaultUraIssuer with the provided DidCreator.
func NewUraVcBuilder(didCreator did_x509.DidCreator, chainParser x509_cert.ChainParser) *DefaultUraIssuer {
	return &DefaultUraIssuer{didCreator, chainParser}
}

// Issue generates a URA Verifiable Credential using provided certificate, signing key, subject DID, and subject name.
func (u DefaultUraIssuer) Issue(certificateFile string, signingKeyFile string, subjectDID string, subjectName string, test bool) (string, error) {
	reader := pem2.NewPemReader()
	certificate, err := reader.ParseFileOrPath(certificateFile, "CERTIFICATE")
	if err != nil {
		return "", err
	}
	_certificates, err := u.chainParser.ParseCertificates(certificate)
	if len(*_certificates) != 1 {
		err = fmt.Errorf("did not find exactly one certificate in file %s", certificateFile)
		return "", err
	}

	chain, err := ca_certs.GetDERs(test)
	if err != nil {
		return "", err
	}
	_chain := append(*chain, *certificate...)
	chain = &_chain

	signingKeys, err := reader.ParseFileOrPath(signingKeyFile, "PRIVATE KEY")
	if err != nil {
		return "", err
	}
	if signingKeys == nil {
		err := fmt.Errorf("no signing keys found")
		return "", err

	}
	var signingKey *[]byte
	if len(*signingKeys) == 1 {
		signingKey = &(*signingKeys)[0]
	} else {
		err := fmt.Errorf("no signing keys found")
		return "", err
	}
	privateKey, err := u.chainParser.ParsePrivateKey(signingKey)
	if err != nil {
		return "", err
	}

	certChain, err := u.chainParser.ParseCertificates(chain)
	if err != nil {
		return "", err
	}

	credential, err := u.BuildUraVerifiableCredential(certChain, privateKey, subjectDID, subjectName)
	if err != nil {
		return "", err
	}
	marshal, err := json.Marshal(credential)
	if err != nil {
		return "", err
	}
	validator := uzi_vc_validator.NewUraValidator(did_x509.NewDidParser(), test)
	jwtString := string(marshal)
	jwtString = jwtString[1:]                // Chop start
	jwtString = jwtString[:len(jwtString)-1] // Chop end
	err = validator.Validate(jwtString)
	if err != nil {
		return "", err
	}
	return jwtString, nil
}

// BuildUraVerifiableCredential constructs a verifiable credential with specified certificates, signing key, subject DID, and subject name.
func (v DefaultUraIssuer) BuildUraVerifiableCredential(certificates *[]x509.Certificate, signingKey *rsa.PrivateKey, subjectDID string, subjectName string) (*vc.VerifiableCredential, error) {
	signingCert, ura, err := x509_cert.FindSigningCertificate(certificates)
	if err != nil {
		return nil, err
	}
	chain := BuildCertificateChain(certificates, signingCert)
	err = validateChain(chain)
	if err != nil {
		return nil, err
	}
	did, err := v.didCreator.CreateDid(chain)
	if err != nil {
		return nil, err
	}
	serialNumber := signingCert.Subject.SerialNumber
	if serialNumber == "" {
		return nil, errors.New("serialNumber not found in signing certificate ")
	}
	uzi := serialNumber
	template, err := uraCredential(did, ura, uzi, subjectDID, subjectName)
	if err != nil {
		return nil, err
	}
	credential, err := vc.CreateJWTVerifiableCredential(context.Background(), template, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
		token, err := convertClaims(claims)
		if err != nil {
			return "", err
		}
		hdrs, err := convertHeaders(headers)
		if err != nil {
			return "", err
		}

		// x5c
		serializedCert, err := marshalChain(chain)
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
func marshalChain(certificates *[]x509.Certificate) (*cert.Chain, error) {
	chainPems := &cert.Chain{}
	for _, certificate := range *certificates {
		err := chainPems.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
		if err != nil {
			return nil, err
		}
	}
	headers, err := x509_cert.FixChainHeaders(chainPems)
	return headers, err
}

func validateChain(certificates *[]x509.Certificate) error {
	certs := *certificates
	var prev *x509.Certificate = nil
	for i := range certs {
		certificate := certs[len(certs)-i-1]
		if prev != nil {
			err := prev.CheckSignatureFrom(&certificate)
			if err != nil {
				return err
			}
		}
		if x509_cert.IsRootCa(&certificate) {
			return nil
		}
		prev = &certificate
	}
	return errors.New("failed to find a path to the root certificate in the chain, are you using a (Test) URA server certificate (Hint: the --test mode is required for Test URA server certificates)")
}

// BuildCertificateChain constructs a certificate chain from a given list of certificates and a starting signing certificate.
// It recursively finds parent certificates for non-root CAs and appends them to the chain.
func BuildCertificateChain(certs *[]x509.Certificate, signingCert *x509.Certificate) *[]x509.Certificate {
	var chain []x509.Certificate
	if signingCert == nil {
		return &chain
	}
	if !x509_cert.IsRootCa(signingCert) {
		for _, parent := range *certs {
			err := signingCert.CheckSignatureFrom(&parent)
			if err == nil {
				parentChain := BuildCertificateChain(certs, &parent)
				chain = append(chain, *parentChain...)
			}
		}
	}
	chain = append(chain, *signingCert)
	return &chain
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

// uraCredential generates a VerifiableCredential for a given URA and UZI number, including the subject's DID and name.
// It sets a 1-year expiration period from the current issuance date.
func uraCredential(did string, ura string, uzi string, subjectDID string, subjectName string) (vc.VerifiableCredential, error) {
	exp := time.Now().Add(time.Hour * 24 * 365)
	iat := time.Now()
	return vc.VerifiableCredential{
		Issuer:         ssi.MustParseURI(did),
		Context:        []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
		Type:           []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("UziServerCertificateCredential")},
		ID:             func() *ssi.URI { id := ssi.MustParseURI(uuid.NewString()); return &id }(),
		IssuanceDate:   iat,
		ExpirationDate: &exp,
		CredentialSubject: []interface{}{
			map[string]interface{}{
				"id":        subjectDID,
				"name":      subjectName,
				"uraNumber": ura,
				"uziNumber": uzi,
			},
		},
	}, nil
}