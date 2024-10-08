package ura_vc

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"strings"
	"time"
)
import "github.com/nuts-foundation/go-did/vc"

// UraVcBuilder is responsible for building URA (UZI-register abonneenummer) Verifiable Credentials.
// It utilizes a DidCreator to generate Decentralized Identifiers (DIDs) given a chain of x509 certificates.
type UraVcBuilder struct {
	didCreator DidCreator
}

// NewUraVcBuilder initializes and returns a new instance of UraVcBuilder with the provided DidCreator.
func NewUraVcBuilder(didCreator DidCreator) *UraVcBuilder {
	return &UraVcBuilder{didCreator}
}

// BuildUraVerifiableCredential constructs a verifiable credential with specified certificates, signing key, subject DID, and subject name.
func (v UraVcBuilder) BuildUraVerifiableCredential(certs *[]x509.Certificate, signingKey *rsa.PrivateKey, subjectDID string, subjectName string) (*vc.VerifiableCredential, error) {
	signingCert, ura, err := FindSigningCertificate(certs)
	if err != nil {
		return nil, err
	}
	did, err := v.didCreator.CreateDid(certs)
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
		serializedCert, err := marshalChain(certs, signingCert)
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
func marshalChain(certificates *[]x509.Certificate, signingCert *x509.Certificate) (*cert.Chain, error) {
	certificates = BuildCertificateChain(certificates, signingCert)
	err := validateChain(certificates)
	if err != nil {
		return nil, err
	}
	chainPems := &cert.Chain{}
	for _, certificate := range *certificates {
		bytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
		err := chainPems.Add(bytes)
		if err != nil {
			return nil, err
		}
	}
	headers, err := fixChainHeaders(chainPems)
	return headers, err
}

func validateChain(certificates *[]x509.Certificate) error {
	certs := *certificates
	var prev *x509.Certificate = nil
	for i, _ := range certs {
		certificate := certs[len(certs)-i-1]
		if prev != nil {
			err := prev.CheckSignatureFrom(&certificate)
			if err != nil {
				return err
			}
		}
		if isRootCa(&certificate) {
			return nil
		}
		prev = &certificate
	}
	return errors.New("failed to find a root certificate in chain")
}

func BuildCertificateChain(certs *[]x509.Certificate, signingCert *x509.Certificate) *[]x509.Certificate {
	var chain []x509.Certificate
	if signingCert == nil {
		return &chain
	}
	if !isRootCa(signingCert) {
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

func isRootCa(signingCert *x509.Certificate) bool {
	return signingCert.IsCA && bytes.Equal(signingCert.RawIssuer, signingCert.RawSubject)
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
// It sets a 12-year expiration period from the current issuance date.
func uraCredential(did string, ura string, uzi string, subjectDID string, subjectName string) (vc.VerifiableCredential, error) {
	exp := time.Now().Add(time.Hour * 24 * 365 * 12)
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

// fixChainHeaders replaces newline characters in the certificate chain headers with escaped newline sequences.
// It processes each certificate in the provided chain and returns a new chain with the modified headers or an error if any occurs.
func fixChainHeaders(chain *cert.Chain) (*cert.Chain, error) {
	rv := &cert.Chain{}
	for i := 0; i < chain.Len(); i++ {
		value, _ := chain.Get(i)
		der := strings.ReplaceAll(string(value), "\n", "\\n")
		err := rv.AddString(der)
		if err != nil {
			return nil, err
		}
	}
	return rv, nil
}

//func buildX509Credential(chainPems *cert.Chain, signingCert *x509.Certificate, rootCert *x509.Certificate, signingKey *rsa.PrivateKey, ura string) (*vc.VerifiableCredential, error) {
//	headers := map[string]interface{}{}
//	headers["x5c"] = chainPems
//	hashSha1 := sha1.Sum(signingCert.Raw)
//	headers["x5t"] = base64.RawURLEncoding.EncodeToString(hashSha1[:])
//
//	hashSha256 := sha256.Sum256(rootCert.Raw)
//	rootCertHashBytes := hashSha256[:]
//	rootCertHashStr := base64.RawURLEncoding.EncodeToString(rootCertHashBytes)
//	did := "did:x509:0:sha256:" + rootCertHashStr + "::subject:serialNumber:" + ura
//	headers["kid"] = did
//
//	claims := map[string]interface{}{}
//	claims["iss"] = did
//	claims["sub"] = did
//	credential, err := uraCredential(did, ura)
//	if err != nil {
//		return nil, err
//	}
//
//	claims["vc"] = *credential
//
//	token, err := nutsCrypto.SignJWT(audit.TestContext(), signingKey, jwa.PS512, claims, headers)
//	if err != nil {
//		return nil, err
//	}
//	cred, err := vc.ParseVerifiableCredential(token)
//	if err != nil {
//		return nil, err
//	}
//	return cred, nil
//}
