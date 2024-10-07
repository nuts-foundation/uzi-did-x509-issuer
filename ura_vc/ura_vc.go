package ura_vc

import (
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

type UraVcBuilder struct {
	didCreator DidCreator
}

func NewUraVcBuilder(didCreator DidCreator) *UraVcBuilder {
	return &UraVcBuilder{didCreator}
}

func (v UraVcBuilder) BuildUraVerifiableCredential(certs *[]x509.Certificate, signingKey *rsa.PrivateKey, subjectDID string, subjectName string) (*vc.VerifiableCredential, error) {
	signingCert, ura, err := FindSigningCertificate(certs)
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
		serializedCert, err := marshalChain(certs)
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

func marshalChain(certs *[]x509.Certificate) (*cert.Chain, error) {
	chainPems := &cert.Chain{}
	for _, certificate := range *certs {
		bytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
		err := chainPems.Add(bytes)
		if err != nil {
			return nil, err
		}
	}
	headers, err := fixChainHeaders(chainPems)
	return headers, err
}

func convertClaims(claims map[string]interface{}) (jwt.Token, error) {
	t := jwt.New()
	for k, v := range claims {
		if err := t.Set(k, v); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func convertHeaders(headers map[string]interface{}) (jws.Headers, error) {
	hdr := jws.NewHeaders()

	for k, v := range headers {
		if err := hdr.Set(k, v); err != nil {
			return nil, err
		}
	}
	return hdr, nil
}

func uraCredential(did string, ura string, uzi string, subjectDID string, subjectName string) (vc.VerifiableCredential, error) {
	exp := time.Now().Add(time.Hour * 24 * 365 * 12)
	iat := time.Now()
	return vc.VerifiableCredential{
		Issuer:         ssi.MustParseURI(did),
		Context:        []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
		Type:           []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("PkiOverheidUraCredential")},
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
