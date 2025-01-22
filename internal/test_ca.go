package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
)

var permanentIdentifierAssigner = asn1.ObjectIdentifier{2, 16, 528, 1, 1007, 3, 3}
var subjectAlternativeNameType = asn1.ObjectIdentifier{2, 5, 29, 17}
var otherNameType = asn1.ObjectIdentifier{2, 5, 5, 5}

type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"tag:0,explicit"`
}

type stringAndOid struct {
	Value    string
	Assigner asn1.ObjectIdentifier
}

// BuildSelfSignedCertChain generates a certificate chain, including root, intermediate, and signing certificates.
func BuildSelfSignedCertChain(identifier string, permanentIdentifierValue string) (chain []*x509.Certificate, chainPems *cert.Chain, rootCert *x509.Certificate, signingKey *rsa.PrivateKey, signingCert *x509.Certificate, err error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	rootCertTmpl, err := certTemplate(nil, "Root CA")
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	rootCert, rootPem, err := createCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL1Tmpl, err := certTemplate(nil, "Intermediate CA Level 1")
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL1Cert, intermediateL1Pem, err := createCert(intermediateL1Tmpl, rootCertTmpl, &intermediateL1Key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL2Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL2Tmpl, err := certTemplate(nil, "Intermediate CA Level 2")
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL2Cert, intermediateL2Pem, err := createCert(intermediateL2Tmpl, intermediateL1Cert, &intermediateL2Key.PublicKey, intermediateL1Key)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	signingTmpl, err := signingCertTemplate(nil, identifier, permanentIdentifierValue)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	signingCert, signingPEM, err := createCert(signingTmpl, intermediateL2Cert, &signingKey.PublicKey, intermediateL2Key)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	chain = []*x509.Certificate{signingCert, intermediateL2Cert, intermediateL1Cert, rootCert}

	chainPems = &cert.Chain{}
	for _, p := range [][]byte{signingPEM, intermediateL2Pem, intermediateL1Pem, rootPem} {
		err = chainPems.Add(p)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}

	chainPems, err = FixChainHeaders(chainPems)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return chain, chainPems, rootCert, signingKey, signingCert, nil
}

// certTemplate generates a template for a x509 certificate with a given serial number. If no serial number is provided, a random one is generated.
// The certificate is valid for one month and uses SHA256 with RSA for the signature algorithm.
func certTemplate(serialNumber *big.Int, organization string) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}
	tmpl := x509.Certificate{
		IsCA:                  true,
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{organization}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30), // valid for a month
		BasicConstraintsValid: true,
	}
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	return &tmpl, nil
}

// signingCertTemplate creates a x509.Certificate template for a signing certificate with an optional serial number.
func signingCertTemplate(serialNumber *big.Int, identifier string, permanentIdentifierValue string) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}
	raw, err := toRawValue(identifier, "ia5")
	if err != nil {
		return nil, err
	}
	identifierOtherName := otherName{
		TypeID: otherNameType,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      raw.FullBytes,
		},
	}

	raw, err = toRawValue(identifierOtherName, "tag:0")
	if err != nil {
		return nil, err
	}
	var list []asn1.RawValue
	list = append(list, *raw)

	if permanentIdentifierValue != "" {
		permId := stringAndOid{
			Value:    permanentIdentifierValue,
			Assigner: permanentIdentifierAssigner,
		}
		raw, err = toRawValue(permId, "seq")
		if err != nil {
			return nil, err
		}
		permOtherName := otherName{
			TypeID: PermanentIdentifierType,
			Value: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      raw.FullBytes,
			},
		}
		raw, err = toRawValue(permOtherName, "tag:0")
		if err != nil {
			return nil, err
		}
		list = append(list, *raw)
	}
	marshal, err := asn1.Marshal(list)
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Faux Care"},
			Locality:     []string{"Testland", "Bug City"},
		},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30), // valid for a month
		EmailAddresses:        []string{"info@example.com"},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       subjectAlternativeNameType,
				Critical: false,
				Value:    marshal,
			},
		},
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	return &tmpl, nil
}

// toRawValue marshals an ASN.1 identifier with a given tag, then unmarshals it into a RawValue structure.
func toRawValue(identifier any, tag string) (*asn1.RawValue, error) {
	b, err := asn1.MarshalWithParams(identifier, tag)
	if err != nil {
		return nil, err
	}
	var val asn1.RawValue
	_, err = asn1.Unmarshal(b, &val)
	if err != nil {
		return nil, err
	}
	return &val, nil
}

// createCert generates a new x509 certificate using the provided template and parent certificates, public and private keys.
// It returns the generated certificate, its PEM-encoded version, and any error encountered during the process.
func createCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (cert *x509.Certificate, certPEM []byte, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return nil, nil, err
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return cert, certPEM, err
}
