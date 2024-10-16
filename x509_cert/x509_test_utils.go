package x509_cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/lestrrat-go/jwx/v2/cert"
)

const (
	CertificateBlockType = "CERTIFICATE"
	RSAPrivKeyBlockType  = "PRIVATE KEY"
)

func EncodeRSAPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	b := bytes.Buffer{}
	err := pem.Encode(&b, &pem.Block{Type: RSAPrivKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return []byte{}, err
	}
	return b.Bytes(), nil
}

func EncodeCertificates(certs ...*x509.Certificate) ([]byte, error) {
	b := bytes.Buffer{}
	for _, c := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: CertificateBlockType, Bytes: c.Raw}); err != nil {
			return []byte{}, err
		}
	}
	return b.Bytes(), nil
}

// BuildSelfSignedCertChain generates a certificate chain, including root, intermediate, and signing certificates.
func BuildSelfSignedCertChain(identifier string) (chain []*x509.Certificate, chainPems *cert.Chain, rootCert *x509.Certificate, signingKey *rsa.PrivateKey, signingCert *x509.Certificate, err error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	rootCertTmpl, err := CertTemplate(nil, "Root CA")
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	rootCert, rootPem, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL1Tmpl, err := CertTemplate(nil, "Intermediate CA Level 1")
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL1Cert, intermediateL1Pem, err := CreateCert(intermediateL1Tmpl, rootCertTmpl, &intermediateL1Key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL2Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL2Tmpl, err := CertTemplate(nil, "Intermediate CA Level 2")
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL2Cert, intermediateL2Pem, err := CreateCert(intermediateL2Tmpl, intermediateL1Cert, &intermediateL2Key.PublicKey, intermediateL1Key)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	signingTmpl, err := SigningCertTemplate(nil, identifier)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	signingCert, signingPEM, err := CreateCert(signingTmpl, intermediateL2Cert, &signingKey.PublicKey, intermediateL2Key)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	chain = make([]*x509.Certificate, 4)
	for i, c := range []*x509.Certificate{signingCert, intermediateL2Cert, intermediateL1Cert, rootCert} {
		chain[i] = c
	}

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

// CertTemplate generates a template for a x509 certificate with a given serial number. If no serial number is provided, a random one is generated.
// The certificate is valid for one month and uses SHA256 with RSA for the signature algorithm.
func CertTemplate(serialNumber *big.Int, organization string) (*x509.Certificate, error) {
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

// SigningCertTemplate creates a x509.Certificate template for a signing certificate with an optional serial number.
func SigningCertTemplate(serialNumber *big.Int, identifier string) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}
	raw, err := toRawValue(identifier, "ia5")
	if err != nil {
		return nil, err
	}
	otherName := OtherName{
		TypeID: OtherNameType,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      raw.FullBytes,
		},
	}

	raw, err = toRawValue(otherName, "tag:0")
	if err != nil {
		return nil, err
	}
	var list []asn1.RawValue
	list = append(list, *raw)
	//fmt.Println("OFF")
	marshal, err := asn1.Marshal(list)
	if err != nil {
		return nil, err
	}
	//err = DebugUnmarshall(marshal, 0)

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"FauxCare"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30), // valid for a month
		EmailAddresses:        []string{"roland@headease.nl"},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       SubjectAlternativeNameType,
				Critical: false,
				Value:    marshal,
			},
		},
	}
	uzi, _, _, err := ParseUraFromOtherNameValue(identifier)
	if err != nil {
		// Crate an incorrect uzi in order to test invalid UZI numbers
		uzi = "9876543212"
	}
	tmpl.Subject.SerialNumber = uzi
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

// CreateCert generates a new x509 certificate using the provided template and parent certificates, public and private keys.
// It returns the generated certificate, its PEM-encoded version, and any error encountered during the process.
func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (cert *x509.Certificate, certPEM []byte, err error) {

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

// DebugUnmarshall recursively unmarshalls ASN.1 encoded data and prints the structure with parsed values.
// Keep this method for debug purposes in the future.
func DebugUnmarshall(data []byte, depth int) error {
	for len(data) > 0 {
		var x asn1.RawValue
		tail, err := asn1.Unmarshal(data, &x)
		if err != nil {
			return err
		}
		prefix := ""
		for i := 0; i < depth; i++ {
			prefix += "\t"
		}
		fmt.Printf("%sUnmarshalled: compound: %t, tag: %d, class: %d", prefix, x.IsCompound, x.Tag, x.Class)

		if x.Bytes != nil {
			if x.IsCompound || x.Tag == 0 {
				fmt.Println()
				err := DebugUnmarshall(x.Bytes, depth+1)
				if err != nil {
					return err
				}
			} else {
				switch x.Tag {
				case asn1.TagBoolean:
					fmt.Printf(", value boolean: %v", x.Bytes)
				case asn1.TagOID:
					fmt.Printf(", value: OID: %v", x.Bytes)
				case asn1.TagInteger:
					fmt.Printf(", value: integer: %v", x.Bytes)
				case asn1.TagUTF8String:
					fmt.Printf(", value: bitstring: %v", x.Bytes)
				case asn1.TagBitString:
					fmt.Printf(", value: bitstring: %v", x.Bytes)
				case asn1.TagOctetString:
					fmt.Printf(", value: octetstring: %v", x.Bytes)
				case asn1.TagIA5String:
					fmt.Printf(", value: TagIA5String: %v", x.Bytes)
				case asn1.TagNull:
					fmt.Printf(", value: null")
				default:
					return fmt.Errorf("unknown tag: %d", x.Tag)

				}
				fmt.Println()
			}
		}
		data = tail
	}

	return nil
}
