package x509_cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestHash(t *testing.T) {
	sha1sum := sha1.Sum([]byte("test"))
	sha256sum := sha256.Sum256([]byte("test"))
	sha384sum := sha3.Sum384([]byte("test"))
	sha512sum := sha512.Sum512([]byte("test"))
	testCases := []struct {
		name  string
		data  []byte
		alg   string
		hash  []byte
		error error
	}{
		{
			name: "SHA1",
			data: []byte("test"),
			alg:  "sha1",
			hash: sha1sum[:],
		},
		{
			name: "SHA256",
			data: []byte("test"),
			alg:  "sha256",
			hash: sha256sum[:],
		},
		{
			name: "SHA384",
			data: []byte("test"),
			alg:  "sha384",
			hash: sha384sum[:],
		},
		{
			name: "SHA512",
			data: []byte("test"),
			alg:  "sha512",
			hash: sha512sum[:],
		},
		{
			name:  "Unsupported",
			data:  []byte("test"),
			alg:   "unsupported",
			hash:  nil,
			error: fmt.Errorf("unsupported hash algorithm: %s", "unsupported"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := Hash(tc.data, tc.alg)
			if tc.error != nil {
				if err.Error() != tc.error.Error() {
					t.Errorf("unexpected error %v, want %v", err, tc.error)
				}
			}
			if !bytes.Equal(hash, tc.hash) {
				t.Errorf("unexpected hash %x, want %x", hash, tc.hash)
			}
		})
	}
}
func TestParseChain(t *testing.T) {
	parser := NewDefaultChainParser()

	_, chainPem, _, _, _, err := BuildCertChain("9907878")
	assert.NoError(t, err)
	derChains := make([][]byte, chainPem.Len())
	for i := 0; i < chainPem.Len(); i++ {
		certBlock, ok := chainPem.Get(i)
		certBlock = []byte(strings.ReplaceAll(string(certBlock), "\\n", "\n"))
		block, _ := pem.Decode(certBlock)
		assert.NotNil(t, block)
		if ok {
			derChains[i] = block.Bytes
		} else {
			t.Fail()
		}
	}

	testCases := []struct {
		name     string
		derChain *[][]byte
		errMsg   string
	}{
		{
			name:     "Valid Certificates",
			derChain: &derChains,
		},
		{
			name:     "Nil ChainPem",
			derChain: nil,
			errMsg:   "derChain is nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parser.ParseCertificates(tc.derChain)
			if err != nil {
				if err.Error() != tc.errMsg {
					t.Errorf("got error %v, want %v", err, tc.errMsg)
				}
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	parser := NewDefaultChainParser()
	_, _, _, privateKey, _, err := BuildCertChain("9907878")
	assert.NoError(t, err)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	assert.NoError(t, err)

	pkcs1PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	testCases := []struct {
		name   string
		der    *[]byte
		errMsg string
	}{
		{
			name: "ValidPrivateKey",
			der:  &privateKeyBytes,
		},
		{
			name:   "InvalidPrivateKey",
			der:    &pkcs1PrivateKey,
			errMsg: "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)",
		},
		{
			name:   "NilDER",
			der:    nil,
			errMsg: "der is nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parser.ParsePrivateKey(tc.der)
			if err != nil {
				if err.Error() != tc.errMsg {
					t.Errorf("got error %v, want %v", err, tc.errMsg)
				}
			}
		})
	}
}

// BuildCertChain generates a certificate chain, including root, intermediate, and signing certificates.
func BuildCertChain(uzi string) (*[]x509.Certificate, *cert.Chain, *x509.Certificate, *rsa.PrivateKey, *x509.Certificate, error) {
	chain := [4]x509.Certificate{}
	chainPems := &cert.Chain{}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	rootCertTmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	rootCertTmpl.IsCA = true
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	rootCert, rootPem, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chain[0] = *rootCert
	err = chainPems.Add(rootPem)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL1Tmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL1Tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	intermediateL1Tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	intermediateL1Cert, intermediateL1Pem, err := CreateCert(intermediateL1Tmpl, rootCertTmpl, &intermediateL1Key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chain[1] = *intermediateL1Cert
	err = chainPems.Add(intermediateL1Pem)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL2Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL2Tmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL2Tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	intermediateL2Tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	intermediateL2Cert, intermediateL2Pem, err := CreateCert(intermediateL2Tmpl, intermediateL1Cert, &intermediateL2Key.PublicKey, intermediateL1Key)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chain[2] = *intermediateL2Cert
	err = chainPems.Add(intermediateL2Pem)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	signingTmpl, err := SigningCertTemplate(nil)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	signingTmpl.Subject.SerialNumber = uzi
	signingTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	signingTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	signingCert, signingPEM, err := CreateCert(signingTmpl, intermediateL2Cert, &signingKey.PublicKey, intermediateL2Key)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chain[3] = *signingCert
	err = chainPems.Add(signingPEM)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chainPems, err = FixChainHeaders(chainPems)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	_chain := chain[:]
	return &_chain, chainPems, rootCert, signingKey, signingCert, nil
}

// CertTemplate generates a template for a x509 certificate with a given serial number. If no serial number is provided, a random one is generated.
// The certificate is valid for one month and uses SHA256 with RSA for the signature algorithm.
func CertTemplate(serialNumber *big.Int) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"JaegerTracing"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30), // valid for a month
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

// SigningCertTemplate creates a x509.Certificate template for a signing certificate with an optional serial number.
func SigningCertTemplate(serialNumber *big.Int) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}
	permanentIdentifier := PermanentIdentifier{
		IdentifierValue: "23123123",
		Assigner:        UraAssigner,
	}
	raw, err := toRawValue(permanentIdentifier, "")
	if err != nil {
		return nil, err
	}
	otherName := OtherName{
		TypeID: PermanentIdentifierType,
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
		Subject:               pkix.Name{Organization: []string{"JaegerTracing"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30), // valid for a month
		EmailAddresses:        []string{"roland@edia.nl"},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       SubjectAlternativeNameType,
				Critical: false,
				Value:    marshal,
			},
		},
	}
	return &tmpl, nil
}

// toRawValue marshals an ASN.1 identifier with a given tag, then unmarshals it into a RawValue structure.
func toRawValue(identifier any, tag string) (*asn1.RawValue, error) {
	bytes, err := asn1.MarshalWithParams(identifier, tag)
	if err != nil {
		return nil, err
	}
	var val asn1.RawValue
	_, err = asn1.Unmarshal(bytes, &val)
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
