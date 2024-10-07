package ura_vc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestDefaultDidCreator_CreateDid(t *testing.T) {
	type fields struct {
	}
	type args struct {
		chain *[]x509.Certificate
	}
	chain, _, rootCert, _, _, err := buildCertChain("123123123")
	if err != nil {
		t.Fatal(err)
	}

	alg := "sha512"
	hash, err := Hash(rootCert.Raw, alg)
	rootHashString := base64.RawURLEncoding.EncodeToString(hash)
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
		errMsg string
	}{
		{
			name:   "Test case 1",
			fields: fields{},
			args:   args{chain: &[]x509.Certificate{}},
			want:   "",
			errMsg: "no certificate found with SAN subjectAltName (2.5.29.17) and attribute Permanent Identifier (1.3.6.1.5.5.7.8.3)",
		},
		{
			name:   "Test case 2",
			fields: fields{},
			args: args{chain: &[]x509.Certificate{
				x509.Certificate{}, // TODO: provide a realistic certificate implementation here
			}},
			want:   "", // TODO: modify this value according to your certificate structure
			errMsg: "no certificate found with SAN subjectAltName (2.5.29.17) and attribute Permanent Identifier (1.3.6.1.5.5.7.8.3)",
		},
		{
			name:   "Happy path",
			fields: fields{},
			args:   args{chain: chain},
			want:   strings.Join([]string{"did", "x509", "0", alg, rootHashString, "", "san", "permanentIdentifier", "23123123"}, ":"),
			errMsg: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DefaultDidCreator{}
			got, err := d.CreateDid(tt.args.chain)
			wantErr := tt.errMsg != ""
			if (err != nil) != wantErr {
				t.Errorf("DefaultDidCreator.CreateDid() error = %v, errMsg %v", err, tt.errMsg)
				return
			} else if wantErr {
				if err.Error() != tt.errMsg {
					t.Errorf("DefaultDidCreator.CreateDid() expected = \"%v\", got: \"%v\"", tt.errMsg, err.Error())
				}
			}

			if got != tt.want {
				t.Errorf("DefaultDidCreator.CreateDid() = \n%v\n, want: \n%v\n", got, tt.want)
			}
		})
	}
}

func buildCertChain(uzi string) (*[]x509.Certificate, *cert.Chain, *x509.Certificate, *rsa.PrivateKey, *x509.Certificate, error) {
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
	chainPems, err = fixChainHeaders(chainPems)
	_chain := chain[:]
	return &_chain, chainPems, rootCert, signingKey, signingCert, nil
}

// CertTemplate is a helper function to create a cert template with a serial number and other required fields
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
func SigningCertTemplate(serialNumber *big.Int) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}

	list, err := toRawList(PermanentIdentifierType)
	if err != nil {
		return nil, err
	}

	bytes, err := asn1.MarshalWithParams(list, "tag:0")

	list, err = toRawList(asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: bytes})
	if err != nil {
		return nil, err
	}
	marshal, err := asn1.MarshalWithParams(list, "tag:0")

	err = DebugUnmarshall(marshal, 0)
	permanentIdentifier := PermanentIdentifier{
		IdentifierValue: "23123123",
		Assigner:        UraAssigner,
	}
	raw, err := toRawValue(permanentIdentifier, "")
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
	list = []asn1.RawValue{}
	list = append(list, *raw)
	fmt.Println("OFF")
	marshal, err = asn1.Marshal(list)
	err = DebugUnmarshall(marshal, 0)

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

func toRawList(value any) ([]asn1.RawValue, error) {
	list := []asn1.RawValue{}
	val, err := toRawValue(value, "")
	if err != nil {
		return nil, err
	}
	list = append(list, *val)
	return list, nil
}

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
