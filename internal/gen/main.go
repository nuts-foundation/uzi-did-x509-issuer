//go:generate go run .
package main

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/nuts-foundation/go-didx509-toolkit/internal"
	"os"
)

func main() {
	chain, _, _, privateKey, _, err := internal.BuildSelfSignedCertChain("2.16.528.1.1007.99.2110-1-1111111-S-2222222-00.000-333333", "2222222")
	if err != nil {
		panic(err)
	}
	encodeCert := func(cert *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	// Build go source file with 2 constants, TestSigningKey and TestCertificateChain in PEM format
	chainPEM := ""
	for _, c := range chain {
		chainPEM += encodeCert(c)
	}

	src := `package internal

const TestSigningKey = ` + "`" + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})) + "`" + `
const TestCertificateChain = ` + "`" + chainPEM + "`"

	if err := os.WriteFile("../test_certs.go", []byte(src), 0644); err != nil {
		panic(err)
	}
}
