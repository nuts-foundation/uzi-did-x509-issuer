package main

import (
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/nuts-foundation/uzi-did-x509-issuer/did_x509"
	"github.com/nuts-foundation/uzi-did-x509-issuer/uzi_vc_issuer"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"os"
)

type VC struct {
	CertificateFile string `arg:"" name:"certificate_file" help:"Certificate PEM file." type:"existingfile"`
	SigningKey      string `arg:"" name:"signing_key" help:"PEM key for signing." type:"existingfile"`
	SubjectDID      string `arg:"" name:"subject_did" help:"The subject DID of the VC." type:"key"`
	Test            bool   `short:"t" help:"Allow test certificates."`
}

type TestCert struct {
	Identifier string `arg:"" name:"identifier" help:"Identifier for the test certificate such as an URA or UZI number."`
}

var CLI struct {
	Version  string   `help:"Show version."`
	Vc       VC       `cmd:"" help:"Create a new VC."`
	TestCert TestCert `cmd:"" help:"Create a new test certificate."`
}

func main() {
	cli := &CLI
	parser, err := kong.New(cli)
	if err != nil {
		panic(err)
	}
	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		parser.FatalIfErrorf(err)
	}

	switch ctx.Command() {
	case "vc <certificate_file> <signing_key> <subject_did>":
		vc := cli.Vc
		jwt, err := issueVc(vc)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		println(jwt)
	case "test-cert <identifier>":
		otherName := fmt.Sprintf("2.16.528.1.1007.1.%s", cli.TestCert.Identifier)
		fmt.Println("Building certificate chain for identifier:", otherName)
		chain, _, _, privKey, _, err := x509_cert.BuildCertChain(cli.TestCert.Identifier)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		chainPems, err := x509_cert.EncodeCertificates(chain...)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		signingKeyPem, err := x509_cert.EncodeRSAPrivateKey(privKey)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}

		os.WriteFile("chain.pem", chainPems, 0644)
		os.WriteFile("signing_key.pem", signingKeyPem, 0644)

		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	default:
		fmt.Println("Unknown command")
		os.Exit(-1)
	}
}

func issueVc(vc VC) (string, error) {
	didCreator := did_x509.NewDidCreator()
	chainParser := x509_cert.NewDefaultChainParser()
	issuer := uzi_vc_issuer.NewUraVcBuilder(didCreator, chainParser)
	return issuer.Issue(vc.CertificateFile, vc.SigningKey, vc.SubjectDID, vc.Test)
}
