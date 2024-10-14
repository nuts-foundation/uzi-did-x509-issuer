package main

import (
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/nuts-foundation/uzi-did-x509-issuer/uzi_vc_issuer"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"os"
)

type VC struct {
	CertificateFile string `arg:"" name:"certificate_file" help:"Certificate PEM file. If the file contains a chain, the chain will be used for signing." type:"existingfile"`
	SigningKey      string `arg:"" name:"signing_key" help:"PEM key for signing." type:"existingfile"`
	SubjectDID      string `arg:"" name:"subject_did" help:"The subject DID of the VC." type:"key"`
	Test            bool   `short:"t" help:"Allow for certificates signed by the TEST UZI Root CA."`
}

type TestCert struct {
	Uzi string `arg:"" name:"uzi" help:"The UZI number for the test certificate."`
	Ura string `arg:"" name:"ura" help:"The URA number for the test certificate."`
	Agb string `arg:"" name:"agb" help:"The AGB code for the test certificate."`
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
	case "test-cert <uzi> <ura> <agb>":
		// Format is 2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344
		// <OID CA>-<versie-nr>-<UZI-nr>-<pastype>-<Abonnee-nr>-<rol>-<AGB-code>
		// 2.16.528.1.1007.99.2110-1-<UZI-nr>-S-<Abonnee-nr>-00.000-<AGB-code>
		otherName := fmt.Sprintf("2.16.528.1.1007.99.2110-1-%s-S-%s-00.000-%s", cli.TestCert.Uzi, cli.TestCert.Ura, cli.TestCert.Agb)
		fmt.Println("Building certificate chain for identifier:", otherName)
		chain, _, _, privKey, _, err := x509_cert.BuildCertChain(otherName)
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
	return uzi_vc_issuer.Issue(vc.CertificateFile, vc.SigningKey, vc.SubjectDID, vc.Test)
}
