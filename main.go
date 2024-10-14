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

var CLI struct {
	Version string `help:"Show version."`
	Vc      VC     `cmd:"" help:"Create a new VC."`
}

func main() {
	cli := &CLI
	parser, err := kong.New(cli)
	if err != nil {
		panic(err)
	}
	_, err = parser.Parse(os.Args[1:])
	if err != nil {
		parser.FatalIfErrorf(err)
	}
	vc := cli.Vc
	jwt, err := issueVc(vc)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	println(jwt)
}

func issueVc(vc VC) (string, error) {
	didCreator := did_x509.NewDidCreator()
	chainParser := x509_cert.NewDefaultChainParser()
	issuer := uzi_vc_issuer.NewUraVcBuilder(didCreator, chainParser)
	return issuer.Issue(vc.CertificateFile, vc.SigningKey, vc.SubjectDID, vc.Test)
}
