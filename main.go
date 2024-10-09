package main

import (
	"fmt"
	"github.com/alecthomas/kong"
	"headease-nuts-pki-overheid-issuer/uzi_vc_issuer"
	"os"
)

type VC struct {
	CertificateFile string `arg:"" name:"certificate_file" help:"Certificate PEM file." type:"file"`
	SigningKey      string `arg:"" name:"signing_key" help:"PEM key for signing." type:"key"`
	SubjectDID      string `arg:"" name:"subject_did" help:"The subject DID of the VC." type:"key"`
	SubjectName     string `arg:"" name:"subject_name" help:"The subject name of the VC." type:"key"`
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
	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		parser.FatalIfErrorf(err)
	}
	command := ctx.Command()
	switch command {
	case "vc <certificate_file> <signing_key> <subject_did> <subject_name>":
		vc := cli.Vc
		jwt, err := issueVc(vc)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
		println(jwt)

	default:
		panic(ctx.Command())
	}
}

func issueVc(vc VC) (string, error) {
	didCreator := uzi_vc_issuer.NewDidCreator()
	chainParser := uzi_vc_issuer.NewDefaultChainParser()
	issuer := uzi_vc_issuer.NewUraVcBuilder(didCreator, chainParser)
	return issuer.Issue(vc.CertificateFile, vc.SigningKey, vc.SubjectDID, vc.SubjectName)
}
