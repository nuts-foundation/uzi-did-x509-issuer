package main

import (
	"bufio"
	"fmt"
	"github.com/alecthomas/kong"
	"github.com/nuts-foundation/uzi-did-x509-issuer/credential_issuer"
	"github.com/nuts-foundation/uzi-did-x509-issuer/x509_cert"
	"os"
)

type VC struct {
	CertificateFile   string                      `arg:"" name:"certificate_file" help:"Certificate PEM file. If the file contains a chain, the chain will be used for signing." type:"existingfile"`
	SigningKey        string                      `arg:"" name:"signing_key" help:"PEM key for signing." type:"existingfile"`
	SubjectDID        string                      `arg:"" name:"subject_did" help:"The subject DID of the VC."`
	SubjectAttributes []x509_cert.SubjectTypeName `short:"s" name:"subject_attr" help:"A list of Subject Attributes u in the VC." default:"O,L"`
	IncludePermanent  bool                        `short:"p" help:"Include the permanent identifier in the did:x509."`
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

	switch ctx.Command() {
	case "vc <certificate_file> <signing_key> <subject_did>":
		vc := cli.Vc
		jwt, err := issueVc(vc)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		err = printLineAndFlush(jwt)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
	default:
		fmt.Println("Unknown command")
		os.Exit(-1)
	}
}

// printLineAndFlush writes a JWT (JSON Web Token) to the standard output and flushes the buffered writer.
func printLineAndFlush(jwt string) error {
	f := bufio.NewWriter(os.Stdout)
	// Make sure to flush
	defer func(f *bufio.Writer) {
		_ = f.Flush()
	}(f)
	// Write the JWT
	_, err := f.WriteString(jwt + "\n")
	return err
}

func issueVc(vc VC) (string, error) {
	chain, err := credential_issuer.NewValidCertificateChain(vc.CertificateFile)
	if err != nil {
		return "", err
	}

	key, err := credential_issuer.NewPrivateKey(vc.SigningKey)
	if err != nil {
		return "", err
	}

	subject, err := credential_issuer.NewSubjectDID(vc.SubjectDID)
	if err != nil {
		return "", err
	}

	credential, err := credential_issuer.Issue(chain, key, subject, credential_issuer.SubjectAttributes(vc.SubjectAttributes...))

	if err != nil {
		return "", err
	}

	return credential.Raw(), nil
}
