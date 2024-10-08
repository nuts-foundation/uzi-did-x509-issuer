package main

import (
	"encoding/json"
	"fmt"
	"github.com/alecthomas/kong"
	"headease-nuts-pki-overheid-issuer/ura_vc"
	"os"
)

type VC struct {
	ChainFileOrPath string `arg:"" name:"chain_file_or_dir" help:"PEM file or path to directory." type:"file"`
	SigningKey      string `arg:"" name:"key" help:"PEM key for signing." type:"key"`
	SubjectDID      string `arg:"" name:"subject_did" help:"The subject DID of the VC." type:"key"`
	SubjectName     string `arg:"" name:"subject_name" help:"The subject name of the VC." type:"key"`
}

var CLI struct {
	Version string `help:"Show version."`
	Vc      VC     `cmd:"" help:"Create a new VC."`
}

func main() {
	cli := &CLI
	//cliInterface := cli2.NewCliInterface()
	parser, err := kong.New(cli)
	if err != nil {
		panic(err)
	}
	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		parser.FatalIfErrorf(err)
	}
	command := ctx.Command()
	//cliInterface := cli.NewCliInterface()
	switch command {
	case "vc <uzi>":
		err := fmt.Errorf("missing required argument: --file or --path")
		parser.FatalIfErrorf(err)
	case "vc <chain_file_or_dir> <key> <subject_did> <subject_name>":
		vc := cli.Vc
		jwt, err := handleVc(vc)
		if err != nil {
			panic(err)
		}
		println(jwt)

	default:
		panic(ctx.Command())
	}
}

func handleVc(vc VC) (string, error) {
	reader := ura_vc.NewPemReader()
	chain, err := reader.ParseFileOrPath(vc.ChainFileOrPath, "CERTIFICATE")
	if err != nil {
		return "", err
	}
	signingKeys, err := reader.ParseFileOrPath(vc.SigningKey, "PRIVATE KEY")
	if err != nil {
		return "", err
	}
	if signingKeys == nil {
		err := fmt.Errorf("no signing keys found")
		return "", err

	}
	var signingKey *[]byte
	if len(*signingKeys) == 1 {
		signingKey = &(*signingKeys)[0]
	} else {
		err := fmt.Errorf("no signing keys found")
		return "", err
	}
	chainParser := ura_vc.NewDefaultChainParser()
	privateKey, err := chainParser.ParsePrivateKey(signingKey)
	if err != nil {
		return "", err
	}

	certChain, err := chainParser.ParseChain(chain)
	if err != nil {
		return "", err
	}

	creator := ura_vc.NewDidCreator()
	builder := ura_vc.NewUraVcBuilder(creator)
	credential, err := builder.BuildUraVerifiableCredential(certChain, privateKey, vc.SubjectDID, vc.SubjectName)
	marshal, err := json.Marshal(credential)
	if err != nil {
		return "", err
	}
	return string(marshal), nil
}
