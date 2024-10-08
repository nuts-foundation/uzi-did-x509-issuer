package ura_vc

import (
	"encoding/pem"
	"os"
)

type PemReader interface {
	ParseFileOrPath(path string, pemType string) (*[][]byte, error)
}

type DefaultPemReader struct {
}

func NewPemReader() *DefaultPemReader {
	return &DefaultPemReader{}
}

func (p *DefaultPemReader) ParseFileOrPath(path string, pemType string) (*[][]byte, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fileInfo.IsDir() {
		files := make([][]byte, 0)
		dir, err := os.ReadDir(path)
		if err != nil {
			return nil, nil
		}
		for _, file := range dir {
			if file.IsDir() {
				continue
			}
			blocks, err := readFile(path+"/"+file.Name(), pemType)
			if err != nil {
				return nil, err
			}
			files = append(files, *blocks...)
		}
		return &files, nil
	} else {
		blocks, err := readFile(path, pemType)
		return blocks, err
	}

}

func readFile(filename string, pemType string) (*[][]byte, error) {
	files := make([][]byte, 0)
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if looksLineCert(content, pemType) {
		foundBlocks := parsePemBlocks(content, pemType)
		files = append(files, *foundBlocks...)
	}
	return &files, nil
}

func parsePemBlocks(cert []byte, pemType string) *[][]byte {
	blocks := make([][]byte, 0)
	for {
		pemBlock, tail := pem.Decode(cert)
		if pemBlock == nil {
			break
		}
		if pemBlock.Type == pemType {
			blocks = append(blocks, pemBlock.Bytes)
		}
		if tail == nil {
			break
		}
		cert = tail

	}
	return &blocks
}

func looksLineCert(cert []byte, pemType string) bool {
	pemBlock, _ := pem.Decode(cert)
	if pemBlock == nil {
		return false
	}
	if pemBlock.Type != pemType {
		return false
	}
	return true
}
