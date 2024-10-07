package ura_vc

import (
	"encoding/pem"
	"io/ioutil"
	"os"
)

type PemReader struct {
}

func NewPemReader() *PemReader {
	return &PemReader{}
}

func (p *PemReader) ParseFileOrPath(path string, pemType string) (*[][]byte, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, nil
	}
	if fileInfo.IsDir() {
		files := make([][]byte, 0)
		dir, err := ioutil.ReadDir(path)
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
			for _, block := range *blocks {
				files = append(files, block)
			}
		}
		return &files, nil
	} else {
		blocks, err := readFile(path, pemType)
		return blocks, err
	}

}

func readFile(filename string, pemType string) (*[][]byte, error) {
	files := make([][]byte, 0)
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if looksLineCert(content, pemType) {
		foundBlocks := parsePemBlocks(content, pemType)
		for _, block := range *foundBlocks {
			files = append(files, block)
		}
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
