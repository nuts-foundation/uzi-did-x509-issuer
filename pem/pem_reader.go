package pem

import (
	"encoding/pem"
	"fmt"
	"os"
)

// ParseFileOrPath processes a file or directory at the given path and extracts PEM blocks of the specified pemType.
func ParseFileOrPath(path string, pemType string) ([][]byte, error) {
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
			files = append(files, blocks...)
		}
		return files, nil
	} else {
		blocks, err := readFile(path, pemType)
		return blocks, err
	}

}

// readFile reads a file from the given filename, parses it for PEM blocks of the specified type, and returns the blocks.
func readFile(filename string, pemType string) ([][]byte, error) {
	fmt.Println("filename: ", filename)
	files := make([][]byte, 0)
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if looksLineCert(content, pemType) {
		foundBlocks := ParsePemBlocks(content, pemType)
		files = append(files, foundBlocks...)
	}
	return files, nil
}

// ParsePemBlocks extracts specified PEM blocks from the provided certificate bytes and returns them as a pointer to a slice of byte slices.
func ParsePemBlocks(cert []byte, pemType string) [][]byte {
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
	return blocks
}

// looksLineCert checks if the given certificate data is a valid PEM block of the specified type.
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
