package pem

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"headease-nuts-pki-overheid-issuer/x509_cert"
	"log"
	"os"
	"strings"
	"testing"
)

func TestParseFileOrPath(t *testing.T) {
	tempFile, _ := os.CreateTemp("", "test")
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			log.Fatal(err)
		}
	}(tempFile.Name())
	pemType := "CERTIFICATE"

	t.Run("FileExistsAndIsNotDirectory", func(t *testing.T) {
		pemReader := NewPemReader()
		result, err := pemReader.ParseFileOrPath(tempFile.Name(), pemType)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("FileDoesNotExist", func(t *testing.T) {
		pemReader := NewPemReader()
		_, err := pemReader.ParseFileOrPath("nonexistent", pemType)
		assert.Error(t, err)
	})

	tempDir, _ := os.MkdirTemp("", "testdir")
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			log.Fatal(err)
		}
	}(tempDir)

	t.Run("PathIsDirectory", func(t *testing.T) {
		pemReader := NewPemReader()
		_, err := pemReader.ParseFileOrPath(tempDir, pemType)
		assert.NoError(t, err)
	})

	t.Run("PathDoesNotExist", func(t *testing.T) {
		pemReader := NewPemReader()
		_, err := pemReader.ParseFileOrPath("nonexistent/path", pemType)
		assert.Error(t, err)
	})
	t.Run("Happy flow single file", func(t *testing.T) {
		pemReader := NewPemReader()
		file, err := os.CreateTemp(tempDir, "prefix")
		if err != nil {
			t.Fatal(err)
		}
		defer func(name string) {
			err := os.Remove(name)
			if err != nil {
				log.Fatal(err)
			}
		}(file.Name())
		certs, chainPem, _, _, _, err := x509_cert.BuildCertChain("A BIG STRING")
		assert.NoError(t, err)
		for i := 0; i < chainPem.Len(); i++ {
			certBlock, ok := chainPem.Get(i)
			certAsString := convertToString(certBlock)
			if ok {
				_, err := file.WriteString(certAsString)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				t.Fail()
			}
		}
		data, err := pemReader.ParseFileOrPath(file.Name(), pemType)
		assert.NoError(t, err)
		for i := 0; i < len(*data); i++ {
			bytes := (*data)[i]
			certificate := (*certs)[i]
			ok := assert.Equal(t, bytes, certificate.Raw)
			if !ok {
				t.Fail()
			}
		}

	})
	t.Run("Happy flow directory", func(t *testing.T) {
		pemReader := NewPemReader()
		certs, chainPem, _, _, _, err := x509_cert.BuildCertChain("A BIG STRING")
		assert.NoError(t, err)
		tempDir, _ := os.MkdirTemp("", "example")
		defer func(path string) {
			err := os.RemoveAll(path)
			if err != nil {
				log.Fatal(err)
			}
		}(tempDir)
		for i := 0; i < chainPem.Len(); i++ {
			certBlock, ok := chainPem.Get(i)
			certAsString := convertToString(certBlock)
			file, err := os.CreateTemp(tempDir, "prefix")
			assert.NoError(t, err)
			if ok {
				_, err := file.WriteString(certAsString)
				assert.NoError(t, err)
			} else {
				t.Fail()
			}
		}
		data, err := pemReader.ParseFileOrPath(tempDir, pemType)
		assert.NoError(t, err)
		dataMap := make(map[string][]byte)
		for i := 0; i < len(*data); i++ {
			bytes := (*data)[i]
			hash, err := x509_cert.Hash(bytes, "sha512")
			assert.NoError(t, err)
			dataMap[base64.RawURLEncoding.EncodeToString(hash)] = bytes
		}
		for i := 0; i < len(*certs); i++ {
			bytes := (*certs)[i].Raw
			hash, err := x509_cert.Hash(bytes, "sha512")
			assert.NoError(t, err)
			fileBytes := dataMap[base64.RawURLEncoding.EncodeToString(hash)]
			ok := assert.Equal(t, bytes, fileBytes)
			if !ok {
				t.Fail()
			}
		}

	})

}

func convertToString(certBlock []byte) string {
	certAsString := string(certBlock)
	certAsString = strings.ReplaceAll(certAsString, "\\n", "\n")
	certAsString = certAsString + "\n"
	return certAsString
}