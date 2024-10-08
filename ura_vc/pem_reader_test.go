package ura_vc

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestParseFileOrPath(t *testing.T) {
	tempFile, _ := ioutil.TempFile("", "test")
	defer os.Remove(tempFile.Name())
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

	tempDir, _ := ioutil.TempDir("", "testdir")
	defer os.RemoveAll(tempDir)

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
		file, err := ioutil.TempFile(tempDir, "prefix")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(file.Name())
		certs, chainPem, _, _, _, err := BuildCertChain("2312312")
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
		certs, chainPem, _, _, _, err := BuildCertChain("2312312")
		tempDir, _ := ioutil.TempDir("", "example")
		defer os.RemoveAll(tempDir)
		for i := 0; i < chainPem.Len(); i++ {
			certBlock, ok := chainPem.Get(i)
			certAsString := convertToString(certBlock)
			file, err := ioutil.TempFile(tempDir, "prefix")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(file.Name())
			if ok {
				_, err := file.WriteString(certAsString)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				t.Fail()
			}
		}
		data, err := pemReader.ParseFileOrPath(tempDir, pemType)
		assert.NoError(t, err)
		dataMap := make(map[string][]byte)
		for i := 0; i < len(*data); i++ {
			bytes := (*data)[i]
			hash, err := Hash(bytes, "sha512")
			assert.NoError(t, err)
			dataMap[base64.RawURLEncoding.EncodeToString(hash)] = bytes
		}
		for i := 0; i < len(*certs); i++ {
			bytes := (*certs)[i].Raw
			hash, err := Hash(bytes, "sha512")
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
