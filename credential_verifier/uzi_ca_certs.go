package credential_verifier

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
)

type uziCaPool struct {
	rootCaUrls         []string
	intermediateCaUrls []string
}

var (
	productionUziCaPool = uziCaPool{
		rootCaUrls:         []string{"http://cert.pkioverheid.nl/PrivateRootCA-G1.cer"},
		intermediateCaUrls: []string{"http://cert.pkioverheid.nl/DomPrivateServicesCA-G1.cer", "http://cert.pkioverheid.nl/UZI-register_Private_Server_CA_G1.cer"},
	}
	testUziCaPool = uziCaPool{
		rootCaUrls:         []string{"http://www.uzi-register-test.nl/cacerts/test_zorg_csp_private_root_ca_g1.cer"},
		intermediateCaUrls: []string{"http://www.uzi-register-test.nl/cacerts/test_zorg_csp_level_2_private_services_ca_g1.cer", "http://www.uzi-register-test.nl/cacerts/test_uzi-register_private_server_ca_g1.cer"},
	}
)

func getCertPools(includeTest bool) (root *x509.CertPool, intermediate *x509.CertPool, err error) {
	pool := prepareAndCombinePools(includeTest)
	return downloadUziPool(pool)
}

func prepareAndCombinePools(includeTest bool) uziCaPool {
	pool := uziCaPool{}
	pool.rootCaUrls = productionUziCaPool.rootCaUrls
	pool.intermediateCaUrls = productionUziCaPool.intermediateCaUrls
	if includeTest {
		pool.rootCaUrls = append(pool.rootCaUrls, testUziCaPool.rootCaUrls...)
		pool.intermediateCaUrls = append(pool.intermediateCaUrls, testUziCaPool.intermediateCaUrls...)
	}
	return pool
}

// Internal Helper Functions

func downloadUziPool(pool uziCaPool) (*x509.CertPool, *x509.CertPool, error) {
	roots, err := downloadPool(pool.rootCaUrls)
	if err != nil {
		return nil, nil, err
	}
	intermediates, err := downloadPool(pool.intermediateCaUrls)
	if err != nil {
		return nil, nil, err
	}

	return roots, intermediates, nil
}

func downloadPool(urls []string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	for _, url := range urls {
		certificate, err := readCertificateFromUrl(url)
		if err != nil {
			return nil, err
		}
		roots.AddCert(certificate)
	}
	return roots, nil
}

func readCertificateFromUrl(url string) (*x509.Certificate, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("Error closing body: %v", err)
		}
	}(response.Body)

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code (%v) from url %s: ", response.StatusCode, url)
	}

	buffer := bytes.Buffer{}
	_, err = io.Copy(&buffer, response.Body)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(buffer.Bytes())
	return certificate, err
}
