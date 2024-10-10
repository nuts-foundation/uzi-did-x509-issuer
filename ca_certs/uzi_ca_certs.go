package ca_certs

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
)

type UziCaPool struct {
	rootCaUrls         []string
	intermediateCaUrls []string
}

var (
	ProductionUziCaPool = UziCaPool{
		rootCaUrls:         []string{"http://cert.pkioverheid.nl/PrivateRootCA-G1.cer"},
		intermediateCaUrls: []string{"http://cert.pkioverheid.nl/DomPrivateServicesCA-G1.cer", "http://cert.pkioverheid.nl/UZI-register_Private_Server_CA_G1.cer"},
	}
	TestUziCaPool = UziCaPool{
		rootCaUrls:         []string{"http://www.uzi-register-test.nl/cacerts/test_zorg_csp_private_root_ca_g1.cer"},
		intermediateCaUrls: []string{"http://www.uzi-register-test.nl/cacerts/test_zorg_csp_level_2_private_services_ca_g1.cer", "http://www.uzi-register-test.nl/cacerts/test_uzi-register_private_server_ca_g1.cer"},
	}
)

func GetCertPools(includeTest bool) (root *x509.CertPool, intermediate *x509.CertPool, err error) {
	pool := prepareAndCombinePools(includeTest)
	return downloadUziPool(pool)
}

func GetCerts(includeTest bool) (*[]x509.Certificate, error) {
	pool := prepareAndCombinePools(includeTest)
	return downloadUziPoolCerts(pool)
}

func GetDERs(includeTest bool) (*[][]byte, error) {
	pool := prepareAndCombinePools(includeTest)
	return downloadUziPoolDERs(pool)
}

func prepareAndCombinePools(includeTest bool) UziCaPool {
	pool := UziCaPool{}
	pool.rootCaUrls = ProductionUziCaPool.rootCaUrls
	pool.intermediateCaUrls = ProductionUziCaPool.intermediateCaUrls
	if includeTest {
		pool.rootCaUrls = append(pool.rootCaUrls, TestUziCaPool.rootCaUrls...)
		pool.intermediateCaUrls = append(pool.intermediateCaUrls, TestUziCaPool.intermediateCaUrls...)
	}
	return pool
}

func downloadUziPoolDERs(pool UziCaPool) (*[][]byte, error) {
	var rv = [][]byte{}
	certs, err := downloadUziPoolCerts(pool)
	if err != nil {
		return nil, err
	}
	for _, cert := range *certs {
		rv = append(rv, cert.Raw)
	}
	return &rv, err
}

func GetTestCerts() (*[]x509.Certificate, error) {
	return downloadUziPoolCerts(TestUziCaPool)
}

// Internal Helper Functions

func downloadUziPool(pool UziCaPool) (*x509.CertPool, *x509.CertPool, error) {
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

func downloadUziPoolCerts(pool UziCaPool) (*[]x509.Certificate, error) {
	allUrls := append(pool.rootCaUrls, pool.intermediateCaUrls...)
	all, err := downloadCerts(allUrls)
	if err != nil {
		return nil, err
	}

	return all, nil
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

func downloadCerts(urls []string) (*[]x509.Certificate, error) {
	certs := make([]x509.Certificate, 0)
	for _, url := range urls {
		certificate, err := readCertificateFromUrl(url)
		if err != nil {
			return nil, err
		}
		certs = append(certs, *certificate)
	}
	return &certs, nil
}

func readCertificateFromUrl(url string) (*x509.Certificate, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// ignore
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
