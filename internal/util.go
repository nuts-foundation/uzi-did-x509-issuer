package internal

import (
	"github.com/lestrrat-go/jwx/v2/cert"
	"strings"
)

// FixChainHeaders replaces newline characters in the certificate chain headers with escaped newline sequences.
// It processes each certificate in the provided chain and returns a new chain with the modified headers or an error if any occurs.
func FixChainHeaders(chain *cert.Chain) (*cert.Chain, error) {
	rv := &cert.Chain{}
	for i := 0; i < chain.Len(); i++ {
		value, _ := chain.Get(i)
		der := strings.ReplaceAll(string(value), "\n", "\\n")
		err := rv.AddString(der)
		if err != nil {
			return nil, err
		}
	}
	return rv, nil
}
