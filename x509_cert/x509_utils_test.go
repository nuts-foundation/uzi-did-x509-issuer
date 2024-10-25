package x509_cert

import (
	"crypto/x509"
	"testing"
)

func TestFindOtherName(t *testing.T) {
	chain, _, _, _, _, err := BuildSelfSignedCertChain("2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		certificate *x509.Certificate
		wantName    string
		wantType    SanTypeName
		wantErr     bool
	}{
		{
			name:        "ValidOtherName",
			certificate: chain[0],
			wantName:    "2.16.528.1.1007.99.2110-1-900030787-S-90000380-00.000-11223344",
			wantType:    SanTypeOtherName,
			wantErr:     false,
		},
		{
			name:        "NoOtherName",
			certificate: chain[1], // This should be a valid initialised certificate without any otherName
			wantErr:     true,
		},
		{
			name:    "NilCertificate",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otherNames, err := FindSanTypes(tt.certificate)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindSanTypes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if otherNames != nil {
				nameValues := otherNames
				gotName := nameValues[0].Value
				if gotName != tt.wantName {
					t.Errorf("FindSanTypes() gotName = %v, want %v", gotName, tt.wantName)
				}
				gotType := nameValues[0].Type
				if gotType != tt.wantType {
					t.Errorf("FindSanTypes() gotType = %v, want %v", gotType, tt.wantType)
				}
			} else if !tt.wantErr {
				t.Errorf("unexpected nil from otherNames")
			}
		})
	}
}
