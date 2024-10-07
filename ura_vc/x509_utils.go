package ura_vc

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

type OtherName struct {
	TypeID asn1.ObjectIdentifier
	//Value  PermanentIdentifier `asn1:"tag:0,explicit"`
	Value asn1.RawValue `asn1:"tag:0,explicit"`
}

type SanType pkix.AttributeTypeAndValue

type PermanentIdentifier struct {
	IdentifierValue string                `asn1:"utf8,optional"`
	Assigner        asn1.ObjectIdentifier `asn1:"tag:6,optional"`
}

// FindUra extracts the SerialNumber from the Subject of a signing certificate in the given certificate chain.
// It returns an error if the signing certificate cannot be found or if the SerialNumber is not present.
func FindUra(chain *[]x509.Certificate) (string, error) {
	_, ura, err := FindSigningCertificate(chain)
	if err != nil {
		return "", err
	}
	if ura == "" {
		return "", errors.New("no SerialNumber found in certificate's Subject")
	}
	return ura, nil
}

// FindPermanentIdentifierValue extracts the PermanentIdentifier from the provided x509.Certificate if it exists.
// The function searches through the extensions of the certificate, specifically the SubjectAlternativeName (SAN).
// If a SAN of type PermanentIdentifier is found, it extracts and returns it; otherwise, it returns nil.
func FindPermanentIdentifierValue(cert *x509.Certificate) (*PermanentIdentifier, error) {
	var identifier PermanentIdentifier
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(SubjectAlternativeNameType) {
			err := forEachSAN(extension.Value, func(tag int, data []byte) error {
				if tag != 0 {
					return nil
				}
				var other OtherName
				_, err := asn1.UnmarshalWithParams(data, &other, "tag:0")
				if err != nil {
					return fmt.Errorf("could not parse requested other SAN: %v", err)
				}
				if other.TypeID.Equal(PermanentIdentifierType) {
					_, err = asn1.Unmarshal(other.Value.Bytes, &identifier)
					if err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			if identifier.IdentifierValue != "" {
				return &identifier, nil
			}
		}
	}
	return nil, nil
}

// forEachSAN iterates over each SAN (Subject Alternative Name) in the provided ASN.1 encoded extension.
// It unmarshals the extension and checks if it is a valid SAN sequence, then processes each element using the callback.
func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("x509: trailing data after X.509 extension")
	}

	if !isSANSequence(seq) {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	return processSANSequence(seq.Bytes, callback)
}

// isSANSequence checks if the given ASN.1 raw value represents a valid SAN (Subject Alternative Name) sequence.
func isSANSequence(seq asn1.RawValue) bool {
	return seq.IsCompound && seq.Tag == 16 && seq.Class == 0
}

// processSANSequence processes a sequence of SAN (Subject Alternative Name) elements in ASN.1 encoding.
// It takes the remaining part of the sequence and a callback function to handle each SAN element.
// Each SAN element is passed to the callback function with its tag and full data bytes.
func processSANSequence(rest []byte, callback func(tag int, data []byte) error) error {
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error

		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.FullBytes); err != nil {
			return err
		}
	}
	return nil
}

// FindSigningCertificate searches the provided certificate chain for a certificate with a specific SAN and Permanent Identifier.
// It returns the found certificate, its IdentifierValue, and an error if no matching certificate is found.
func FindSigningCertificate(chain *[]x509.Certificate) (*x509.Certificate, string, error) {
	for _, cert := range *chain {
		identifier, err := FindPermanentIdentifierValue(&cert)
		if err != nil {
			return nil, "", err
		}
		if identifier != nil && identifier.IdentifierValue != "" {
			return &cert, identifier.IdentifierValue, nil
		}
	}
	err := errors.New("no certificate found with SAN subjectAltName (2.5.29.17) and attribute Permanent Identifier (1.3.6.1.5.5.7.8.3)")
	return nil, "", err
}
