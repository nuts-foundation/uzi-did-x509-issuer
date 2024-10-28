package x509_cert

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"tag:0,explicit"`
}

type StingAndOid struct {
	Value    string
	Assigner asn1.ObjectIdentifier
}

type PolicyType string

const (
	PolicyTypeSan PolicyType = "san"
)

type SanType pkix.AttributeTypeAndValue

type SanTypeName string

const (
	SanTypeOtherName                   SanTypeName = "otherName"
	SanTypePermanentIdentifierValue    SanTypeName = "permanentIdentifier.value"
	SanTypePermanentIdentifierAssigner SanTypeName = "permanentIdentifier.assigner"
)

type OtherNameValue struct {
	PolicyType PolicyType
	Type       SanTypeName
	Value      string
}

func FindSanTypes(certificate *x509.Certificate) ([]*OtherNameValue, error) {
	rv := make([]*OtherNameValue, 0)
	if certificate == nil {
		return nil, errors.New("certificate is nil")
	}
	otherNameValue, err := findOtherNameValue(certificate)
	if err != nil {
		return nil, err
	}
	if otherNameValue != "" {
		rv = append(rv, &OtherNameValue{
			Value:      otherNameValue,
			Type:       SanTypeOtherName,
			PolicyType: PolicyTypeSan,
		})
	}

	value, assigner, err := findPermanentIdentifiers(certificate)
	if err != nil {
		return nil, err
	}
	if value != "" {
		rv = append(rv, &OtherNameValue{
			Value:      value,
			Type:       SanTypePermanentIdentifierValue,
			PolicyType: PolicyTypeSan,
		})
	}
	if len(assigner) > 0 {
		rv = append(rv, &OtherNameValue{
			Value:      assigner.String(),
			Type:       SanTypePermanentIdentifierAssigner,
			PolicyType: PolicyTypeSan,
		})
	}
	if len(rv) == 0 {
		err = errors.New("no values found in the SAN attributes, please check if the certificate is an UZI Server Certificate")
		return nil, err
	}
	return rv, nil
}

func FindOtherNameValue(value []*OtherNameValue, policyType PolicyType, sanTypeName SanTypeName) (string, error) {
	for _, v := range value {
		if v != nil && v.PolicyType == policyType && v.Type == sanTypeName {
			return v.Value, nil
		}
	}
	return "", fmt.Errorf("failed to find value for policyType: %s and sanTypeName: %s", policyType, sanTypeName)
}

func findPermanentIdentifiers(cert *x509.Certificate) (string, asn1.ObjectIdentifier, error) {
	value := ""
	var assigner asn1.ObjectIdentifier
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
					var x StingAndOid
					_, err = asn1.Unmarshal(other.Value.Bytes, &x)
					if err != nil {
						return err
					}
					value = x.Value
					assigner = x.Assigner

				}
				return nil
			})
			if err != nil {
				return "", nil, err
			}

			return value, assigner, err
		}
	}
	return "", nil, nil
}

func findOtherNameValue(cert *x509.Certificate) (string, error) {
	value := ""
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
				if other.TypeID.Equal(OtherNameType) {
					_, err = asn1.Unmarshal(other.Value.Bytes, &value)
					if err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return "", err
			}
			return value, err
		}
	}
	return "", nil
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

func IsRootCa(signingCert *x509.Certificate) bool {
	return signingCert.IsCA && bytes.Equal(signingCert.RawIssuer, signingCert.RawSubject)
}
