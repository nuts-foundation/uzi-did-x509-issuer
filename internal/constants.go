package internal

import (
	"encoding/asn1"
)

var (
	// SubjectAlternativeNameType represents the ASN.1 Object Identifier for Subject Alternative Name.
	SubjectAlternativeNameType = asn1.ObjectIdentifier{2, 5, 29, 17}
	PermanentIdentifierType    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	OtherNameType              = asn1.ObjectIdentifier{2, 5, 5, 5}
)
