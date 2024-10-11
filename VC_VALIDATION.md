# Validating a UziServerCertificateCredential

This specification explains how to validate a Verifiable Credential of this type.

## About the UZI Server Certificate
UZI Server Certificates contain the URA number in the `san:otherName` field encoded in a compound string: 
```
<OID CA>-<versie-nr>-<UZI-nr>-<pastype>-<Abonnee-nr>-<rol>-<AGB-code>
```
After 8 nov 2023 the UZI Server Certificates  also has the URA number in the `san:otherName.permanentIdentifier` field. 

## Structure of the Verifiable Credential

The Verifiable Credential has the following structure:

1. The credential has a type `UziServerCertificateCredential`.
2. The `subject.id` points to the holder of the credential, typically a `did:nuts` or `did:web`.
3. The credential is issued by a `did:x509`, with changes defined in the
   section [Changes to the did:x509 Method Specification](#changes-to-the-didx509-method-specification), as part of
   this specification:
    1. The `x5c` header contains the UZI Server Certificate with the full certificate chain.
    2. The `x5t` header contains the sha1 hash of the UZI Server Certificate.
    3. The policy string of the `did:x509` contains either a `san:otherName.permanentIdentifier:<ura-number>` or
       `san:otherName:<ura-number>` policy.
    4. If the `san:otherName:<ura-number>` is present, the URA number should be found as part of the `san:otherName`
       field.
    5. If the `san:otherName.permanentIdentifier:<ura-number>` is present, the URA number should be found as part of the
       `san:otherName.permanentIdentifier` field.

## Validating a UziServerCertificateCredential Verifiable Credential

A UziServerCertificateCredential is valid when:

1. The credential MUST be of type `UziServerCertificateCredential`.
2. The `x5c` header MUST contain the UZI Server Certificate with the full certificate chain.
3. The `x5t` header MUST contain the sha1 hash of the UZI Server Certificate.
4. The signature of the Verifiable Credential MUST validate against the public key of the UZI Server Certificate.
5. The UZI Server Certificate chain MUST be valid and match
   the [UZI-register certificate chain](https://www.zorgcsp.nl/ca-certificaten).
6. The issuer of the credential MUST be a `did:x509` with changes defined in the
   section [Changes to the did:x509 Method Specification](#changes-to-the-didx509-method-specification).
7. The issuer of the credential MUST have an `san:otherName:<othername-value>` policy.
8. The value of `<othername-value>` MUST match the value of the
   `SubjectAltName (2.5.29.17)` `OtherName (2.5.5.5)` with the group 1 of the following regular expression as the URA number:
   ```regexp
   2\.16\.528\.1\.1007.\d+\.\d+-\d+-\d+-S-(\d+)-00\.000-\d+
   ```

## Changes to the did:x509 Method Specification

The UziServerCertificateCredential makes use of an additional otherName san-type. This 
san-type is currently not part of the x509 standard. The suggested policy definition will look like this:
```
policy-name     = "san"
policy-value    = san-type ":" san-value
san-type        = "email" / "dns" / "uri" / "otherName"
san-value       = 1*idchar
```
A request to support this will be 
