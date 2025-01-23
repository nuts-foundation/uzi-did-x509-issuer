# Golang did:x509 and X509Credential Toolkit

[![Maintainability](https://api.codeclimate.com/v1/badges/f92496250890e40900aa/maintainability)](https://codeclimate.com/github/nuts-foundation/go-didx509-toolkit/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/f92496250890e40900aa/test_coverage)](https://codeclimate.com/github/nuts-foundation/go-didx509-toolkit/test_coverage)

## Description

This is a Golang-based toolkit for creating `did:x509` DIDs and `X509Credential`s.
`X509Credential`s can be used present the identity information contained in the `did:x509` DID as Verifiable Credential.

Its original purpose is to create Verifiable Credentials from certificates issued by the [UZI certificate chain from the CIBG registry](https://www.zorgcsp.nl/ca-certificaten).

## Features

### Creating `did:x509` DIDs

The toolkit creates `did:x509` DIDs as specified by https://trustoverip.github.io/tswg-did-x509-method-specification/.
It extends this DID method specification by adding support for the `san:otherName` field in the certificate (required by the CIBG UZI certificate use case).

### Issuing `X509Credential`s

The primary use of this toolkit is self-issuing `X509Credential`s through a `did:x509` DID, backed by an X.509 certificate.
To issue an `X509Credential`, provide the following parameters:

- **certificate_file**: the PEM file of the certificate
- **ca_fingerprint_dn**: the DN of the certificate in the chain that should be used as ca-fingerprint. 
  It must be one of the intermediate CA or root CAs. If invalid, it prints the DNs of the certificates in the chain.
- **signing_key**: the unencrypted PEM file of the private key used for signing.
- **credential_subject**: the ID of the credential subject, typically a DID.

Usage:
```shell
./issuer vc <certificate_file> <signing_key> <ca_fingerprint_dn> <credential_subject>
```

Example:
```shell
./issuer vc certificate.pem key.pem "CN=Fake Root CA"  did:web:example.com
```

### Validating `X509Credential`s

TODO

## Limitations

Only RSA keys are supported at the moment.

## Contributing

We welcome contributions! To contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Create a new Pull Request.

Please ensure your code follows the project's coding conventions and passes all tests.

## License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.
