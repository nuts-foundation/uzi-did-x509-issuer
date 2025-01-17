# did:x509 Golang Toolkit

[![Maintainability](https://api.codeclimate.com/v1/badges/f92496250890e40900aa/maintainability)](https://codeclimate.com/github/nuts-foundation/go-didx509-toolkit/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/f92496250890e40900aa/test_coverage)](https://codeclimate.com/github/nuts-foundation/go-didx509-toolkit/test_coverage)

## Description

This is a Golang-based toolkit for creating `did:x509` DIDs and `X509Credential`s.
`X509Credential`s can be used present the identity information contained in the `did:x509` DID as Verfiaible Credential.

Its original purpose is to create Verifiable Credentials from certificates issued by the [UZI certificate chain from the CIBG registry](https://www.zorgcsp.nl/ca-certificaten).

## Features

### Creating `did:x509` DIDs

It creates `did:x509` DIDs as specified by https://trustoverip.github.io/tswg-did-x509-method-specification/.
It extends this DID method specification by adding support for the `san:otherName` field in the certificate (required by the CIBG UZI certificate use case).

### Issuing `X509Credential`s

### Validating `X509Credential`s

TODO

## Usage

1. **Run the application:**

   ```sh
   ./issuer
   ```

2. **Getting command line help:**
   - Use the CLI options provided by the application to generate new certificates. Refer to the help command for more details:
   ```sh
   ./issuer --help
   ```
3. **Call for generating a VC:**
   - The following parameters are required:
     - **certificate_file**, the PEM file of the URA server certificate
     - **signing_key** ,the unencrypted PEM file of the private key used for signing.
     - **subject_did** and **subject_name**, the vc.subject.id and vc.subject.name of the generated verifiable credential.

### Examples

- **Example call with a TEST certificate**
  ```
  ./issuer vc cert.pem key.key did:web:example.com:example --test
  ```
- **Example call with a production certificate**
  ```
  ./issuer vc cert.pem key.key did:web:example.com:example
  ```

## Limitations

Only RSA keys are supported at the moment.

## Project UZI CA and Intermediate CA files

This project downloads the relevant CA certs from:

- [https://www.zorgcsp.nl/ca-certificaten](https://www.zorgcsp.nl/ca-certificaten)
- [https://acceptatie.zorgcsp.nl/ca-certificaten](https://acceptatie.zorgcsp.nl/ca-certificaten)

## Converting to PEM files:

The following command converts .cer files to PEM:

```shell
 openssl x509 -inform der -in certificate.cer -out certificate.pem
```

## Validating a X509Credential

The logic on Validating a X509Credential is described in the [VC_VALIDATION.md](VC_VALIDATION.md) file.

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
