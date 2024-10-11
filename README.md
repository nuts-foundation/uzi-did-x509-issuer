# Nuts UZI Server Certificaat Issuer 


< 8 nov 2023

## Description

The UZI Server Certificaat Issuer is a Go-based tool designed for issuing Verifiable Credentials signed by a UZI Server Certificaat. The issuer creates a did:x509 based on the PKI certificate chain.

## Features

The UZI Server Certificaat Issuer generated a Verifiable Credential of type UziServerCertificateCredential with the following features:

- The DID method is a customized did:x509 DID pointing to the x5c header.
- The x5c filled with the certificate chain. The chain is built from:
  - The provided UZI server (Test) Certificate
  - All the required certificates from the [UZI register](https://www.zorgcsp.nl/certificate-revocation-lists-crl-s). 
  - If the test mode is enabled, the [Test UZI register](https://acceptatie.zorgcsp.nl/ca-certificaten)
- Signed by the private key of the UZI Server Certificaat.
- The VC issued to the provided DID and name.

## Note on security, trust, and secrecy 
The VC that is signed by this application are cryptographic proofs, signed by the private key used in the UZI Server Certificate process. Note that:
* This private key is supposed to be kept very secret.
* The Subject DID of the signed credential is mandated with cryptographic proof to act on behalf of the owner of the private key on the NUTS network.  

## Prerequisites

Before you begin, ensure you have met the following requirements:

- You have installed Go SDK 1.23.1 or compatible version.
- You are using a Unix-based operating system like macOS or Linux.
- You have the necessary permissions to install software and manage certificates.

## Installation

Follow these steps to set up the project:

1. **Clone the repository:**
   ```sh
   git clone https://github.com/nuts-foundation/uzi-did-x509-issuer
   ```
2. **Change to the project directory:**
   ```sh
   cd uzi-did-x509-issuer
   ```
3. **Download dependencies:**
   ```sh
   go mod download && go mod verify
   ```
4. **Build the project:**
   ```sh
   go build -ldflags="-w -s " -o ./issuer
   ```

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
     - **subject_did** and **subject_name**, the vc.subject.id and  vc.subject.name of the generated verifiable credential.
### Examples
 - **Example call with a TEST certificate**
    ```
    ./issuer vc cert.pem key.key did:web:example.com:example --test
    ```
 - **Example call with a production certificate**
    ```
    ./issuer vc cert.pem key.key did:web:example.com:example
    ```

## Project UZI CA and Intermediate CA files
This project downloads the relevant CA certs from:
- [https://www.zorgcsp.nl/ca-certificaten](https://www.zorgcsp.nl/ca-certificaten)
- [https://acceptatie.zorgcsp.nl/ca-certificaten](https://acceptatie.zorgcsp.nl/ca-certificaten)

## Converting to PEM files:
The following command converts .cer files to PEM:
```shell
 openssl x509 -inform der -in certificate.cer -out certificate.pem
```
## Validating a UziServerCertificateCredential

The logic on Validating a UziServerCertificateCredential is described in the [VC_VALIDATION.md](VC_VALIDATION.md) file.

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

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

If you have any questions or suggestions, feel free to open an issue or contact the project maintainers at [roland@headease.nl](mailto:roland@headease.nl).
