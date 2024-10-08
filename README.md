# HeadEase Nuts PKI Overheid Issuer

## Description

The HeadEase Nuts PKI Overheid Issuer is a Go-based tool designed for managing Public Key Infrastructure (PKI) operations within the HeadEase project. It focuses on the issuance and management of certificates in a regulated healthcare environment, ensuring secure communication and data integrity.

## Features

- Issuance of new certificates
- Validation of certificate chains
- Reading and handling PEM files
- Integration with the Nuts ecosystem for healthcare applications

## Prerequisites

Before you begin, ensure you have met the following requirements:

- You have installed Go SDK 1.23.1 or compatible version.
- You are using a Unix-based operating system like macOS or Linux.
- You have the necessary permissions to install software and manage certificates.

## Installation

Follow these steps to set up the project:

1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/headease-nuts-pki-overheid-issuer.git
   ```
2. **Change to the project directory:**
   ```sh
   cd headease-nuts-pki-overheid-issuer
   ```
3. **Download dependencies:**
   ```sh
   go mod tidy
   ```

## Usage

To use the HeadEase Nuts PKI Overheid Issuer:

1. **Build the project:**
   ```sh
   go build -o headease-nuts-pki-overheid-issuer main.go
   ```
   
2. **Run the application:**
   ```sh
   ./headease-nuts-pki-overheid-issuer
   ```

3. **Generating a new certificate:**
   - Use the CLI options provided by the application to generate new certificates. Refer to the help command for more details:
   ```sh
   ./headease-nuts-pki-overheid-issuer --help
   ```

## Project Structure

- `main.go`: The main entry point of the application.
- `ura_vc/pem_reader.go`: Handles reading PEM files.
- `ura_vc/x509_chain.go`: Manages X.509 certificate chains.
- `cert/*`: Directory containing certificate-related files.

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
