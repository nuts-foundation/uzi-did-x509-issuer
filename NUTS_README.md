# Using the Nuts *UZI Server Certificaat Issuer* with *NUTS*
This guide describes how to load the generated VCs by the *UZI Server Certificaat Issuer* into a NUTS node.

## Prerequisites
The following is required to load the VC into the NUTS node
 * A UZI Server Certificate and private key, either a test or production. In order to use the test certificate, the `-t` option must be provided.
 * This tool, make sure to run `make build` for generating the binary. For more details see the [README.md](README.md) file.
 * A running NUTS node to create a did and load the certificate. The NUTS node will be referred to as ``${nuts_base_url}``
 * The NUTS node should have the [CA](http://cert.pkioverheid.nl/PrivateRootCA-G1.cer) cert added to the ca certificate chain `tls.truststorefile`.
 * The same goes for the test certificate, the [Test CA](http://www.uzi-register-test.nl/cacerts/test_zorg_csp_private_root_ca_g1.cer) should be added to the ca certificate chain `tls.truststorefile`.

## Issuing a VC to a NUTS node.
### Creating the subject (only once)
#### request
Parameters:
 * `nuts_base_url`: the internal base URL of the NUTS node
 * `subject`: the NUTS subject used to issue the VC to
```shell
curl --location '${nuts_base_url}/internal/vdr/v2/subject' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--data '{
  "subject": "${subject}"
}'
```
#### response
```json
{
    "documents": [
        {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json"
            ],
            ...
        }
    ],
    "subject": "zbj_test"
}
```
### Fetch the did
#### request
* `nuts_base_url`: the internal base URL of the NUTS node
* `subject`: the NUTS subject used to issue the VC to
```shell
curl --location '${nuts_base_url}/internal/vdr/v2/subject/${subject}' \
--header 'Accept: application/json'
```
#### response
The response contains the did that will be used for issuance.
```json
[
    "did:web:example.com:iam:809c0e66-dba7-496b-96b9-cd3ac71c34ff"
]
```
### Generate the VC
* `certificate_file`: the certificate file
* `key_file`: the private key paired with the certificate file
* `did`: the NUTS subject did
```shell
./issuer vc "${certificate_file}" "${key_file}" "${did}"
```
Note, for test certificates, use the `-t` flag.
```shell
./issuer vc "${certificate_file}" "${key_file}" "${did}" -t
```
The output looks like (abbreviated):
```text
ey...
```
### Load the VC into the NUTS node
* `nuts_base_url`: the internal base URL of the NUTS node
* `subject`: the NUTS subject used to issue the VC to
* `vc`: The VC from the previous step, note that the body is JSON and the VC should be surrounded with double quotes (").
```shell
curl --location '${nuts_base_url}/internal/vcr/v2/holder/${subject}/vc' \
--header 'Content-Type: application/json' \
--data '"${vc}"'
```

### Verify the VC's presence in NUTS
#### request
* `nuts_base_url`: the internal base URL of the NUTS node
* `subject`: the NUTS subject used to issue the VC to
```shell
curl --location '${nuts_base_url}/internal/vcr/v2/holder/${subject}/vc' \
--header 'Accept: application/json'
```
#### response
```json
[
    "ey..."
]
```
