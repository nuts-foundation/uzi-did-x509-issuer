To issue a new fake UZI certificate, you can use the following command:

```bash
./issue-cert.sh <domain> <uzi> <ura> <agb>
```

You can then use the credential issuance tool (given you've run `go build .` in the parent directory) to generate a Verifiable Credential:

```bash
 ../issuer vc test_ca/out/<domain>-chain.pem test_ca/out/<domain>.key <did>
```