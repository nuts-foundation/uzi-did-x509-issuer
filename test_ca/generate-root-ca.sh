#!/bin/bash

if [[ $OSTYPE == msys ]]; then
  echo Script does not work on GitBash/Cygwin!
  exit 1
fi

CONFIG="
[req]
distinguished_name=dn
[ dn ]
[ ext ]
basicConstraints=CA:TRUE,pathlen:0
"

echo Generating root CA
openssl genrsa -out ca.key 2048
openssl req -config <(echo "$CONFIG") -extensions ext -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem -subj "/CN=Fake UZI Root CA"