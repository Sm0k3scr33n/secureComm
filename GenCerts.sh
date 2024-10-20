#!/bin/bash

# Default names
CERT_NAME="cert.pem"
KEY_NAME="key.pem"

# Check for input parameters
while getopts c:k: flag
do
    case "${flag}" in
        c) CERT_NAME=${OPTARG};;
        k) KEY_NAME=${OPTARG};;
    esac
done

# Generate the private key
openssl genrsa -out $KEY_NAME 2048

# Generate the certificate signing request (CSR)
openssl req -new -key $KEY_NAME -out csr.pem

# Generate the self-signed certificate
openssl x509 -req -days 365 -in csr.pem -signkey $KEY_NAME -out $CERT_NAME

# Clean up the CSR
rm csr.pem

echo "Generated $CERT_NAME and $KEY_NAME"

