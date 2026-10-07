#!/bin/bash

# CS469
# Fedil Grogan & Brian Leake
# cert_gen.sh is a small utility script that generates self-signed ssl certifcates for testing the cs469 fileserver.

openssl req -x509 -newkey rsa:4096 -keyout primary_key.pem -out primary_cert.pem -days 365 -nodes -subj "/CN=primary.localhost"
