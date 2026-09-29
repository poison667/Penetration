#!/usr/bin/env bash
# Self-signed certificate for the TLS fixture target (TEST DATA ONLY).
# CN deliberately does NOT match 127.0.0.1 so the TLS engine has a genuine
# hostname-mismatch + self-signed condition to detect.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/../fixtures/vuln-app/certs"
mkdir -p "$DIR"
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
  -subj "/CN=meridian-fixture.local/O=Meridian Fixture (TEST)" \
  -addext "subjectAltName=DNS:meridian-fixture.local,DNS:fixture.local" \
  -addext "basicConstraints=critical,CA:FALSE" 2>/dev/null
echo "[certs] generated self-signed fixture certificate in $DIR (CN=meridian-fixture.local — intentionally mismatched for TLS engine testing)"
