#!/usr/bin/env bash
# Self-signed certificate for the TLS fixture target (TEST DATA ONLY).
# Deliberately weak properties so the TLS engine has genuine conditions to detect:
#   - CN/SAN do NOT match 127.0.0.1 or localhost  → hostname mismatch (TLS-005)
#   - self-signed, not in any CA store            → trust problem (TLS-006)
#   - SHA-1 signature                             → weak signature algorithm (TLS-004)
#   - 10-day validity                             → expiring soon (TLS-003)
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/../fixtures/vuln-app/certs"
mkdir -p "$DIR"
openssl req -x509 -newkey rsa:2048 -sha1 -days 10 -nodes \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
  -subj "/CN=meridian-fixture.local/O=Meridian Fixture (TEST)" \
  -addext "subjectAltName=DNS:meridian-fixture.local,DNS:fixture.local" \
  -addext "basicConstraints=critical,CA:FALSE" 2>/dev/null
echo "[certs] generated deliberately-weak self-signed fixture certificate in $DIR (CN=meridian-fixture.local, SHA-1, 10 days)"
