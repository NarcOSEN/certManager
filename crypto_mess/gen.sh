#!/bin/bash
set -euo pipefail

# Create output directory
mkdir -p certs
cd certs

# Define key types that support signing
KEY_TYPES=("rsa" "dsa" "ec" "ed25519" "ed448")

# Curve name for EC
EC_CURVE="prime256v1"

# Step 1: Generate key pairs
echo "Generating key pairs..."
for key_type in "${KEY_TYPES[@]}"; do
  case "$key_type" in
  rsa)
    openssl genpkey -algorithm RSA -out "$key_type.key" -pkeyopt rsa_keygen_bits:2048
    ;;
  dsa)
    openssl dsaparam -out dsaparam.pem 2048
    openssl gendsa -out "$key_type.key" dsaparam.pem
    ;;
  ec)
    openssl ecparam -name "$EC_CURVE" -genkey -noout -out "$key_type.key"
    ;;
  ed25519 | ed448)
    openssl genpkey -algorithm "${key_type^^}" -out "$key_type.key"
    ;;
  esac
done

# Step 2: Generate self-signed CA certificates
echo "Generating CA certificates..."
for key_type in "${KEY_TYPES[@]}"; do
  subj="/CN=${key_type^^} CA"
  openssl req -new -x509 -key "$key_type.key" -out "$key_type"_ca.crt -subj "$subj" -days 365 || echo "Failed for $key_type"
done

# Step 3: Generate CSRs
echo "Generating CSRs..."
for key_type in "${KEY_TYPES[@]}"; do
  subj="/CN=${key_type^^} Certificate"
  openssl req -new -key "$key_type.key" -out "$key_type.csr" -subj "$subj"
done

# Step 4: Sign CSRs with every CA
echo "Signing CSRs with every CA..."
for csr_type in "${KEY_TYPES[@]}"; do
  for ca_type in "${KEY_TYPES[@]}"; do
    csr_file="$csr_type.csr"
    ca_cert="$ca_type"_ca.crt
    ca_key="$ca_type.key"
    output_cert="${csr_type}_signed_by_${ca_type}.crt"
    echo "Signing $csr_file with CA $ca_cert"
    openssl x509 -req -in "$csr_file" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial -out "$output_cert" -days 365 || echo "❌ Failed to sign $csr_file with $ca_type"
  done
done

echo "✅ All certificates and CSRs are generated in: $(pwd)"
