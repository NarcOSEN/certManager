#!/bin/bash
mkdir -p certs csrs keys
cat >openssl.cnf <<EOF
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = Example
O = Example Org
C = US
EOF

# Generate keys for all algorithms
openssl genpkey -algorithm RSA -out keys/key_rsa.pem -pkeyopt rsa_keygen_bits:2048
openssl genpkey -algorithm EC -out keys/key_ec.pem -pkeyopt ec_paramgen_curve:secp384r1
openssl genpkey -algorithm ED25519 -out keys/key_ed25519.pem
openssl genpkey -algorithm ED448 -out keys/key_ed448.pem
openssl genpkey -algorithm X25519 -out keys/key_x25519.pem
openssl genpkey -algorithm X448 -out keys/key_x448.pem

# DSA requires parameter generation first
openssl genpkey -genparam -algorithm DSA -out keys/dsaparam.pem -pkeyopt dsa_paramgen_bits:2048
openssl genpkey -paramfile keys/dsaparam.pem -out keys/key_dsa.pem

# Generate CSRs for signing-capable keys
for alg in rsa dsa ec ed25519 ed448; do
  openssl req -new -config openssl.cnf -key keys/key_$alg.pem -out csrs/csr_$alg.pem
done

# Generate CA keys and self-signed certificates
for ca_alg in rsa dsa ec ed25519 ed448; do
  # Generate CA key
  case $ca_alg in
  dsa)
    openssl genpkey -paramfile keys/dsaparam.pem -out keys/ca_key_$ca_alg.pem
    ;;
  *)
    openssl genpkey -algorithm ${ca_alg^^} -out keys/ca_key_$ca_alg.pem \
      $([[ "$ca_alg" == "rsa" ]] && echo "-pkeyopt rsa_keygen_bits:2048") \
      $([[ "$ca_alg" == "ec" ]] && echo "-pkeyopt ec_paramgen_curve:secp384r1")
    ;;
  esac

  # Create self-signed CA cert
  openssl req -x509 -new -config openssl.cnf -key keys/ca_key_$ca_alg.pem \
    -out certs/ca_cert_$ca_alg.pem -subj "/CN=CA-$ca_alg"
done

# Sign all CSRs with all CA types
for signer in rsa dsa ec ed25519 ed448; do
  for signee in rsa dsa ec ed25519 ed448; do
    openssl x509 -req -in csrs/csr_$signee.pem -CA certs/ca_cert_$signer.pem \
      -CAkey keys/ca_key_$signer.pem -CAcreateserial \
      -out certs/cert_${signee}_signed_by_${signer}.pem 2>/dev/null
  done
done
