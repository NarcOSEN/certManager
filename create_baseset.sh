#!/bin/bash
set -e

OUT_DIR="crypto_mess"
mkdir -p $OUT_DIR/{roots,intermediates,leaves,keys,csrs,pfx,broken,misc}

# Generate Roots (RSA/ECC)
openssl genrsa -out $OUT_DIR/roots/root_rsa.key 4096
openssl req -x509 -new -key $OUT_DIR/roots/root_rsa.key -out $OUT_DIR/roots/root_rsa.crt -days 3650 -subj "/CN=Global RSA Root"
openssl ecparam -genkey -name secp384r1 -out $OUT_DIR/roots/root_ec.key
openssl req -x509 -new -key $OUT_DIR/roots/root_ec.key -out $OUT_DIR/roots/root_ec.crt -days 3650 -subj "/CN=Global ECC Root"

# Generate Intermediates (RSA/ECC, cross-signed)
for type in rsa ec; do
  openssl genrsa -out $OUT_DIR/intermediates/int_${type}1.key 2048
  openssl req -new -key $OUT_DIR/intermediates/int_${type}1.key -out $OUT_DIR/intermediates/int_${type}1.csr -subj "/CN=${type^^} Intermediate 1"
  openssl x509 -req -in $OUT_DIR/intermediates/int_${type}1.csr -CA $OUT_DIR/roots/root_${type}.crt -CAkey $OUT_DIR/roots/root_${type}.key -CAcreateserial -out $OUT_DIR/intermediates/int_${type}1.crt -days 1800
done

# Generate Leaf Certs (Server/Client, expired, wildcard)
generate_leaf() {
  parent_cert=$1
  parent_key=$2
  name=$3
  days=$4
  openssl genrsa -out $OUT_DIR/leaves/${name}.key 2048
  openssl req -new -key $OUT_DIR/leaves/${name}.key -out $OUT_DIR/leaves/${name}.csr -subj "/CN=$name"
  openssl x509 -req -in $OUT_DIR/leaves/${name}.csr -CA $parent_cert -CAkey $parent_key -out $OUT_DIR/leaves/${name}.crt -days $days
}
generate_leaf $OUT_DIR/intermediates/int_rsa1.crt $OUT_DIR/intermediates/int_rsa1.key "server_valid" 365
#generate_leaf $OUT_DIR/roots/root_ec.crt $OUT_DIR/roots/root_ec.key "client_expired" -365

# Generate Keys (RSA/ECC/EdDSA, encrypted)
openssl genpkey -algorithm Ed25519 -out $OUT_DIR/keys/ed25519.key
openssl genrsa -aes256 -passout pass:test -out $OUT_DIR/keys/encrypted_rsa.key 2048

# Generate PKCS#12 Bundles
openssl pkcs12 -export -password pass:test -out $OUT_DIR/pfx/full_chain.p12 -inkey $OUT_DIR/leaves/server_valid.key -in $OUT_DIR/leaves/server_valid.crt -certfile $OUT_DIR/intermediates/int_rsa1.crt

# Create DER Variants
openssl x509 -in $OUT_DIR/roots/root_rsa.crt -outform DER -out $OUT_DIR/roots/root_rsa.der
openssl rsa -in $OUT_DIR/keys/encrypted_rsa.key -outform DER -out $OUT_DIR/keys/encrypted_rsa.der -passin pass:test

# Create broken/invalid files
head -c 500 /dev/urandom >$OUT_DIR/broken/corrupted.crt
cp $OUT_DIR/leaves/server_valid.key $OUT_DIR/broken/cert_as_key.crt
echo "NOT A KEY" >$OUT_DIR/broken/fake.key

# Create non-crypto files
echo "Just a text file" >$OUT_DIR/misc/notes.txt
base64 /dev/urandom | head -c 1M >$OUT_DIR/misc/data.bin

# Create ambiguous extensions
cp $OUT_DIR/intermediates/int_rsa1.crt $OUT_DIR/intermediates/int_rsa1.pem
cp $OUT_DIR/leaves/client_expired.key $OUT_DIR/leaves/client_expired.pem
