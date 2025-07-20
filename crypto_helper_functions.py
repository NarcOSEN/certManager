from cryptography import x509
from cryptography import hazmat


def der_or_pem(data):
    if b"-----BEGIN CERTIFICATE-----" in data:
        return "PEM"
    try:
        x509.load_der_x509_certificate(data)
        return "DER"
    except Exception:
        return "Unknown or not certificate"


def get_private_key_as_dict(input_key, passwords_list):

    key_dict = {}
    for password in passwords_list:
        try:
            key = hazmat.primitives.serialization.load_der_private_key(
                input_key, password.encode())
            key_dict["password"] = password
            break
        except Exception as e:
            try:
                key = hazmat.primitives.serialization.load_pem_private_key(
                    input_key, password.encode())
                break
            except Exception as e:
                pass
    return key_dict


def get_der_csr_as_dict(input_csr):
    """
    Takes as input a DER CSR and returns python dict with useful stuff
    """
    try:
        loaded_csr = x509.load_der_x509_csr(input_csr)
        der_dict = {}
        der_dict["type"] = "DER_CSR"
        der_dict["public_key"] = get_public_key_as_dict(
            loaded_csr.public_key())
        der_dict["subject"] = {}
        for attribute in loaded_csr.subject:
            der_dict["subject"][attribute.oid._name] = attribute.value
        der_dict["signature"] = loaded_csr.signature.hex()
        der_dict["public_bytes"] = loaded_csr.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM).decode("utf-8")
        return der_dict
    except Exception as e:
        return e


def get_pem_csr_as_dict(input_csr):
    """
    Takes as input a PEM CSR and returns python dict with useful stuff
    """
    try:
        loaded_csr = x509.load_pem_x509_csr(input_csr)
        pem_dict = {}
        pem_dict["type"] = "PEM_CSR"
        pem_dict["public_key"] = get_public_key_as_dict(
            loaded_csr.public_key())
        pem_dict["subject"] = {}
        for attribute in loaded_csr.subject:
            pem_dict["subject"][attribute.oid._name] = attribute.value
        pem_dict["signature"] = loaded_csr.signature.hex()
        pem_dict["public_bytes"] = loaded_csr.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM).decode("utf-8")
        return pem_dict
    except Exception as e:
        return e


def get_der_cert_as_dict(input_der):
    """
        Takes as input a certificate as read bytes and outputs a dictionary
        containing certificate type (PEM here),
        public_key (subdict with keys modulus, type, public_bytes),
        subject, issuer, iso_not_valid_before_utc, iso_not_valid_after_utc,
        epoch_not_valid_before_utc, epoch_not_valid_after_utc,
        serial_number, sha1_fingerprint,public_bytes
    """
    try:
        loaded_der = x509.load_der_x509_certificate(input_der)
        der_dict = {}
        der_dict["type"] = "DER"
        der_dict["version"] = loaded_der.version.name
        der_dict["public_key"] = get_public_key_as_dict(
            loaded_der.public_key())
        der_dict["subject"] = {}
        for attribute in loaded_der.subject:
            der_dict["subject"][attribute.oid._name] = attribute.value
        der_dict["issuer"] = {}
        for attribute in loaded_der.issuer:
            der_dict["issuer"][attribute.oid._name] = attribute.value
        der_dict["iso_not_valid_before_utc"] = loaded_der.not_valid_before_utc.isoformat()
        der_dict["iso_not_valid_after_utc"] = loaded_der.not_valid_after_utc.isoformat()
        der_dict["epoch_not_valid_before_utc"] = int(
            loaded_der.not_valid_before_utc.timestamp())
        der_dict["epoch_not_valid_after_utc"] = int(
            loaded_der.not_valid_after_utc.timestamp())
        der_dict["serial_number"] = loaded_der.serial_number
        der_dict["sha1_fingerprint"] = ''.join(f'{b:02X}' for b in loaded_der.fingerprint(
            algorithm=hazmat.primitives.hashes.SHA1()))
        der_dict["public_bytes"] = loaded_der.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM).decode("utf-8")
    except Exception as e:
        return e
    return der_dict


def get_pem_cert_as_dict(input_pem):
    """
        Takes as input a certificate as read bytes and outputs a dictionary 
        containing certificate type (PEM here), 
        public_key (subdict with keys modulus, type, public_bytes),
        subject, issuer, iso_not_valid_before_utc, iso_not_valid_after_utc,
        epoch_not_valid_before_utc, epoch_not_valid_after_utc,
        serial_number, sha1_fingerprint,public_bytes
    """
    try:
        loaded_pem = x509.load_pem_x509_certificate(input_pem)
        pem_dict = {}
        pem_dict["type"] = "PEM"
        pem_dict["version"] = loaded_pem.version.name
        pem_dict["public_key"] = get_public_key_as_dict(
            loaded_pem.public_key())
        pem_dict["subject"] = {}
        for attribute in loaded_pem.subject:
            pem_dict["subject"][attribute.oid._name] = attribute.value
        pem_dict["issuer"] = {}
        for attribute in loaded_pem.issuer:
            pem_dict["issuer"][attribute.oid._name] = attribute.value
        pem_dict["iso_not_valid_before_utc"] = loaded_pem.not_valid_before_utc.isoformat()
        pem_dict["iso_not_valid_after_utc"] = loaded_pem.not_valid_after_utc.isoformat()
        pem_dict["epoch_not_valid_before_utc"] = int(
            loaded_pem.not_valid_before_utc.timestamp())
        pem_dict["epoch_not_valid_after_utc"] = int(
            loaded_pem.not_valid_after_utc.timestamp())
        pem_dict["serial_number"] = loaded_pem.serial_number
        pem_dict["sha1_fingerprint"] = ''.join(f'{b:02X}' for b in loaded_pem.fingerprint(
            algorithm=hazmat.primitives.hashes.SHA1()))
        pem_dict["public_bytes"] = loaded_pem.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM).decode("utf-8")
        return pem_dict

    except Exception as e:
        return e


def get_public_key_as_dict(input_key):
    """
    Takes as input a public key of type hazmat.bindings._rust.openssl.*
    Outputs the key type, modulus, public_bytes
    """

    if type(input_key) is hazmat.bindings._rust.openssl.rsa.RSAPublicKey:
        pub_key_dict = {}
        pub_key_dict["type"] = "RSAPublicKey"
        pub_key_dict["modulus"] = hex(input_key.public_numbers().n)
        pub_key_dict["public_bytes"] = input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM, format=hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        return pub_key_dict

    elif type(input_key) is hazmat.bindings._rust.openssl.dsa.DSAPublicKey:
        pub_key_dict = {}
        pub_key_dict["type"] = "DSAPublicKey"
        pub_key_dict["modulus"] = hex(input_key.public_numbers().y)
        pub_key_dict["public_bytes"] = input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM, format=hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        return pub_key_dict

    elif type(input_key) is hazmat.bindings._rust.openssl.ec.ECPublicKey:
        pub_key_dict = {}
        pub_key_dict["type"] = "ECPublicKey"
        pub_key_dict["modulus"] = {}
        pub_key_dict["modulus"]["x"] = input_key.public_numbers().x
        pub_key_dict["modulus"]["y"] = input_key.public_numbers().y
        pub_key_dict["public_bytes"] = input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM, format=hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        return pub_key_dict

    elif type(input_key) is hazmat.bindings._rust.openssl.ed25519.Ed25519PublicKey:
        pub_key_dict = {}
        pub_key_dict["type"] = "Ed25519PublicKey"
        pub_key_dict["modulus"] = ''.join(f'{b:02X}' for b in input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.Raw,
            format=hazmat.primitives.serialization.PublicFormat.Raw
        ))
        pub_key_dict["public_bytes"] = input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM, format=hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        return pub_key_dict

    elif type(input_key) is hazmat.bindings._rust.openssl.ed448.Ed448PublicKey:
        pub_key_dict = {}
        pub_key_dict["type"] = "Ed448PublicKey"
        pub_key_dict["modulus"] = ''.join(f'{b:02X}' for b in input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.Raw,
            format=hazmat.primitives.serialization.PublicFormat.Raw
        ))
        pub_key_dict["public_bytes"] = input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM, format=hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        return pub_key_dict

        # TODO: UNTESTED!!!
    elif type(input_key) is hazmat.bindings._rust.openssl.x25519.X25519PublicKey:
        pub_key_dict = {}
        pub_key_dict["type"] = "X25519PublicKey"
        pub_key_dict["modulus"] = ''.join(f'{b:02X}' for b in input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.Raw,
            format=hazmat.primitives.serialization.PublicFormat.Raw
        ))
        pub_key_dict["public_bytes"] = input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM, format=hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        return pub_key_dict

        # TODO: UNTESTED!!!
    elif type(input_key) is hazmat.bindings._rust.openssl.x448.X448PublicKey:
        pub_key_dict = {}
        pub_key_dict["type"] = "X448PublicKey"
        pub_key_dict["modulus"] = ''.join(f'{b:02X}' for b in input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.Raw,
            format=hazmat.primitives.serialization.PublicFormat.Raw
        ))
        pub_key_dict["public_bytes"] = input_key.public_bytes(
            encoding=hazmat.primitives.serialization.Encoding.PEM, format=hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        return pub_key_dict

    else:
        pub_key_dict = {}
        pub_key_dict["type"] = "UNKNOWN"

        return pub_key_dict
