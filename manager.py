import os
import time
import json
from cryptography import x509
from cryptography import hazmat
import cryptography
from crypto_helper_functions import *
import logging
import datetime
import hashlib
logger = logging.getLogger(__name__)
"""
    During check try:
        * load as csr - if OK:
            - save csr to csr table.
            - save public key to public_keys table if not exists.
            - is_csr = true
        * load as signed certificate -if OK:
            - save certificate to certificates table if not exists.
            - save public key to public_keys table if not exists.
            - is_cert = true
        * load as private key - if OK:
            - save private key in private_keys table if not exists.
            -- is_private_key = true;
        else:
            - if is_csr == true:
                Log as csr with path to file.
            - else if is_cert == true:
                Log as cert with path to file.
            - else if is_private-key == true:
                Log as private_key with path to file.
            - else: Log with "could not load as either csr certificate or private key for path <path>"


###############################################################################################
DB schema:
    TABLE certificates:
    - sha256(public_key.public_bytes) PRIMARY KEY
    - public_bytes
    - path
    - subject
    - iso_not_valid_before_utc
    - iso_not_valid_after_utc
    - sha1_fingerprint

    TABLE csrs:
    - sha256(public_key.public_bytes) PRIMARY KEY
    - public_bytes
    - path
    - subject


    TABLE private_keys:
    - sha256(public_key.public_bytes) PRIMARY KEY
    - public_bytes
    - path



"""
def hash_string(text: str) -> str:
    """Return the SHA-256 hash of a given string."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()
def curr_time():
    return datetime.datetime.now(tz=datetime.UTC)
def run_load():
    logging.basicConfig(filename="dev.log",level=logging.INFO)
    logger.info("Started loading certificate from path:")
    file_paths = []
    for root, dir, files in os.walk("./home"):
        for file in files:
            full_path = os.path.join(root, file)
            file_paths.append(full_path)


    for path in file_paths:
        is_pem_cert, is_der_cert, is_pem_csr, is_der_csr, is_private_key, is_pem_bundle_list = False, False, False, False, False, False
        result_dict_der_cert = None
        result_dict_pem_csr = None
        result_dict_der_csr = None
        result_dict_private_key = None
        list_result_dict_pem_cert = None
        list_sha256 = None
        try:
            with open(path, "rb") as file:
                read_data = file.read()
                try:
                    result_dict_der_cert = get_der_cert_as_dict(read_data)
                    if result_dict_der_cert and "public_key" in result_dict_der_cert:
                        result_dict_der_cert["path"] = path
                        is_der_cert = True
                except Exception as der_cert_e:
                    pass
                try:
                    result_dict_pem_csr = get_pem_csr_as_dict(read_data)
                    if result_dict_pem_csr and "public_key" in result_dict_pem_csr:
                        result_dict_pem_csr["path"] = path
                        is_pem_csr = True
                except Exception as pem_csr_e:
                    pass
                try:
                    result_dict_der_csr = get_der_csr_as_dict(read_data)
                    if result_dict_der_csr and "public_key" in result_dict_der_csr:
                        result_dict_der_csr["path"] = path
                        is_der_csr = True
                except Exception as der_csr_e:
                    pass
                try:
                    list_result_dict_pem_cert = get_pem_certS_as_dict(read_data)
                    list_sha256 = []
                    for entry in list_result_dict_pem_cert:
                        if entry and "public_key" in entry:
                            sha256hash = hash_string(entry['public_key']['public_bytes'])
                            entry["path"] = path
                            list_sha256.append(sha256hash)
                            is_pem_bundle_list = True
                except Exception as pem_bundle_cert_e:
                    pass
                try:
                    passwords_list = [b'test', None]
                    result_dict_private_key = get_private_key_as_dict(read_data, passwords_list=passwords_list)
                    if result_dict_private_key and "public_key" in result_dict_private_key:
                        result_dict_private_key["path"] = path
                        is_private_key = True
                except Exception as pem_private_key_e:
                    pass


                if is_pem_bundle_list == False and is_der_cert == False and is_pem_csr == False and is_der_csr == False and is_private_key == False:
                    logger.info(f"[{curr_time()}] File {path} was read but could not be loaded as either csr, cert or private key. Skipping.")
                if is_pem_bundle_list == True:
                    logger.info(f"[{curr_time()}] File {path} was read and loaded as x509 cert BUNDLE. PubKey sha256 list: [{list_sha256}]")
                if is_der_cert == True:
                    logger.info(f"[{curr_time()}] File {path} was read and loaded as x509 der cert. PubKey Sha256: [{hash_string(result_dict_der_cert['public_key']['public_bytes'])}]")
                if is_pem_csr == True:
                    logger.info(f"[{curr_time()}] File {path} was read and loaded as x509 pem csr. PubKey Sha256: [{hash_string(result_dict_pem_csr['public_key']['public_bytes'])}]")
                if is_der_csr == True:
                    logger.info(f"[{curr_time()}] File {path} was read and loaded as x509 der csr. PubKey Sha256: [{hash_string(result_dict_der_csr['public_key']['public_bytes'])}]")
                if is_private_key == True:
                    logger.info(f"[{curr_time()}] File {path} was read and loaded as private key. PubKey Sha256: [{hash_string(result_dict_private_key['public_key']['public_bytes'])}]")
        except Exception as e:
            logger.info(f"[{curr_time()}] Could not read file {path}. Exception: {e,type(e)}")

if __name__ == "__main__":
    while True:
        run_load()
        time.sleep(50000)
