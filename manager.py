import os
import time
import json
from cryptography import x509
from cryptography import hazmat
import cryptography
from crypto_helper_functions import *
import logging
import datetime
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
"""

def curr_time():
    return datetime.datetime.now(tz=datetime.UTC)
def run_load():
    logging.basicConfig(filename="manager.logs",level=logging.INFO)
    logger.info("Started loading certificate from path:")
    file_paths = []
    for root, dir, files in os.walk("./crypto_mess/"):
        for file in files:
            full_path = os.path.join(root, file)
            file_paths.append(full_path)


    for path in file_paths:
        #logger.info(f'[{curr_time()}] Trying to load {path}')
        is_csr,is_cert,is_private_key = False,False,False
        try:
            with open(path, "rb") as file:
                read_data = file.read()
                try:
                    result_dict = get_der_cert_as_dict(read_data)
                    result_dict["path"] = path
                    is_cert = True
                except Exception as e:
                    #logger.info(f"[{curr_time()}]Couldn't load file {path} as DER X509 CERT. Exception: {e}")
                    pass
                try:
                    result_dict = get_pem_cert_as_dict(read_data)
                    result_dict["path"] = path
                    is_cert = True
                except Exception as e:
                    #logger.info(f"[{curr_time()}]Couldn't load file {path} as PEM X509 CERT. Exception: {e}")
                    pass 
                try:
                    result_dict = get_pem_csr_as_dict(read_data)
                    result_dict["path"] = path
                    is_csr = True
                except Exception as e:
                    #logger.info(f"[{curr_time()}]Couldn't load file {path} as PEM CSR. Exception: {e}")
                    pass 
                try:
                    result_dict = get_der_csr_as_dict(read_data)
                    result_dict["path"] = path
                    is_csr = True
                except Exception as e:
                    #logger.info(f"[{curr_time()}]Couldn't load file {path} as DER CSR. Exception: {e}")
                    pass 
                #TODO: Fix get_private_key_as_dict() function. Not working
                #try:
                #    passwords_list = [b"test", None]
                #    print(f"Successfully loaded {path} as PRIVATE KEY", json.dumps(
                #        get_private_key_as_dict(read_data, passwords_list=passwords_list)))
                #except Exception as e:
                #    print(f"Couldn't load file {path} as PRIVATE KEY.", e)
                #
                if is_cert == False and is_csr == False and is_private_key == False:
                    logger.info(f"[{curr_time()}] File {path} was read but could not be loaded as either csr, cert or private key. Skipping.")
                elif is_cert == True:
                    logger.info(f"[{curr_time()}] File {path} was read and loaded as x509 cert.")
                elif is_csr == True:
                    logger.info(f"[{curr_time()}] File {path} was read and loaded as x509 csr.")
                elif is_private_key == True:
                    logger.info(f"[{curr_time()}] File {path} was read and loaded as private key.")

        except Exception as e:
            logger.info(f"[{curr_time()}]Could not read file {path}. Exception: {e}")
        time.sleep(0.1)

if __name__ == "__main__":
    while True:
        run_load()
        time.sleep(10)
        #sleep(10)

