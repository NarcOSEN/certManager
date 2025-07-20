from crypto_helper_functions import *
import os
import json


def check_value_types(input_dict):
    type_dict = {}
    for key, value in input_dict.items():
        type_dict[key] = type(value).__name__  # Get the type name as string
    return type_dict


def main():

    file_paths = []
    for root, dir, files in os.walk("crypto_mess"):
        for file in files:
            full_path = os.path.join(root, file)
            file_paths.append(full_path)

    for path in file_paths:
        with open(path, "rb") as file:
            read_data = file.read()
            try:
                print(f"Successfully loaded{path} as DER CERT.", json.dumps(
                    get_der_cert_as_dict(read_data)))
            except Exception as e:
                print(f"Couldn't load file {path} as DER X509 CERT.", e)
            try:
                print(f"Successfully loaded {path} as PEM CERT", json.dumps(
                    get_pem_cert_as_dict(read_data)))
            except Exception as e:
                print(f"Couldn't load file {path} as PEM X509 CERT.", e)
            try:
                print(f"Successfully loaded {path} as PEM CSR.", json.dumps(
                    get_pem_csr_as_dict(read_data)))
            except Exception as e:
                print(f"Coudln't load file {path} as PEM CSR.", e)
            try:
                print(f"Successfully loaded {path} as DER CSR", json.dumps(
                    get_der_csr_as_dict(read_data)))
            except Exception as e:
                print(f"Coudln't load file {path} as DER CSR.", e)
            try:
                passwords_list = [b"test", None]
                print(f"Successfully loaded {path} as PRIVATE KEY", json.dumps(
                    get_private_key_as_dict(read_data, passwords_list=passwords_list)))
            except Exception as e:
                print(f"Coudln't load file {path} as PRIVATE_KEY.", e)


if __name__ == "__main__":
    main()
    # comment
