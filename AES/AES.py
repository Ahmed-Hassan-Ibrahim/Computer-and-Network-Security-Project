import sys
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl import backend
from base64 import urlsafe_b64encode

# Password Based Key Derivation Function
# From Cryptography Lib documentation : https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
def generate_aes_key():
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(b"1901148")
    return key

def get_encryption_key(choice,ext_key,mode):
    if (choice.lower() == '-gen'):
        if (mode == 'dec'):
            print("Error: -gen cannot be used in decryption.")
            sys.exit(1)

        key = generate_aes_key()
        key_folder = 'key'
        os.makedirs(key_folder, exist_ok=True)  # Create the output folder if it doesn't exist
        output_key = os.path.join(key_folder,'key_secret.bin')
        with open(output_key, 'wb') as file:
            file.write(key)
        return key

    elif (choice.lower() == '-key'):
        if(ext_key == 0):
            print("Error: Please enter key filename")
            sys.exit(1)
        key_file_path = ext_key
        with open(key_file_path, 'rb') as key_file:
            custom_key = key_file.read()
            if len(custom_key) != 32:
                print("Error: Custom key must be 32 bytes long.")
                sys.exit(1)
        return custom_key

    else:
        print("Invalid option. Please enter '-gen' or '-key'.")
        sys.exit(1)

def pad(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def encrypt_file(input_file, output_folder, key):
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    plaintext = pad(plaintext)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    output_filename = os.path.join(output_folder, os.path.basename(input_file) + '_encrypted.bin')
    os.makedirs(output_folder, exist_ok=True)  # Create the output folder if it doesn't exist

    with open(output_filename, 'wb') as file:
        file.write(iv + ciphertext)

def decrypt_file(input_file, output_folder, key):
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_data = unpad(decrypted_data)
    os.makedirs(output_folder, exist_ok=True)  # Create the output folder if it doesn't exist

    output_filename = os.path.join(output_folder, os.path.basename(input_file) + '_decrypted.bin')

    with open(output_filename, 'wb') as file:
        file.write(decrypted_data)

def openssl_info():
    print(backend.openssl_version_text())

if __name__ == "__main__":
    choice = sys.argv[1]
    input_filename = sys.argv[2]
    key_choice = sys.argv[3]
    if len(sys.argv) == 5:
        key_file = sys.argv[4]
    else:
        key_file = 0

    openssl_info()

    encryption_output_folder = 'encryption'
    decryption_output_folder = 'decryption'

    encryption_key = get_encryption_key(key_choice,key_file,choice.lower())

    if choice.lower() == '-enc' :
        encrypt_file(input_filename, encryption_output_folder, encryption_key)
        print("Encryption Successful...")
    elif choice.lower() == '-dec':
        decrypt_file(input_filename, decryption_output_folder, encryption_key)
        print("Decryption Successful...")
