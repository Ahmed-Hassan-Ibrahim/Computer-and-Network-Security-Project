import AES
import RSA
import Hash
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl import backend
from base64 import urlsafe_b64encode

def source_Confidentiality_Authentication(message_file, private_key, symmetric_key):
    message = RSA.sign_message(private_key, message_file)
    AES.encrypt_file(message, "ENC", symmetric_key)
    AES.encrypt_file("message.signature", "ENC", symmetric_key)

def destination_Confidentiality_Authentication(public_key, symmetric_key):
    AES.decrypt_file("ENC\\Test.txt_encrypted.bin","DEC",symmetric_key)
    AES.decrypt_file("ENC\\message.signature_encrypted.bin","DEC",symmetric_key)
    is_valid = RSA.verify_signature(public_key,"DEC\\Test.txt_encrypted.bin_decrypted.bin","DEC\\message.signature_encrypted.bin_decrypted.bin")
    if is_valid:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")

