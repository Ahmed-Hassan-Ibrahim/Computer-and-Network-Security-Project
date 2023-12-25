from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key


import sys

def generate_key():
    return Fernet.generate_key()

def symmetric_encryption(message, key):
    cipher_suite = Fernet(key)
    encrypted_message = cipher_suite.encrypt(message)
    return encrypted_message

def symmetric_decryption(encrypted_message, key):
    cipher_suite = Fernet(key)
    decrypted_message = cipher_suite.decrypt(encrypted_message)
    return decrypted_message

def encrypt_message(message, key):
    ciphertext = key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(cipher_text, key):
    data = key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return data

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(message, private_key):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hashed_message = digest.finalize()

    signature = private_key.sign(
        hashed_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hashed_message = digest.finalize()
    try:
        public_key.verify(
            signature,
            hashed_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Signature is valid
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False  # Signature is invalid

def Source_Confidentiality_Authentication(path):
    with open(path, 'rb') as file:
        message = file.read()
    private_key, public_key = generate_key_pair()
    
    encrypted_signature = sign_message(message, private_key)

    symmetric_key = generate_key()

    combined_data = message + encrypted_signature
    encrypted_message = symmetric_encryption(combined_data,symmetric_key)

    print(combined_data)
    print(type(symmetric_key))

    with open("message_encrypted.txt", "wb") as f:
        f.write(encrypted_message)

    public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
# Write the bytes to a file
    with open("public_key.pem", "wb") as f:
        f.write(public_key_bytes)
    
    with open("Symmetric_Key.pem", "wb") as f:
        f.write(symmetric_key)
    return symmetric_key,public_key,encrypted_message
    

def Destination_Confidentiality_Authentication(encrypted_message_path, symmetric_key_path, public_key_path):
    with open(encrypted_message_path, 'rb') as file:
        encrypted_message = file.read()
    with open(public_key_path, "rb") as key_file:
        key = key_file.read()
        public_key = load_pem_public_key(key)
    with open(symmetric_key_path, 'rb') as file:
        symmetric_key = file.read()
    decrypted_combined_data = symmetric_decryption(encrypted_message,symmetric_key)
    decrypted_message = decrypted_combined_data[:-256]  # Assuming the hash length is 256 bits
    decrypted_signature = decrypted_combined_data[-256:]
    print("Decrypted Message:", decrypted_message)
    print("Decrypted Signature:", decrypted_signature)
    is_verified = verify_signature(decrypted_message,decrypted_signature,public_key)
    return is_verified


def main():
    # Message to be sent from the source to the destination
    message_to_send = "Hello, this is a confidential and authenticated message!"
    symmetric_key,public_key,encrypted_message = Source_Confidentiality_Authentication(message_to_send)
    if(Destination_Confidentiality_Authentication(encrypted_message,symmetric_key,public_key)):
        print("Verified")
    else:
        print("Not Verified")
        

if __name__ == "__main__":
    main()
