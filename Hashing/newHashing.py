import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import hashlib


## genereting the private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# def hasing(plaintext):
#     '''
#         input : plaintext-> str
#         output :-> encrypted text which is 64 character long.
#         hash function : (sha-256)
#     '''
#     hash_object = hashlib.sha512(text.encode()) ## I used sha256 as a hash function
#     hashed_text = hash_object.hexdigest() ## convert a binary  into a hexadecimal (64 charachter)
#     return hashed_text


def EncryptWitPrivateKey(file_path, privateKey=None, algorithm ="sha512",  buffer_size=65536):
    '''
        here the input hash -> must be a byte represent b'text'
    '''

    digest = hashes.Hash(hashes.SHA512(),backend=default_backend())
    # Open the file in binary mode
    with open(file_path, "rb") as file:
        # Read the file in chunks and update the hash object
        for chunk in iter(lambda: file.read(buffer_size), b""):
            digest.update(chunk)
            
    hashed_data = digest.finalize()

    with open('hashing.sha512', 'w') as file:
        # Write content to the file
        file.write(f"{file}: {hashed_data}\n")
        
    signature = private_key.sign(    ## here we assign the hashed data with the the private key
        hashed_data, ## data -> the data to be encrypted 
        padding.PSS( ## padding -> padding
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ), 
        hashes.SHA512() # the algorthim which is used SHA-256
    )
    public_key = private_key.public_key()
    try:
        public_key.verify(
            signature,
            hashed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        with open('hashing.sha512', 'a') as file:
            # Write content to the file
            file.write(f"{file}: {signature}\n")
       
        print("Done")
    except:
        print("Faild")
    
# print(private_key.public_key())

# text = b"mansour mohamed mansour" ## where b represent it is a seris of bytes.
# EncryptWitPrivateKey(text,private_key)

# def hash_file(file_path, algorithm="sha512", buffer_size=65536):
#     # Create a hash object using the specified algorithm
#     hash_object = hashlib.new(algorithm)

#     # Open the file in binary mode
#     with open(file_path, "rb") as file:
#         # Read the file in chunks and update the hash object
#         for chunk in iter(lambda: file.read(buffer_size), b""):
#             hash_object.update(chunk)

#     # Get the hexadecimal representation of the hash
#     file_hash = hash_object.hexdigest()

#     return file_hash

# def save_hash_to_file(file_path, hash_value):
#     with open("hashes.txt", "a") as hash_file:
#         hash_file.write(f"{file_path}: {hash_value}\n")

# Example usage
file_path = 'athan.mp3'
EncryptWitPrivateKey(file_path,private_key)
