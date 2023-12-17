import sys
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

#function to generate key===============================================
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

#Function to sign the message==========================================
def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

#Function to verify signature=========================================
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Example usage
private_key, public_key = generate_key_pair()

# Message to be signed
message = b"Hello, this is a message to be signed."

# Generate signature
signature = sign_message(private_key, message)
# Verify signature
is_valid = verify_signature(public_key, message, signature)

if is_valid:
    print("Signature is valid.")
else:
    print("Signature is invalid.")
#==========================================================================================
#->Required to be called from cmd and inputed by user
#->Allow user to have option either provide his own public, private key or generate them
#==========================================================================================