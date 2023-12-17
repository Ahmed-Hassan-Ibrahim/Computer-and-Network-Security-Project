import sys
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

#function to generate key===============================================
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)

    with open("private_key.pem", "wb") as f:
        f.write(private_pem)
    with open("public_key.pem", "wb") as f:
        f.write(public_pem)
#Function to encrypt the message========================================
def encrypt_message(public_keyfile, file):
    with open(public_keyfile, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
    message = open(file, "rb").read()
    encrypted_message = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
    with open("message.encrypted", "wb") as f:
        f.write(encrypted_message)
#Function to decrypt the message========================================
def decrypt_message(private_keyfile, file):
    message = open(file, "rb").read()
    with open(private_keyfile, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
                            key_file.read(),
                            password=None,)     
    decrypted_message = private_key.decrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
    with open("message.decrypted", "wb") as f:
        f.write(decrypted_message)
#Function to sign the message==========================================
def sign_message(private_keyfile, messagefile):
    with open(private_keyfile, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
                            key_file.read(),
                            password=None,)       
    message = open(messagefile, "rb").read()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    with open("message.signature", "wb") as f:
        f.write(signature)

#Function to verify signature=========================================
def verify_signature(public_keyfile, messagefile, signaturefile):
    with open(public_keyfile, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )
    message = open(messagefile, "rb").read()
    signature = open(signaturefile, "rb").read()
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

if __name__ == "__main__":
    # python RSA.py rsa -enc/-dec/-sign/-verify -gen/-inkey (pub/pri) infile (signaturefile)
    if sys.argv[1] == "rsa":
        if sys.argv[3] == "-gen":
            generate_key_pair()
        
        if sys.argv[2] == "-enc":
            if sys.argv[3] == "-inkey":
                encrypt_message(sys.argv[4],sys.argv[5])
            else :
                encrypt_message("public_key.pem", sys.argv[4])
        
        elif sys.argv[2] == "-dec":
            if sys.argv[3] == "-gen":
                print("Decryption error!")
                exit(1)
            decrypt_message(sys.argv[4],sys.argv[5])
        
        
        elif sys.argv[2] == "-sign":
             if sys.argv[3] == "-inkey":
                 sign_message(sys.argv[4], sys.argv[5])
             else : 
                sign_message("private_key.pem", sys.argv[4])
        
        elif sys.argv[2] == "-verify":
            if sys.argv[3] == "-gen":
                print("Verification error!")
                exit(1)    
            is_valid = verify_signature(sys.argv[4], sys.argv[5], sys.argv[6])
            if is_valid:
                print("Signature is valid.")
            else:
                print("Signature is invalid.")
#==========================================================================================
#->Required to be called from cmd and inputed by user
#->Allow user to have option either provide his own public, private key or generate them
#==========================================================================================