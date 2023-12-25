import sys
import AES
import datetime
import RSA
import Hash
import Signing
import Certificate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl import backend
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

if __name__ == "__main__":
    #AES============================================================
    if sys.argv[1].lower() == "-enc" or sys.argv[1].lower() == '-dec' :
        choice = sys.argv[1]
        input_filename = sys.argv[2]
        key_choice = sys.argv[3]
        if len(sys.argv) == 5:
            key_file = sys.argv[4]
        else:
            key_file = 0
        AES.openssl_info()
        encryption_output_folder = 'encryption'
        decryption_output_folder = 'decryption'

        encryption_key = AES.get_encryption_key(key_choice,key_file,choice.lower())

        if choice.lower() == '-enc' :
            AES.encrypt_file(input_filename, encryption_output_folder, encryption_key)
            print("Encryption Successful...")
        elif choice.lower() == '-dec':
            AES.decrypt_file(input_filename, decryption_output_folder, encryption_key)
            print("Decryption Successful...")
    
    #RSA============================================================
    if sys.argv[1] == "-rsa":
        if sys.argv[2] == "-gen":
            RSA.generate_key_pair()
        
        if sys.argv[2] == "-enc":
            if sys.argv[3] == "-inkey":
                #User provide public key encrypt_message(Public Key,Message)
                RSA.encrypt_message(sys.argv[4],sys.argv[5])
            elif sys.argv[3] == "-gen":
                #Uses generated public key encrypt_message(Public Key,Message)
                RSA.generate_key_pair()
                RSA.encrypt_message("public_key.pem", sys.argv[4])
        
        elif sys.argv[2] == "-dec":
            if sys.argv[3] == "-gen":
                print("Error: -gen cannot be used in decryption.")
                sys.exit(1)
            RSA.decrypt_message(sys.argv[4],sys.argv[5])
        
        
        elif sys.argv[2] == "-sign":
            if sys.argv[3] == "-inkey":
                #User provide public key sign_message(Public Key,Message)
                RSA.sign_message(sys.argv[4],sys.argv[5])
            else:
                #Uses generated public key encrypt_message(Public Key,Message)
                RSA.generate_key_pair()
                RSA.sign_message("private_key.pem", sys.argv[4])
        
        elif sys.argv[2] == "-verify":
            if sys.argv[3] == "-gen":
                print("Error: -gen cannot be used in Verification.")
                sys.exit(1)
            #verify_signature(public_keyfile, messagefile, signaturefile) 
            is_valid = RSA.verify_signature(sys.argv[4], sys.argv[5], sys.argv[6])
            if is_valid:
                print("Signature is valid.")
            else:
                print("Signature is invalid.")
                
    #Hash============================================================
    if sys.argv[1] == "-hash":
        #calculate_hash(message, Hashing Algorithm)
        Hash.calculate_hash(sys.argv[3], sys.argv[2])
        
    #Conf+Auth============================================================
    if sys.argv[1] == "-sign":
        symmetric_key,public_key,encrypted_message = Signing.Source_Confidentiality_Authentication(sys.argv[2])
    if sys.argv[1] == "-verify":
        #Destination_Confidentiality_Authentication(encrypted_message, symmetric_key, public_key)
        if(Signing.Destination_Confidentiality_Authentication(sys.argv[2],sys.argv[3],sys.argv[4])):
            print("Verified")
        else:
            print("Not Verified")
    #Self-Signed Certificate============================================================
    if sys.argv[1] == "-certify":
        subject_name = sys.argv[2]
        issuer_name = sys.argv[3]

        private_key, public_key = Certificate.generate_key_pair()
        certificate = Certificate.generate_self_signed_certificate(private_key, public_key, subject_name, issuer_name)

        Certificate.save_private_key(private_key, "private_key.pem")
        Certificate.save_public_key(public_key, "public_key.pem")
        Certificate.save_certificate(certificate, "certificate.pem")