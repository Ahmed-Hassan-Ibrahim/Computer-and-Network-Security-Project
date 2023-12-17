import rsa

#Generate Public Key
with open("public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

#Generate Private Key
with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

#message to encrypt
message = "Hello, this message is sent from Ahmed Hassan"

#Signature
signature = rsa.sign(message.encode(), private_key, "SHA-256")

with open("signature", "wb") as f:
    f.write(signature)


with open("signature", "rb") as f:
    read_signature = f.read()

#public_key, private_key = rsa.newkeys(1024)

print(rsa.verify(message.encode(), read_signature, public_key))
