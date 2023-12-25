# Computer and Network Security Project
- Use openssl library to develop security tool.
- Allow user to define encryption methods and keys.
- Encrypt/Decrypt using shared key.
- Sign/Verify files using private/public certificates.
- Encrypt + Sign/Decrypt + Verify files using private/public certificates.
- Use Python, C/C++, C#, Java, JavaScript.
- Make software application for desktop, web or mobile.

<img src="https://fossa.com/blog/content/images/2022/10/openssl.png" width="500" height="250" />


--- 

# Commands

## Decryption

python .\AES.py -dec <file_name> -key <key_file_name>

## AES Encryption Providing Key

```
python .\App.py -enc <file_name> -key <key_file_name>
```

* Can encrypt/decrypt any binary file.

## AES Encryption Generated Key

```
python .\App.py -enc <file_name> -gen
```

* *Note:* key is written to a file security is your responsibility.

## AES Decryption

```
python .\App.py -dec <file_name> -key <key_file_name>
```
## Key Generation

```
python .\App.py -rsa -gen  
```

## RSA Encryption Providing Key

```
python .\App.py -rsa -enc -inkey <Public_Key_File_Name> <file_name>
```
## RSA Encryption Generated Key

```
python .\App.py -rsa -enc -gen <file_name>
```
## RSA Decryption Providing Key

```
python .\App.py -rsa -dec -inkey <Private_Key_File_Name> <Message_Encrypted_File_Name>  
```

## RSA Signature

```
python .\App.py -rsa -sign -gen <file_name>  
```
## RSA Verification

```
python .\App.py -rsa -verify -inkey <Public_Key_File_Name> <file_name> <Signed_Message_File_Name> 
```
## Hashing

```
python App.py -hash "Algorithm type" <file_name>
```
## Prepare Confidentiality + Authentication
```
python App.py -sign <file_name>  
```
## Verify Confidentiality + Authentication
```
python App.py -verify <Message_Encrypted_File_Name>  <Symmetric_Key_File_Name> <Public_Key_File_Name>  
```

## Self_Certification

```
python App.py -certify <subject_name> <issuer_name>   
```