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

## Encryption

* Can encrypt/decrypt any binary file.

### Use a custom key :


python .\AES.py -enc <file_name> -key <key_file_name>

### Use a generated key :


python .\AES.py -enc <file_name> -gen


* *Note:* key is written to a file security is your responsibility.

## Decryption


python .\AES.py -dec <file_name> -key <key_file_name>