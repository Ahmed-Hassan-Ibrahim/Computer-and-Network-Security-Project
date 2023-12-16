## Encryption

* Can encrypt/decrypt any binary file.
### Use a custom key :
```
python .\AES.py -enc <file_name> -key <key_file_name>
```
### Use a generated key :
```
python .\AES.py -enc <file_name> -gen
```
* **Note:** key is written to a file security is your responsibility.

## Decryption
```
python .\AES.py -dec <file_name> -key <key_file_name>
```
