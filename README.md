# mypackage

A Python package providing a comprehensive suite of cryptographic, encoding, hashing, and file compression utilities designed for secure data processing and manipulation. This package integrates advanced encryption (symmetric, asymmetric, and hybrid), diverse encoding/decoding methods, hashing algorithms, and helpful file I/O utilities.

## 📦 Project Structure

The `mypackage` folder contains the core modules of this project:

| File            | Description                                                                                                         |
|-----------------|---------------------------------------------------------------------------------------------------------------------|
| `__init__.py`   | Package initializer                                                                                                 |
| `compressor.py` | Utilities for compressing/decompressing folders and files                                                           | 
| `crypto.py`     | Symmetric and asymmetric encryption, hybrid cryptography schemes using PyCryptodome and Cryptography libraries      |
| `encoder.py`    | Encoding and decoding utilities, including Base64, URL, HTML, ASCII, UTF-8, binary, and Morse code                  |
| `hasher.py`     | Hashing and HMAC functions, supporting MD5, SHA family, BLAKE, and HMAC-SHA256                                      | 
| `utils.py`      | Helper functions for salt generation/application/removal, PKCS7 padding/unpadding, and file I/O                     |

## 🤖 Supported Language Models

This project also demonstrates integrations and compatibility with several open-source language models for NLP tasks:

- **llama3:8b-instruct-q4_0**  
- **phi3:mini**  
- **gemma:2b**

These models can be leveraged interchangeably depending on project needs for tasks such as instruction following, text generation, or embedding creation.

## 🔐 Security Features

- AES, DES, Blowfish, ChaCha20 symmetric encryption with PKCS7 padding
- RSA, ECC, ElGamal asymmetric encryption with hybrid file encryption support
- Fernet symmetric encryption support for easy-to-use secure data management
- Password-based key derivation using PBKDF2 with configurable salt and iterations
- Hybrid file encryption schemes combining asymmetric and symmetric methods
- Comprehensive encode/decode for multiple data representations and formats

## ⚙️ Installation

Install dependencies via pip:

pip install -r requirements.txt


Ensure the following key packages are installed:

- `cryptography>=42.0.0`
- `pycryptodome>=3.20.0`

## 📝 Usage Examples

### Compressing and Decompressing Folders

from mypackage import compressor

zip_file = compressor.compress_folder("data_folder")
extracted_folder = compressor.decompress_file(zip_file)


### Encrypting and Decrypting Files

from mypackage import crypto

Generate RSA key pair
priv_key, pub_key = crypto.generate_keypair('rsa')

Encrypt a file
encrypted_file = crypto.hybrid_encrypt_file("secret.txt", pub_key)

Decrypt the file
decrypted_file = crypto.hybrid_decrypt_file(encrypted_file, priv_key)


### Encoding and Decoding Strings

from mypackage import encoder

encoded = encoder.encode_base64(b"My secret message")
decoded = encoder.decode_base64(encoded)


### Hashing Strings

from mypackage import hasher

hashed = hasher.hash_data("password123", algorithm="sha256", salt="salty")
is_valid = hasher.verify_hash("password123", hashed, algorithm="sha256", salt="salty")


## 📁 File I/O Utilities

Utility functions for reading and writing bytes safely, along with salt application/removal and PKCS7 padding are provided in `utils.py` to support cryptographic and encoding workflows.

## 🙌 Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the [issues page](https://github.com/CHARANSAI2003/mypackage/issues) if you want to contribute.

---

## 👤 Author

**Charan Sai Batthala**  
- GitHub: [@CHARANSAI2003](https://github.com/CHARANSAI2003)  
- Email: charansai2003110@gmail.com  

---

*Last updated: August 2025*


