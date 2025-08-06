import os
from base64 import b64encode as std_b64encode, b64decode as std_b64decode
from Crypto.Cipher import AES, DES, Blowfish, ChaCha20
from Crypto.PublicKey import RSA, ECC, ElGamal
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pickle

from .utils import (
    apply_salt,
    remove_salt,
    pkcs7_pad,
    pkcs7_unpad,
    read_file,
    write_file
)

KEY_SIZES = {
    "aes": 32,
    "des": 8,
    "blowfish": 16,
    "chacha20": 32,
    "rsa": 2048,
    "fernet": 32
}

BLOCK_SIZES = {
    "aes": AES.block_size,
    "des": DES.block_size,
    "blowfish": Blowfish.block_size
}

PBKDF2_ITERATIONS = 100_000
CIPHER_CLASSES = {"aes": AES, "des": DES, "blowfish": Blowfish}

# ---------- Key Generation ----------

def generate_key(method: str):
    method = method.lower()
    if method in ("aes", "des", "blowfish", "chacha20"):
        return get_random_bytes(KEY_SIZES[method])
    if method == "fernet":
        return Fernet.generate_key()
    if method == "rsa":
        key = RSA.generate(KEY_SIZES[method])
        return key.publickey().export_key(), key.export_key()
    raise ValueError(f"Unsupported method: {method}")

def generate_keypair(method='rsa', key_size=2048):
    method = method.lower()
    if method == 'rsa':
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    elif method == 'ecc':
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        return private_key, public_key
    elif method == 'elgamal':
        key = ElGamal.generate(1024, Random.new().read)
        return key, key.publickey()
    else:
        raise ValueError("Key generation for method not supported")

# ---------- Password Key Derivation ----------

def derive_key_from_password(password: str, method: str, salt: bytes = None):
    if not salt:
        salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=KEY_SIZES[method], count=PBKDF2_ITERATIONS)
    return key, salt

# ---------- Symmetric Encrypt/Decrypt ----------

def symmetric_encrypt(data: bytes, key, method):
    if method in CIPHER_CLASSES:
        cipher = CIPHER_CLASSES[method].new(key, CIPHER_CLASSES[method].MODE_CBC)
        return cipher.iv + cipher.encrypt(pkcs7_pad(data))
    if method == "chacha20":
        cipher = ChaCha20.new(key=key)
        return cipher.nonce + cipher.encrypt(data)
    if method == "fernet":
        return Fernet(key).encrypt(data)
    raise ValueError(f"Unsupported symmetric method: {method}")

def symmetric_decrypt(data: bytes, key, method):
    if method in CIPHER_CLASSES:
        bs = BLOCK_SIZES[method]
        iv, ciphertext = data[:bs], data[bs:]
        cipher = CIPHER_CLASSES[method].new(key, CIPHER_CLASSES[method].MODE_CBC, iv)
        return pkcs7_unpad(cipher.decrypt(ciphertext))
    if method == "chacha20":
        nonce, ciphertext = data[:8], data[8:]
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return cipher.decrypt(ciphertext)
    if method == "fernet":
        return Fernet(key).decrypt(data)
    raise ValueError(f"Unsupported symmetric method: {method}")

# ---------- Asymmetric Hybrid Encrypt/Decrypt ----------

def hybrid_encrypt_file(filename: str, pub_key, method="rsa", salt=False, out_filename=None, sym_method="aes") -> str:
    data = read_file(filename)
    if salt:
        data = apply_salt(data)

    session_key = get_random_bytes(KEY_SIZES[sym_method])
    encrypted_data = symmetric_encrypt(data, session_key, sym_method)

    if method == "rsa":
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(pub_key))
        encrypted_session_key = cipher_rsa.encrypt(session_key)
    elif method == "elgamal":
        encrypted_session_key = pickle.dumps(pub_key.encrypt(session_key, 32))
    elif method == "ecc":
        ephemeral_key = ec.generate_private_key(ec.SECP384R1())
        shared_key = ephemeral_key.exchange(ec.ECDH(), pub_key)
        derived_key = hashes.Hash(hashes.SHA256())
        derived_key.update(shared_key)
        session_key = derived_key.finalize()[:32]
        encrypted_data = symmetric_encrypt(data, session_key, sym_method)
        ephemeral_pub_bytes = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        encrypted_session_key = ephemeral_pub_bytes
    else:
        raise ValueError("Unsupported asymmetric method")

    final = sym_method.encode() + b'||' + encrypted_session_key + b'||' + encrypted_data
    out_path = out_filename or (filename + ".enc")
    write_file(out_path, final)
    return out_path

def hybrid_decrypt_file(filename: str, priv_key, method="rsa", salt=False, out_filename=None) -> str:
    data = read_file(filename)
    try:
        sym_method_raw, encrypted_key, encrypted_data = data.split(b'||', 2)
        sym_method = sym_method_raw.decode()
    except ValueError:
        raise ValueError("Invalid hybrid encryption format. Expected sym_method||key||data")

    if method == "rsa":
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(priv_key))
        session_key = cipher_rsa.decrypt(encrypted_key)
    elif method == "elgamal":
        decrypted_key = pickle.loads(encrypted_key)
        session_key = priv_key.decrypt(decrypted_key)
    elif method == "ecc":
        peer_pub_key = serialization.load_pem_public_key(encrypted_key)
        shared_key = priv_key.exchange(ec.ECDH(), peer_pub_key)
        derived_key = hashes.Hash(hashes.SHA256())
        derived_key.update(shared_key)
        session_key = derived_key.finalize()[:32]
    else:
        raise ValueError("Unsupported asymmetric method")

    decrypted = symmetric_decrypt(encrypted_data, session_key, sym_method)
    if salt:
        decrypted = remove_salt(decrypted)
    out_path = out_filename or filename.replace(".enc", ".dec")
    write_file(out_path, decrypted)
    return out_path

# ---------- Symmetric File-Level Encrypt/Decrypt ----------

def encrypt_file(filename: str, key: bytes, method="aes", salt=False, out_filename=None) -> str:
    data = read_file(filename)
    if salt:
        data = apply_salt(data)
    encrypted = symmetric_encrypt(data, key, method)
    out_path = out_filename or (filename + ".enc")
    write_file(out_path, encrypted)
    return out_path

def decrypt_file(filename: str, key: bytes, method="aes", salt=False, out_filename=None) -> str:
    encrypted = read_file(filename)
    decrypted = symmetric_decrypt(encrypted, key, method)
    if salt:
        decrypted = remove_salt(decrypted)
    out_path = out_filename or filename.replace(".enc", ".dec")
    write_file(out_path, decrypted)
    return out_path

# ---------- String Encrypt/Decrypt ----------

def encrypt_string(data: str, key: bytes, method: str = "aes", salt: bool = False) -> bytes:
    data = data.encode()
    if salt:
        data = apply_salt(data)
    return symmetric_encrypt(data, key, method)

def decrypt_string(ciphertext: bytes, key: bytes, method: str = "aes", salt: bool = False) -> bytes:
    plaintext = symmetric_decrypt(ciphertext, key, method)
    return remove_salt(plaintext) if salt else plaintext
