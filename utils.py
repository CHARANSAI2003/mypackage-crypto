import os
import base64

# 🔐 Salt Generation
def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)

# 🔐 Salt Application
def apply_salt(data: bytes) -> bytes:
    salt = generate_salt()
    print(f"[DEBUG] Applying Salt: {salt.hex()}")  # See this in your terminal
    return salt + data


# 🔐 Salt Removal (renamed to match crypto.py)
def remove_salt(data: bytes, length: int = 16) -> bytes:
    salt = data[:length]
    print(f"[DEBUG] Removing Salt: {salt.hex()}")  # Salt being removed
    return data[length:]


# 📦 PKCS7 Padding (renamed to match crypto.py)
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

# 📦 PKCS7 Unpadding (renamed to match crypto.py)
def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Cannot unpad empty data.")
    pad_len = data[-1]
    if pad_len > len(data):
        raise ValueError("Invalid padding length.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding.")
    return data[:-pad_len]

# 🔁 Base64 Encoding
def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

# 🔁 Base64 Decoding
def b64decode(data: str) -> bytes:
    return base64.b64decode(data)

# 📁 File Read
def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

# 📁 File Write
def write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
