import urllib.parse
import html
from .utils import (
    generate_salt,
    apply_salt,
    remove_salt,
    b64encode,
    b64decode,
    read_file,
    write_file
)

# =========================
#   Encoding Methods
# =========================

def encode_base64(data: bytes, salt: bool = False) -> str:
    if salt:
        data = apply_salt(data)
    return b64encode(data)

def encode_url(data: bytes, salt: bool = False) -> str:
    if salt:
        data = apply_salt(data)
    return urllib.parse.quote_from_bytes(data)

def encode_html(data: bytes, salt: bool = False) -> str:
    if salt:
        data = apply_salt(data)
    return html.escape(data.decode(errors="ignore"))

def encode_ascii(data: bytes, salt: bool = False) -> str:
    if salt:
        data = apply_salt(data)
    return ''.join([chr(b) if 32 <= b < 127 else '?' for b in data])

def encode_utf8(data: bytes, salt: bool = False) -> str:
    if salt:
        data = apply_salt(data)
    return data.decode('utf-8', errors='ignore')

def encode_binary(data: bytes, salt: bool = False) -> str:
    if salt:
        data = apply_salt(data)
    return ' '.join(format(b, '08b') for b in data)

MORSE_CODE_DICT = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',   'E': '.',
    'F': '..-.',  'G': '--.',   'H': '....',  'I': '..',    'J': '.---',
    'K': '-.-',   'L': '.-..',  'M': '--',    'N': '-.',    'O': '---',
    'P': '.--.',  'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',  'Y': '-.--',
    'Z': '--..',  '0': '-----', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', ' ': '/'
}

def encode_morse(data: bytes, salt: bool = False) -> str:
    if salt:
        data = apply_salt(data)
    return ' '.join(MORSE_CODE_DICT.get(chr(b).upper(), '?') for b in data)

# =========================
#   Decoding Methods
# =========================

def decode_base64(data: str, salted: bool = False) -> bytes:
    raw = b64decode(data)
    return remove_salt(raw) if salted else raw

def decode_url(data: str, salted: bool = False) -> bytes:
    raw = urllib.parse.unquote_to_bytes(data)
    return remove_salt(raw) if salted else raw

def decode_html(data: str, salted: bool = False) -> bytes:
    raw = html.unescape(data).encode()
    return remove_salt(raw) if salted else raw

def decode_ascii(data: str, salted: bool = False) -> bytes:
    raw = bytes([ord(c) if 32 <= ord(c) < 127 else 63 for c in data])
    return remove_salt(raw) if salted else raw

def decode_utf8(data: str, salted: bool = False) -> bytes:
    raw = data.encode('utf-8')
    return remove_salt(raw) if salted else raw

def decode_binary(data: str, salted: bool = False) -> bytes:
    raw = bytes([int(b, 2) for b in data.strip().split()])
    return remove_salt(raw) if salted else raw

REVERSE_MORSE_CODE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}

def decode_morse(data: str, salted: bool = False) -> bytes:
    text = ''.join(REVERSE_MORSE_CODE_DICT.get(code, '?') for code in data.strip().split())
    raw = text.encode()
    return remove_salt(raw) if salted else raw

# =========================
#   Dispatch Tables
# =========================

encode_dispatch = {
    "base64": encode_base64,
    "url": encode_url,
    "html": encode_html,
    "ascii": encode_ascii,
    "utf-8": encode_utf8,
    "binary": encode_binary,
    "morse": encode_morse,
}

decode_dispatch = {
    "base64": decode_base64,
    "url": decode_url,
    "html": decode_html,
    "ascii": decode_ascii,
    "utf-8": decode_utf8,
    "binary": decode_binary,
    "morse": decode_morse,
}

# =========================
#   File Encode/Decode
# =========================

def encode_file(input_path: str, output_path: str, encoding: str = "base64", salted: bool = False) -> str:
    data = read_file(input_path)
    func = encode_dispatch.get(encoding.lower())
    if not func:
        raise ValueError(f"Unsupported encoding: {encoding}")
    encoded = func(data, salt=salted)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(encoded)
    return output_path

def decode_file(input_path: str, output_path: str, encoding: str = "base64", salted: bool = False) -> str:
    with open(input_path, "r", encoding="utf-8") as f:
        encoded = f.read()
    func = decode_dispatch.get(encoding.lower())
    if not func:
        raise ValueError(f"Unsupported encoding: {encoding}")
    decoded = func(encoded, salted=salted)
    write_file(output_path, decoded)
    return output_path

# =========================
#   String Encode/Decode
# =========================

def encode_string(text: str, encoding: str = "base64", salt: bool = False) -> str:
    data = text.encode("utf-8")
    func = encode_dispatch.get(encoding.lower())
    if not func:
        raise ValueError(f"Unsupported encoding: {encoding}")
    return func(data, salt=salt)

def decode_string(text: str, encoding: str = "base64", salted: bool = False) -> str:
    func = decode_dispatch.get(encoding.lower())
    if not func:
        raise ValueError(f"Unsupported encoding: {encoding}")
    raw = func(text, salted=salted)
    return raw.decode("utf-8", errors="ignore")
