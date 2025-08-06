import hashlib
import hmac

# ========== Hasher Implementations ==========

def md5_hash(text: str, salt: str = "") -> str:
    return hashlib.md5((salt + text).encode()).hexdigest()

def sha1_hash(text: str, salt: str = "") -> str:
    return hashlib.sha1((salt + text).encode()).hexdigest()

def sha256_hash(text: str, salt: str = "") -> str:
    return hashlib.sha256((salt + text).encode()).hexdigest()

def sha512_hash(text: str, salt: str = "") -> str:
    return hashlib.sha512((salt + text).encode()).hexdigest()

def blake2b_hash(text: str, salt: str = "") -> str:
    return hashlib.blake2b((salt + text).encode()).hexdigest()

def blake2s_hash(text: str, salt: str = "") -> str:
    return hashlib.blake2s((salt + text).encode()).hexdigest()

def hmac_sha256_hash(text: str, salt: str = "") -> str:
    return hmac.new(salt.encode(), text.encode(), hashlib.sha256).hexdigest()

# ========== Mapping ==========

HASHERS = {
    "md5": md5_hash,
    "sha1": sha1_hash,
    "sha256": sha256_hash,
    "sha512": sha512_hash,
    "blake2b": blake2b_hash,
    "blake2s": blake2s_hash,
    "hmac": hmac_sha256_hash,
}

# ========== Public API ==========

def hash_data(text: str, algorithm: str = "sha256", salt: str = "") -> str:
    algo = algorithm.lower()
    if algo not in HASHERS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return HASHERS[algo](text, salt)

def verify_hash(text: str, hashed: str, algorithm: str = "sha256", salt: str = "") -> bool:
    return hash_data(text, algorithm, salt) == hashed
