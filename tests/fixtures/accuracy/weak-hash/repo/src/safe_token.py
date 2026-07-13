import hashlib


def sign(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
