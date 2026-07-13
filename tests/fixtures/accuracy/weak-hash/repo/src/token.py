import hashlib


def sign(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()
