"""Opaque replica creation for the non-trusted storage tier."""
import base64
import hashlib
import json

from cryptography.fernet import Fernet

from .config import JWT_SECRET


def _cipher():
    key_material = hashlib.sha256((JWT_SECRET + ':non-trusted-replica').encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_material))


def encrypt_replica(record: dict) -> tuple[str, str]:
    plaintext = json.dumps(record, separators=(',', ':'), sort_keys=True).encode()
    return _cipher().encrypt(plaintext).decode(), hashlib.sha256(plaintext).hexdigest()
