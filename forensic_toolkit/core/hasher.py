"""
Hashing Module
===============
Generates cryptographic hashes for file integrity verification.
Supports MD5, SHA-1, SHA-256, SHA-512.
"""

import hashlib
import os


HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
CHUNK_SIZE = 8192


def compute_hashes(file_path):
    """
    Compute multiple hash digests for a file.

    Returns a dict: {"md5": "...", "sha1": "...", "sha256": "...", "sha512": "..."}
    """
    hashers = {alg: hashlib.new(alg) for alg in HASH_ALGORITHMS}

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)

    return {alg: h.hexdigest() for alg, h in hashers.items()}


def compute_partial_hashes(file_path, size=4096):
    """
    Compute hashes of the first and last N bytes of a file.
    Useful for quick comparison before doing a full hash.
    """
    file_size = os.path.getsize(file_path)
    result = {}

    with open(file_path, "rb") as f:
        # First N bytes
        head = f.read(min(size, file_size))
        result["head_sha256"] = hashlib.sha256(head).hexdigest()

        # Last N bytes
        if file_size > size:
            f.seek(-size, 2)
            tail = f.read(size)
        else:
            tail = head
        result["tail_sha256"] = hashlib.sha256(tail).hexdigest()

    return result
