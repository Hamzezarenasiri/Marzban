import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def x25519_public_from_private(private_key_base64: str) -> str:
    """
    Compute the X25519 public key from a base64-encoded private key.
    Used for REALITY protocol where we need to derive public key from private key.
    """
    try:
        private_key_bytes = base64.urlsafe_b64decode(private_key_base64 + '==')
        private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key_bytes = private_key.public_key().public_bytes_raw()
        public_key_base64 = base64.urlsafe_b64encode(public_key_bytes).decode().rstrip('=')
        return public_key_base64
    except Exception:
        return None
