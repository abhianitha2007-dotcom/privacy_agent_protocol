import hashlib
import secrets
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

class ECDH:
    @staticmethod
    def generate_keypair() -> tuple[int, Point]:
        sk = secrets.randbelow(secp256k1.q - 1) + 1
        pk = sk * secp256k1.G
        return sk, pk

    @staticmethod
    def generate_ephemeral_keypair() -> tuple[int, Point]:
        """Generates a single-use disposable keypair (e_A, E_A) for forward secrecy."""
        return ECDH.generate_keypair()

    @staticmethod
    def derive_shared_key(private_key: int, public_point: Point) -> bytes:
        """Derives a symmetric secret key using point multiplication."""
        shared_point = private_key * public_point
        return hashlib.sha256(shared_point.x.to_bytes(32, byteorder="big")).digest()

    @staticmethod
    def encrypt_scalar(scalar: int, key: bytes) -> bytes:
        scalar_bytes = scalar.to_bytes(32, byteorder="big")
        return bytes(a ^ b for a, b in zip(scalar_bytes, key[:32]))

    @staticmethod
    def decrypt_scalar(encrypted_bytes: bytes, key: bytes) -> int:
        raw_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, key[:32]))
        return int.from_bytes(raw_bytes, byteorder="big")
