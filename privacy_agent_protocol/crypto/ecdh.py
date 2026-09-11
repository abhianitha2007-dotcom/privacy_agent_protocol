import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
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
        """Derives a symmetric secret key using point multiplication and HKDF."""
        shared_point = private_key * public_point
        raw_point = shared_point.x.to_bytes(32, byteorder="big") + shared_point.y.to_bytes(32, byteorder="big")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"privacy-agent-protocol-ecdh-v1",
        )
        return hkdf.derive(raw_point)

    @staticmethod
    def encrypt_scalar(scalar: int, key: bytes) -> bytes:
        """Encrypts a 256-bit scalar using AES-256-GCM authenticated encryption.
        
        Returns: 12-byte nonce concatenated with AES-GCM ciphertext and 16-byte authentication tag.
        """
        scalar_bytes = scalar.to_bytes(32, byteorder="big")
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, scalar_bytes, None)
        return nonce + ciphertext

    @staticmethod
    def decrypt_scalar(encrypted_bytes: bytes, key: bytes) -> int:
        """Decrypts and verifies an AES-256-GCM encrypted scalar.
        
        Raises cryptography.exceptions.InvalidTag if ciphertext was tampered with.
        """
        if len(encrypted_bytes) < 28:
            raise ValueError("Invalid ciphertext length: must be at least nonce (12) + tag (16)")
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        aesgcm = AESGCM(key)
        raw_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return int.from_bytes(raw_bytes, byteorder="big")

