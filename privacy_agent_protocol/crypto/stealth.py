import hashlib
import secrets
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

class StealthAddress:
    @staticmethod
    def generate_stealth_address(recipient_pk: Point) -> tuple[Point, Point, int]:
        """
        Derives a single-use stealth public key for recipient identity hiding.
        Returns: (stealth_pk, ephemeral_pk, ephemeral_sk)
        """
        r = secrets.randbelow(secp256k1.q - 1) + 1
        R = r * secp256k1.G  # Ephemeral public key
        
        shared_point = r * recipient_pk
        c_hash = hashlib.sha256(shared_point.x.to_bytes(32, "big")).digest()
        c_scalar = int.from_bytes(c_hash, "big") % secp256k1.q
        
        stealth_pk = recipient_pk + (c_scalar * secp256k1.G)
        return stealth_pk, R, r

    @staticmethod
    def check_and_derive_private_key(
        recipient_sk: int, 
        recipient_pk: Point, 
        ephemeral_pk: Point, 
        target_stealth_pk: Point
    ) -> tuple[bool, int | None]:
        """
        Checks if a stealth address belongs to this agent and computes the single-use private key.
        """
        shared_point = recipient_sk * ephemeral_pk
        c_hash = hashlib.sha256(shared_point.x.to_bytes(32, "big")).digest()
        c_scalar = int.from_bytes(c_hash, "big") % secp256k1.q
        
        expected_stealth_pk = recipient_pk + (c_scalar * secp256k1.G)
        
        if expected_stealth_pk == target_stealth_pk:
            stealth_sk = (recipient_sk + c_scalar) % secp256k1.q
            return True, stealth_sk
        return False, None
