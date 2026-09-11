import hashlib
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

class PedersenCommitment:
    def __init__(self):
        self.G = secp256k1.G
        # Derive independent generator H via nothing-up-my-sleeve hash of G
        g_bytes = self.G.x.to_bytes(32, "big") + self.G.y.to_bytes(32, "big")
        h_scalar = int.from_bytes(hashlib.sha256(g_bytes).digest(), "big") % secp256k1.q
        self.H = h_scalar * self.G

    def commit(self, value: int, blinding_factor: int) -> Point:
        """Computes homomorphic Pedersen Commitment: C = v * G + r * H"""
        return (value * self.G) + (blinding_factor * self.H)
