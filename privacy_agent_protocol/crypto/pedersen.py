import secrets
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

class PedersenCommitment:
    def __init__(self):
        self.curve = secp256k1
        self.G = secp256k1.G
        self.H = Point(
            0xa865c26489d5847b4dd984006c76ba6d88af6d8f5cef771eb4119c9a9ea330a,
            0x1782576f59e897138c02db38b645dac8c017fec3d8702fb4663e647bf15ada54,
            curve=secp256k1
        )

    def commit(self, value: int, blinding_factor: int | None = None) -> tuple[Point, int] | Point:
        """Generates a commitment C = value*G + blinding_factor*H.
        
        If blinding_factor is None, generates a secure random blinding factor and returns (commitment, blinding_factor).
        If blinding_factor is provided, returns commitment.
        """
        if blinding_factor is None:
            r = secrets.randbelow(self.curve.q - 1) + 1
            c = (value * self.G) + (r * self.H)
            return c, r
        return (value * self.G) + (blinding_factor * self.H)

    def verify(self, commitment: Point, value: int, blinding_factor: int) -> bool:
        """Verifies if C == value*G + blinding_factor*H."""
        expected_commitment = (value * self.G) + (blinding_factor * self.H)
        return commitment == expected_commitment

    def add_commitments(self, c1: Point, c2: Point) -> Point:
        """Homomorphically adds two commitments: C_sum = C1 + C2."""
        return c1 + c2

    def combine_blinding_factors(self, r1: int, r2: int) -> int:
        """Combines two blinding factors: r_sum = (r1 + r2) mod q."""
        return (r1 + r2) % self.curve.q

    def subtract_commitments(self, c1: Point, c2: Point) -> Point:
        """Homomorphically subtracts two commitments: C_diff = C1 - C2."""
        return c1 - c2

    def subtract_blinding_factors(self, r1: int, r2: int) -> int:
        """Subtracts blinding factors: r_diff = (r1 - r2) mod q."""
        return (r1 - r2) % self.curve.q
