import hashlib
import secrets
from fastecdsa.point import Point
from privacy_agent_protocol.crypto.pedersen import PedersenCommitment

class OpeningProof:
    """Dataclass holding a non-interactive zero-knowledge opening proof."""
    def __init__(self, R: Point, s_v: int, s_r: int):
        self.R = R
        self.s_v = s_v
        self.s_r = s_r

class ZKOpeningProver:
    def __init__(self):
        self.pedersen = PedersenCommitment()

    def _compute_challenge(self, C: Point, R: Point) -> int:
        """Derives a deterministic challenge 'e' using the Fiat-Shamir transform."""
        G, H = self.pedersen.G, self.pedersen.H
        raw_data = f"{G.x}:{G.y}:{H.x}:{H.y}:{C.x}:{C.y}:{R.x}:{R.y}".encode()
        hash_digest = hashlib.sha256(raw_data).digest()
        return int.from_bytes(hash_digest, 'big') % self.pedersen.curve.q

    def prove_knowledge(self, C: Point, value: int, blinding_factor: int) -> OpeningProof:
        """Generates a NIZK proof of knowledge for commitment C = value*G + blinding_factor*H."""
        q = self.pedersen.curve.q
        
        # 1. Random nonces
        k_v = secrets.randbelow(q)
        k_r = secrets.randbelow(q)
        
        # 2. Announcement point R = k_v*G + k_r*H
        R = (k_v * self.pedersen.G) + (k_r * self.pedersen.H)
        
        # 3. Challenge via Hash
        e = self._compute_challenge(C, R)
        
        # 4. Responses
        s_v = (k_v + e * value) % q
        s_r = (k_r + e * blinding_factor) % q
        
        return OpeningProof(R, s_v, s_r)

    def verify_proof(self, C: Point, proof: OpeningProof) -> bool:
        """Verifies proof equation: s_v*G + s_r*H == R + e*C."""
        q = self.pedersen.curve.q
        e = self._compute_challenge(C, proof.R)
        
        # Left side: s_v*G + s_r*H
        lhs = (proof.s_v * self.pedersen.G) + (proof.s_r * self.pedersen.H)
        
        # Right side: R + e*C
        rhs = proof.R + (e * C)
        
        return lhs == rhs
