import hashlib
import secrets
from dataclasses import dataclass
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from privacy_agent_protocol.crypto.pedersen import PedersenCommitment

@dataclass
class BitProof:
    bit_commitment: Point
    R0: Point
    R1: Point
    e0: int
    e1: int
    s0: int
    s1: int

class ZKRangeProver:
    def __init__(self, bit_length: int = 16):
        self.bit_length = bit_length
        self.commitment_engine = PedersenCommitment()

    def _hash_transcript(self, C: Point, R0: Point, R1: Point) -> int:
        G, H = self.commitment_engine.G, self.commitment_engine.H
        raw = f"{G.x}:{G.y}:{H.x}:{H.y}:{C.x}:{C.y}:{R0.x}:{R0.y}:{R1.x}:{R1.y}".encode()
        return int.from_bytes(hashlib.sha256(raw).digest(), "big") % self.commitment_engine.curve.q

    def prove_bit(self, bit: int, r: int) -> BitProof:
        """Constructs a Cramer-Damgård-Schoenmakers (CDS) 1-of-2 disjunctive ZK proof for bit in {0, 1}."""
        if bit not in (0, 1):
            raise ValueError("Bit must be 0 or 1")
        G = self.commitment_engine.G
        H = self.commitment_engine.H
        q = self.commitment_engine.curve.q
        C = (bit * G) + (r * H)
        P0 = C
        P1 = C - G

        if bit == 0:
            w0 = secrets.randbelow(q - 1) + 1
            R0 = w0 * H
            e1 = secrets.randbelow(q - 1) + 1
            s1 = secrets.randbelow(q - 1) + 1
            R1 = (s1 * H) - (e1 * P1)

            e = self._hash_transcript(C, R0, R1)
            e0 = (e - e1) % q
            s0 = (w0 + e0 * r) % q
        else:
            e0 = secrets.randbelow(q - 1) + 1
            s0 = secrets.randbelow(q - 1) + 1
            R0 = (s0 * H) - (e0 * P0)
            w1 = secrets.randbelow(q - 1) + 1
            R1 = w1 * H

            e = self._hash_transcript(C, R0, R1)
            e1 = (e - e0) % q
            s1 = (w1 + e1 * r) % q

        return BitProof(
            bit_commitment=C,
            R0=R0,
            R1=R1,
            e0=e0,
            e1=e1,
            s0=s0,
            s1=s1,
        )

    def verify_bit(self, proof: BitProof) -> bool:
        """Verifies that a bit proof satisfies the CDS 1-of-2 equations and Fiat-Shamir challenge."""
        G = self.commitment_engine.G
        H = self.commitment_engine.H
        q = self.commitment_engine.curve.q
        C = proof.bit_commitment
        P0 = C
        P1 = C - G

        e = self._hash_transcript(C, proof.R0, proof.R1)
        if (proof.e0 + proof.e1) % q != e:
            return False

        lhs0 = proof.s0 * H
        rhs0 = proof.R0 + (proof.e0 * P0)
        if lhs0 != rhs0:
            return False

        lhs1 = proof.s1 * H
        rhs1 = proof.R1 + (proof.e1 * P1)
        if lhs1 != rhs1:
            return False

        return True

    def prove_range(self, value: int, blinding_factor: int) -> tuple[list[BitProof], list[int]]:
        if value < 0 or value >= (1 << self.bit_length):
            raise ValueError(f"Value {value} out of range [0, 2^{self.bit_length} - 1]")

        bit_blindings = []
        accumulated_r_sum = 0
        q = self.commitment_engine.curve.q

        # 1. Choose random blinding factors for bits 0 .. n-2
        for i in range(self.bit_length - 1):
            r_i = secrets.randbelow(q - 1) + 1
            bit_blindings.append(r_i)
            accumulated_r_sum = (accumulated_r_sum + (1 << i) * r_i) % q

        # 2. Derive r_{n-1} so that sum(2^i * r_i) = blinding_factor (mod q)
        two_pow_last = (1 << (self.bit_length - 1)) % q
        two_pow_last_inv = pow(two_pow_last, q - 2, q)
        r_last = ((blinding_factor - accumulated_r_sum) * two_pow_last_inv) % q
        bit_blindings.append(r_last)

        # 3. Construct bit commitments and CDS 1-of-2 proofs
        bit_proofs = []
        for i in range(self.bit_length):
            bit = (value >> i) & 1
            r_i = bit_blindings[i]
            bit_proof = self.prove_bit(bit, r_i)
            bit_proofs.append(bit_proof)

        return bit_proofs, bit_blindings

    def verify_range(self, total_commitment: Point, bit_proofs: list[BitProof]) -> bool:
        if len(bit_proofs) != self.bit_length:
            return False

        reconstructed_commitment = None

        for i, bp in enumerate(bit_proofs):
            if bp.bit_commitment is None:
                return False

            # Verify individual CDS bit proof (guarantees bit in {0, 1})
            if not self.verify_bit(bp):
                return False

            scaled_commitment = (1 << i) * bp.bit_commitment
            if reconstructed_commitment is None:
                reconstructed_commitment = scaled_commitment
            else:
                reconstructed_commitment = reconstructed_commitment + scaled_commitment

        return reconstructed_commitment == total_commitment

