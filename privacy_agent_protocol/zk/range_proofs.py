import secrets
from dataclasses import dataclass
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from privacy_agent_protocol.crypto.commitment import PedersenCommitment
from privacy_agent_protocol.zk.proofs import ZKOpeningProver

@dataclass
class BitProof:
    bit_commitment: Point
    proof_zero: tuple
    proof_one: tuple

class ZKRangeProver:
    def __init__(self, bit_length: int = 16):
        self.bit_length = bit_length
        self.prover = ZKOpeningProver()
        self.commitment_engine = PedersenCommitment()

    def prove_range(self, value: int, blinding_factor: int) -> tuple[list[BitProof], list[int]]:
        if value < 0 or value >= (1 << self.bit_length):
            raise ValueError(f"Value {value} out of range [0, 2^{self.bit_length} - 1]")

        bit_blindings = []
        accumulated_r_sum = 0

        # 1. Choose random blinding factors for bits 0 .. n-2
        for i in range(self.bit_length - 1):
            r_i = secrets.randbelow(secp256k1.q - 1) + 1
            bit_blindings.append(r_i)
            accumulated_r_sum = (accumulated_r_sum + (1 << i) * r_i) % secp256k1.q

        # 2. Derive r_{n-1} so that sum(2^i * r_i) = blinding_factor (mod q)
        two_pow_last = (1 << (self.bit_length - 1)) % secp256k1.q
        two_pow_last_inv = pow(two_pow_last, secp256k1.q - 2, secp256k1.q)
        r_last = ((blinding_factor - accumulated_r_sum) * two_pow_last_inv) % secp256k1.q
        bit_blindings.append(r_last)

        # 3. Construct bit commitments and proofs
        bit_proofs = []
        for i in range(self.bit_length):
            bit = (value >> i) & 1
            r_i = bit_blindings[i]

            C_i = self.commitment_engine.commit(bit, r_i)
            proof = self.prover.prove_knowledge(C_i, bit, r_i)
            
            bit_proof = BitProof(
                bit_commitment=C_i,
                proof_zero=(proof.R, proof.s_v, proof.s_r),
                proof_one=(proof.R, proof.s_v, proof.s_r)
            )
            bit_proofs.append(bit_proof)

        return bit_proofs, bit_blindings

    def verify_range(self, total_commitment: Point, bit_proofs: list[BitProof]) -> bool:
        if len(bit_proofs) != self.bit_length:
            return False

        reconstructed_commitment = None

        for i, bp in enumerate(bit_proofs):
            if bp.bit_commitment is None:
                return False

            scaled_commitment = (1 << i) * bp.bit_commitment
            if reconstructed_commitment is None:
                reconstructed_commitment = scaled_commitment
            else:
                reconstructed_commitment = reconstructed_commitment + scaled_commitment

        return reconstructed_commitment == total_commitment
