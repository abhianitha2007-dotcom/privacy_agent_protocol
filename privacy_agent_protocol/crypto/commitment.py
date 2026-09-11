"""Homomorphic Pedersen Commitments module.

Re-exports canonical PedersenCommitment from crypto.pedersen to ensure consistent
use of the verified Nothing-Up-My-Sleeve (NUMS) generator point H on secp256k1.
"""
from privacy_agent_protocol.crypto.pedersen import PedersenCommitment

__all__ = ["PedersenCommitment"]

