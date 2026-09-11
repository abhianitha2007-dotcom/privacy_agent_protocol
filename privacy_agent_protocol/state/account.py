from fastecdsa.point import Point
from privacy_agent_protocol.crypto.pedersen import PedersenCommitment

# 64-bit integer ceiling to prevent field wrapping overflow
MAX_TRANSFER_AMOUNT = (1 << 64) - 1

class PrivateAccount:
    def __init__(self, initial_balance: int = 0):
        if not (0 <= initial_balance <= MAX_TRANSFER_AMOUNT):
            raise ValueError(f"Initial balance out of valid range [0, 2^64 - 1]")
        self.pedersen = PedersenCommitment()
        self.commitment, self._blinding_factor = self.pedersen.commit(initial_balance)

    def deposit(self, amount: int) -> Point:
        """Homomorphically deposits an amount after verifying range bounds."""
        if not (0 <= amount <= MAX_TRANSFER_AMOUNT):
            raise ValueError(f"Deposit amount {amount} violates range bounds [0, 2^64 - 1]")
            
        deposit_commitment, deposit_r = self.pedersen.commit(amount)
        self.commitment = self.pedersen.add_commitments(self.commitment, deposit_commitment)
        self._blinding_factor = self.pedersen.combine_blinding_factors(self._blinding_factor, deposit_r)
        return deposit_commitment

    def withdraw(self, amount: int) -> tuple[Point, int]:
        """Deducts an amount homomorphically after confirming non-negativity."""
        if not (0 <= amount <= MAX_TRANSFER_AMOUNT):
            raise ValueError(f"Withdrawal amount {amount} violates range bounds [0, 2^64 - 1]")
            
        transfer_commitment, transfer_r = self.pedersen.commit(amount)
        self.commitment = self.pedersen.subtract_commitments(self.commitment, transfer_commitment)
        self._blinding_factor = self.pedersen.subtract_blinding_factors(self._blinding_factor, transfer_r)
        return transfer_commitment, transfer_r

    def receive_transfer(self, transfer_commitment: Point, transfer_r: int):
        self.commitment = self.pedersen.add_commitments(self.commitment, transfer_commitment)
        self._blinding_factor = self.pedersen.combine_blinding_factors(self._blinding_factor, transfer_r)

    def verify_balance(self, expected_balance: int) -> bool:
        return self.pedersen.verify(self.commitment, expected_balance, self._blinding_factor)
