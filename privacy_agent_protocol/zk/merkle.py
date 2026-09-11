import hashlib
from fastecdsa.point import Point

class MerkleTree:
    def __init__(self, leaves_pk: list[Point]):
        self.leaves_bytes = [self._hash_point(pk) for pk in leaves_pk]
        self.tree = self._build_tree(self.leaves_bytes)

    @staticmethod
    def _hash_point(point: Point) -> bytes:
        data = point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")
        return hashlib.sha256(data).digest()

    @staticmethod
    def _hash_pair(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(left + right).digest()

    def _build_tree(self, leaves: list[bytes]) -> list[list[bytes]]:
        tree = [leaves]
        while len(tree[-1]) > 1:
            current_level = tree[-1]
            next_level = []
            
            # Duplicate last element if odd number of leaves
            if len(current_level) % 2 == 1:
                current_level = current_level + [current_level[-1]]

            for i in range(0, len(current_level), 2):
                next_level.append(self._hash_pair(current_level[i], current_level[i+1]))
            
            tree.append(next_level)
        return tree

    def get_root(self) -> bytes:
        return self.tree[-1][0] if self.tree else b""

    def get_membership_proof(self, point: Point) -> tuple[int, list[tuple[bytes, str]]]:
        """Generates a Merkle membership path for a given public key."""
        target_leaf = self._hash_point(point)
        if target_leaf not in self.leaves_bytes:
            raise ValueError("Public key not present in authorization set.")

        index = self.leaves_bytes.index(target_leaf)
        proof = []

        for level in self.tree[:-1]:
            # Handle odd length levels
            current_level = level + [level[-1]] if len(level) % 2 == 1 else level
            
            is_right = index % 2 == 1
            sibling_index = index - 1 if is_right else index + 1
            sibling = current_level[sibling_index]
            
            proof.append((sibling, "left" if is_right else "right"))
            index = index // 2

        return index, proof

    @staticmethod
    def verify_membership_proof(leaf_pk: Point, proof: list[tuple[bytes, str]], expected_root: bytes) -> bool:
        """Verifies that a public key belongs to the authorized cluster root without exposing identity."""
        current_hash = MerkleTree._hash_point(leaf_pk)

        for sibling_hash, direction in proof:
            if direction == "left":
                current_hash = MerkleTree._hash_pair(sibling_hash, current_hash)
            else:
                current_hash = MerkleTree._hash_pair(current_hash, sibling_hash)

        return current_hash == expected_root
