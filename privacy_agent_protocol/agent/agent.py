import asyncio
import hashlib
from fastecdsa.point import Point
from privacy_agent_protocol.crypto.ecdh import ECDH
from privacy_agent_protocol.crypto.stealth import StealthAddress
from privacy_agent_protocol.network.cluster import ClusterManager
from privacy_agent_protocol.network.node import AsyncPeerNode
from privacy_agent_protocol.network.serializer import NetworkSerializer
from privacy_agent_protocol.state.account import PrivateAccount
from privacy_agent_protocol.zk.merkle import MerkleTree
from privacy_agent_protocol.zk.proofs import ZKOpeningProver

class PrivacyAgent:
    def __init__(self, name: str, initial_balance: int = 0):
        self.name = name
        self.account = PrivateAccount(initial_balance)
        self.prover = ZKOpeningProver()
        self.sk, self.pk = ECDH.generate_keypair()
        self.seen_tx_hashes = set()
        self.cluster = ClusterManager()
        self.my_host = "127.0.0.1"
        self.my_port = None
        self.cluster_merkle_root: bytes | None = None

    def set_endpoint(self, host: str, port: int):
        self.my_host = host
        self.my_port = port

    def set_cluster_merkle_root(self, root: bytes):
        self.cluster_merkle_root = root

    def deposit(self, amount: int) -> Point:
        return self.account.deposit(amount)

    def register_cluster_peer(self, name: str, host: str, port: int, public_key: Point):
        self.cluster.register_peer(name, host, port, public_key)

    def prepare_handshake_payload(self, host: str, port: int, is_ack: bool = False) -> bytes:
        return NetworkSerializer.serialize_handshake(self.name, host, port, self.pk, is_ack=is_ack)

    async def connect_to_peer(self, target_host: str, target_port: int, my_host: str, my_port: int):
        self.set_endpoint(my_host, my_port)
        payload = self.prepare_handshake_payload(my_host, my_port)
        await AsyncPeerNode.send_payload(target_host, target_port, payload)

    def verify_agent_authorization(self, sender_pk: Point, merkle_proof: list[tuple[bytes, str]]) -> bool:
        """Verifies if a sending node is authorized via the cluster Merkle root."""
        if not self.cluster_merkle_root:
            return True  # If no root enforced, default to open cluster
        return MerkleTree.verify_membership_proof(sender_pk, merkle_proof, self.cluster_merkle_root)

    def prepare_stealth_transfer(self, recipient_pk: Point, amount: int) -> tuple[bytes, Point, Point]:
        """
        Creates a confidential transfer utilizing:
        1. Stealth Address (Identity Hiding)
        2. Ephemeral ECDH key exchange (Forward Secrecy)
        """
        stealth_pk, ephemeral_stealth_pk, _ = StealthAddress.generate_stealth_address(recipient_pk)
        transfer_commitment, transfer_r = self.account.withdraw(amount)
        
        # Disposable ephemeral key pair for key exchange
        e_sk, e_pk = ECDH.generate_ephemeral_keypair()
        ephemeral_shared_key = ECDH.derive_shared_key(e_sk, stealth_pk)
        encrypted_r = ECDH.encrypt_scalar(transfer_r, ephemeral_shared_key)
        
        payload = NetworkSerializer.serialize_transfer(transfer_commitment, encrypted_r, e_pk)
        return payload, stealth_pk, ephemeral_stealth_pk

    def process_stealth_transfer(
        self, 
        payload_bytes: bytes, 
        ephemeral_stealth_pk: Point, 
        stealth_pk: Point
    ) -> bool:
        """Scans and unlocks funds sent to a stealth address if owned by this agent."""
        is_owner, stealth_sk = StealthAddress.check_and_derive_private_key(
            self.sk, self.pk, ephemeral_stealth_pk, stealth_pk
        )
        if not is_owner or stealth_sk is None:
            return False

        tx_hash = hashlib.sha256(payload_bytes).hexdigest()
        if tx_hash in self.seen_tx_hashes:
            print(f"[{self.name}] Replay Attack Blocked!")
            return False

        transfer_commitment, encrypted_r, e_pk, nonce = NetworkSerializer.deserialize_transfer(payload_bytes)
        
        # Derive shared key using single-use stealth private key and ephemeral public key
        ephemeral_shared_key = ECDH.derive_shared_key(stealth_sk, e_pk)
        transfer_r = ECDH.decrypt_scalar(encrypted_r, ephemeral_shared_key)
        
        self.account.receive_transfer(transfer_commitment, transfer_r)
        self.seen_tx_hashes.add(tx_hash)
        return True

    def handle_incoming_payload(self, payload_bytes: bytes) -> dict:
        msg_type = NetworkSerializer.peek_message_type(payload_bytes)

        if msg_type in ("handshake", "handshake_ack"):
            sender_name, host, port, sender_pk = NetworkSerializer.deserialize_handshake(payload_bytes)
            self.register_cluster_peer(sender_name, host, port, sender_pk)

            if msg_type == "handshake" and self.my_port is not None:
                ack_payload = self.prepare_handshake_payload(self.my_host, self.my_port, is_ack=True)
                asyncio.create_task(AsyncPeerNode.send_payload(host, port, ack_payload))

            return {"type": msg_type, "status": "peer_registered", "peer": sender_name}

        elif msg_type == "proof":
            commitment, is_valid = self.verify_peer_payload(payload_bytes)
            return {"type": "proof", "valid": is_valid}

        else:
            return {"type": "unknown", "status": "ignored"}

    def create_state_proof_payload(self, asserted_value: int) -> bytes:
        proof = self.prover.prove_knowledge(
            C=self.account.commitment,
            value=asserted_value,
            blinding_factor=self.account._blinding_factor,
        )
        return NetworkSerializer.serialize_proof(self.account.commitment, proof)

    def verify_peer_payload(self, payload_bytes: bytes) -> tuple[Point, bool]:
        commitment, proof = NetworkSerializer.deserialize_proof(payload_bytes)
        is_valid = self.prover.verify_proof(commitment, proof)
        return commitment, is_valid
