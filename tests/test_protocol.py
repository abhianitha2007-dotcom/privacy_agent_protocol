import pytest
import asyncio
from privacy_agent_protocol import PrivacyAgent, AsyncPeerNode, MerkleTree, StealthAddress
from privacy_agent_protocol.crypto.ecdh import ECDH
from privacy_agent_protocol.crypto.commitment import PedersenCommitment
from privacy_agent_protocol.zk.range_proofs import ZKRangeProver

def test_ecdh_ephemeral_key_exchange():
    sk_a, pk_a = ECDH.generate_keypair()
    sk_b, pk_b = ECDH.generate_keypair()

    shared_a = ECDH.derive_shared_key(sk_a, pk_b)
    shared_b = ECDH.derive_shared_key(sk_b, pk_a)
    assert shared_a == shared_b

    secret_scalar = 987654321
    encrypted = ECDH.encrypt_scalar(secret_scalar, shared_a)
    decrypted = ECDH.decrypt_scalar(encrypted, shared_b)
    assert decrypted == secret_scalar

def test_stealth_address_unlinkability():
    bob_sk, bob_pk = ECDH.generate_keypair()

    stealth_pk, ephemeral_pk, _ = StealthAddress.generate_stealth_address(bob_pk)
    
    is_owner, stealth_sk = StealthAddress.check_and_derive_private_key(
        bob_sk, bob_pk, ephemeral_pk, stealth_pk
    )
    assert is_owner is True
    assert stealth_sk is not None

def test_merkle_authorization():
    _, pk_1 = ECDH.generate_keypair()
    _, pk_2 = ECDH.generate_keypair()
    _, rogue_pk = ECDH.generate_keypair()

    tree = MerkleTree([pk_1, pk_2])
    root = tree.get_root()

    _, proof_1 = tree.get_membership_proof(pk_1)
    assert MerkleTree.verify_membership_proof(pk_1, proof_1, root) is True

    with pytest.raises(ValueError):
        tree.get_membership_proof(rogue_pk)

def test_zk_range_proof():
    prover = ZKRangeProver(bit_length=16)
    commitment_engine = PedersenCommitment()
    value = 500
    r = 123456789
    
    C = commitment_engine.commit(value, r)
    bit_proofs, _ = prover.prove_range(value, r)
    
    assert prover.verify_range(C, bit_proofs) is True

@pytest.mark.asyncio
async def test_end_to_end_agent_mesh():
    alice = PrivacyAgent("Alice", 1000)
    bob = PrivacyAgent("Bob", 200)

    alice.set_endpoint("127.0.0.1", 9101)
    bob.set_endpoint("127.0.0.1", 9102)

    async def alice_handler(payload: bytes):
        alice.handle_incoming_payload(payload)

    async def bob_handler(payload: bytes):
        bob.handle_incoming_payload(payload)

    a_node = AsyncPeerNode("127.0.0.1", 9101, alice_handler)
    b_node = AsyncPeerNode("127.0.0.1", 9102, bob_handler)
    
    await a_node.start()
    await b_node.start()

    await alice.connect_to_peer("127.0.0.1", 9102, "127.0.0.1", 9101)
    await asyncio.sleep(0.05)

    assert "Bob" in alice.cluster.peers
    assert "Alice" in bob.cluster.peers

    await a_node.stop()
    await b_node.stop()
