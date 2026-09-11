import pytest
import asyncio
from cryptography.exceptions import InvalidTag
from privacy_agent_protocol import (
    PrivacyAgent,
    AsyncPeerNode,
    MerkleTree,
    StealthAddress,
    PedersenCommitment,
    AnonymousRingAuth,
    ZKRangeProver,
)
from privacy_agent_protocol.crypto.ecdh import ECDH

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

def test_ecdh_aead_tampering_detection():
    sk_a, pk_a = ECDH.generate_keypair()
    sk_b, pk_b = ECDH.generate_keypair()
    shared_key = ECDH.derive_shared_key(sk_a, pk_b)

    secret_scalar = 123456789
    encrypted = ECDH.encrypt_scalar(secret_scalar, shared_key)

    # Tamper with ciphertext by flipping one byte
    tampered_bytes = bytearray(encrypted)
    tampered_bytes[-1] ^= 0x01

    with pytest.raises(Exception):
        ECDH.decrypt_scalar(bytes(tampered_bytes), shared_key)

def test_stealth_address_unlinkability():
    bob_sk, bob_pk = ECDH.generate_keypair()
    stealth_pk, ephemeral_pk, _ = StealthAddress.generate_stealth_address(bob_pk)
    
    is_owner, stealth_sk = StealthAddress.check_and_derive_private_key(
        bob_sk, bob_pk, ephemeral_pk, stealth_pk
    )
    assert is_owner is True
    assert stealth_sk is not None

    # Another node cannot claim or derive stealth private key
    eve_sk, eve_pk = ECDH.generate_keypair()
    eve_owner, eve_stealth_sk = StealthAddress.check_and_derive_private_key(
        eve_sk, eve_pk, ephemeral_pk, stealth_pk
    )
    assert eve_owner is False
    assert eve_stealth_sk is None

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

def test_anonymous_ring_authorization():
    sk_1, pk_1 = ECDH.generate_keypair()
    sk_2, pk_2 = ECDH.generate_keypair()
    sk_rogue, pk_rogue = ECDH.generate_keypair()

    ring = [pk_1, pk_2]
    challenge = b"cluster-auth-nonce-42"
    auth = AnonymousRingAuth()

    # Legitimate cluster member signs
    sig = auth.sign(challenge, ring, sk_1)
    assert auth.verify(challenge, ring, sig) is True

    # Rogue member outside ring attempts to sign
    with pytest.raises(ValueError):
        auth.sign(challenge, ring, sk_rogue)

def test_pedersen_commitment_homomorphic_properties():
    ped = PedersenCommitment()
    v1, r1 = 300, 111111111
    v2, r2 = 200, 222222222

    c1 = ped.commit(v1, r1)
    c2 = ped.commit(v2, r2)

    c_sum = ped.add_commitments(c1, c2)
    expected_sum = ped.commit(v1 + v2, ped.combine_blinding_factors(r1, r2))
    assert c_sum == expected_sum

    c_diff = ped.subtract_commitments(c1, c2)
    expected_diff = ped.commit(v1 - v2, ped.subtract_blinding_factors(r1, r2))
    assert c_diff == expected_diff

def test_zk_range_proof():
    prover = ZKRangeProver(bit_length=16)
    ped = PedersenCommitment()
    value = 500
    C, r = ped.commit(value)
    
    bit_proofs, _ = prover.prove_range(value, r)
    assert prover.verify_range(C, bit_proofs) is True

    # Range violation check
    with pytest.raises(ValueError):
        prover.prove_range(-1, r)
    with pytest.raises(ValueError):
        prover.prove_range(1 << 16, r)

    # Tampering with a bit proof fails verification
    tampered_proofs = list(bit_proofs)
    tampered_proofs[0].s0 = (tampered_proofs[0].s0 + 1) % ped.curve.q
    assert prover.verify_range(C, tampered_proofs) is False

@pytest.mark.asyncio
async def test_end_to_end_agent_mesh_and_wire_transfer():
    alice = PrivacyAgent("Alice", 1000)
    bob = PrivacyAgent("Bob", 200)

    alice.set_endpoint("127.0.0.1", 9201)
    bob.set_endpoint("127.0.0.1", 9202)

    async def alice_handler(payload: bytes):
        alice.handle_incoming_payload(payload)

    async def bob_handler(payload: bytes):
        bob.handle_incoming_payload(payload)

    a_node = AsyncPeerNode("127.0.0.1", 9201, alice_handler)
    b_node = AsyncPeerNode("127.0.0.1", 9202, bob_handler)
    
    await a_node.start()
    await b_node.start()

    # Handshake
    await alice.connect_to_peer("127.0.0.1", 9202, "127.0.0.1", 9201)
    await asyncio.sleep(0.05)

    assert "Bob" in alice.cluster.peers
    assert "Alice" in bob.cluster.peers

    # Over-the-wire TCP Stealth Transfer
    send_ok, payload, stealth_pk, ephemeral_stealth_pk = await alice.send_stealth_transfer(
        target_host="127.0.0.1",
        target_port=9202,
        recipient_pk=bob.pk,
        amount=350,
    )
    assert send_ok is True
    await asyncio.sleep(0.05)

    # Verify balances updated over network
    assert alice.account.verify_balance(650) is True
    assert bob.account.verify_balance(550) is True

    # Replay attack rejection over TCP
    resend_ok = await AsyncPeerNode.send_payload("127.0.0.1", 9202, payload)
    assert resend_ok is True
    await asyncio.sleep(0.05)
    # Balance should still be 550, not 900
    assert bob.account.verify_balance(550) is True

    await a_node.stop()
    await b_node.stop()

