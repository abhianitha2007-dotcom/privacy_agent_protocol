import asyncio
from privacy_agent_protocol import AsyncPeerNode, PrivacyAgent, MerkleTree

async def main():
    print("==========================================================")
    print("  TOPIC 9: PRIVACY-PRESERVING MULTI-AGENT PROTOCOL DEMO  ")
    print("==========================================================\n")

    # 1. Initialize nodes
    alice = PrivacyAgent("Alice", initial_balance=3000)
    bob = PrivacyAgent("Bob", initial_balance=500)
    eve = PrivacyAgent("Eve", initial_balance=0)

    # 2. Build Merkle tree of authorized network identities
    authorized_cluster_pks = [alice.pk, bob.pk]
    merkle_tree = MerkleTree(authorized_cluster_pks)
    cluster_root = merkle_tree.get_root()

    alice.set_cluster_merkle_root(cluster_root)
    bob.set_cluster_merkle_root(cluster_root)

    print("--- 1. Cluster Authorization Setup ---")
    print(f"Merkle Root: {cluster_root.hex()[:16]}...")

    _, alice_proof = merkle_tree.get_membership_proof(alice.pk)
    alice_authorized = bob.verify_agent_authorization(alice.pk, alice_proof)
    print(f"Alice authorized in cluster? {alice_authorized}")

    eve_authorized = False
    try:
        _, eve_proof = merkle_tree.get_membership_proof(eve.pk)
        eve_authorized = bob.verify_agent_authorization(eve.pk, eve_proof)
    except ValueError:
        pass
    print(f"Eve authorized in cluster? {eve_authorized}\n")

    # 3. Start TCP servers for both Alice (9001) and Bob (9002)
    alice.set_endpoint("127.0.0.1", 9001)
    async def alice_handler(payload: bytes):
        res = alice.handle_incoming_payload(payload)
        print(f"[Alice Node] Processed message '{res['type']}': {res}")

    alice_node = AsyncPeerNode("127.0.0.1", 9001, alice_handler)
    await alice_node.start()

    bob.set_endpoint("127.0.0.1", 9002)
    async def bob_handler(payload: bytes):
        res = bob.handle_incoming_payload(payload)
        print(f"[Bob Node] Processed message '{res['type']}': {res}")

    bob_node = AsyncPeerNode("127.0.0.1", 9002, bob_handler)
    await bob_node.start()

    # 4. Mutual Handshake
    await alice.connect_to_peer("127.0.0.1", 9002, "127.0.0.1", 9001)
    await asyncio.sleep(0.05)

    print("\n--- 2. Stealth Confidential Settlement (Forward Secret) ---")
    transfer_payload, stealth_pk, ephemeral_stealth_pk = alice.prepare_stealth_transfer(
        recipient_pk=bob.pk, 
        amount=700
    )

    x_str, y_str = str(stealth_pk.x), str(stealth_pk.y)
    print(f"Destination Stealth Address: Point({x_str[:10]}..., {y_str[:10]}...)")

    settlement_success = bob.process_stealth_transfer(
        transfer_payload, ephemeral_stealth_pk, stealth_pk
    )
    print(f"Bob successfully scanned and settled stealth transfer? {settlement_success}")

    eve_settlement = eve.process_stealth_transfer(
        transfer_payload, ephemeral_stealth_pk, stealth_pk
    )
    print(f"Eve able to claim Bob's stealth transfer? {eve_settlement}\n")

    print("--- 3. Final Cryptographic State Verification ---")
    print(f"Alice's balance equals 2300? {alice.account.verify_balance(2300)}")
    print(f"Bob's balance equals 1200? {bob.account.verify_balance(1200)}")

    await alice_node.stop()
    await bob_node.stop()

if __name__ == "__main__":
    asyncio.run(main())
