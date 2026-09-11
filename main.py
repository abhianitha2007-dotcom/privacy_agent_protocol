import asyncio
from privacy_agent_protocol import AsyncPeerNode, PrivacyAgent, MerkleTree, AnonymousRingAuth, ZKRangeProver

async def main():
    print("==========================================================")
    print("      PRIVACY-PRESERVING MULTI-AGENT PROTOCOL DEMO  ")
    print("==========================================================\n")

    # 1. Initialize nodes
    alice = PrivacyAgent("Alice", initial_balance=3000)
    bob = PrivacyAgent("Bob", initial_balance=500)
    eve = PrivacyAgent("Eve", initial_balance=0)

    # 2. Build Merkle tree & Cluster Public Key Ring
    authorized_cluster_pks = [alice.pk, bob.pk]
    merkle_tree = MerkleTree(authorized_cluster_pks)
    cluster_root = merkle_tree.get_root()

    alice.set_cluster_merkle_root(cluster_root)
    bob.set_cluster_merkle_root(cluster_root)

    print("--- 1. Cluster Setup & Anonymous Ring Authentication ---")
    print(f"Merkle Cluster Root: {cluster_root.hex()[:16]}...")

    # Anonymous Ring Authentication: Alice proves membership without disclosing her identity
    auth_challenge = b"cluster-session-auth-challenge-v1"
    alice_ring_token = alice.create_anonymous_auth_token(authorized_cluster_pks, auth_challenge)
    anon_verified = bob.verify_anonymous_auth_token(alice_ring_token, authorized_cluster_pks)
    print(f"Anonymous Ring Signature verified by Bob? {anon_verified} (Signer identity strictly hidden)")

    # Rogue node Eve attempts to forge anonymous authentication
    eve_rogue_token = eve.create_anonymous_auth_token([eve.pk, bob.pk], auth_challenge)
    eve_cluster_verified = bob.verify_anonymous_auth_token(eve_rogue_token, authorized_cluster_pks)
    print(f"Eve authorized in cluster? {eve_cluster_verified}\n")

    # 3. Start TCP servers for both Alice (9001) and Bob (9002)
    alice.set_endpoint("127.0.0.1", 9001)
    async def alice_handler(payload: bytes):
        res = alice.handle_incoming_payload(payload)
        print(f"[Alice Node TCP] Received '{res['type']}': {res}")

    alice_node = AsyncPeerNode("127.0.0.1", 9001, alice_handler)
    await alice_node.start()

    bob.set_endpoint("127.0.0.1", 9002)
    async def bob_handler(payload: bytes):
        res = bob.handle_incoming_payload(payload)
        print(f"[Bob Node TCP] Received '{res['type']}': {res}")

    bob_node = AsyncPeerNode("127.0.0.1", 9002, bob_handler)
    await bob_node.start()

    # 4. Mutual Handshake
    print("--- 2. P2P Mutual Handshake ---")
    await alice.connect_to_peer("127.0.0.1", 9002, "127.0.0.1", 9001)
    await asyncio.sleep(0.05)

    print("\n--- 3. Wire-Level Stealth Confidential Settlement (AES-GCM AEAD) ---")
    # Alice sends stealth transfer directly over TCP socket to Bob's port 9002
    send_ok, wire_payload, stealth_pk, ephemeral_stealth_pk = await alice.send_stealth_transfer(
        target_host="127.0.0.1",
        target_port=9002,
        recipient_pk=bob.pk,
        amount=700
    )
    print(f"Wire transfer transmitted over TCP socket? {send_ok}")
    x_str, y_str = str(stealth_pk.x), str(stealth_pk.y)
    print(f"Destination One-Time Stealth Address: Point({x_str[:10]}..., {y_str[:10]}...)")
    await asyncio.sleep(0.05)  # Allow socket handler to process and settle

    # Eve intercepts the wire payload and attempts to scan/claim Bob's transfer
    eve_scan = eve.process_stealth_transfer(wire_payload)
    print(f"Eve able to scan/claim Bob's stealth transfer? {eve_scan}")

    # Replay attack protection test (resending the exact same wire transfer)
    print("Testing replay attack over TCP socket...")
    await AsyncPeerNode.send_payload("127.0.0.1", 9002, wire_payload)
    await asyncio.sleep(0.05)

    print("\n--- 4. Zero-Knowledge Range Proof (CDS 1-of-2 Disjunctive Sigma Proof) ---")
    from privacy_agent_protocol.crypto.pedersen import PedersenCommitment
    range_prover = ZKRangeProver(bit_length=16)
    ped = PedersenCommitment()
    transfer_amount = 700
    c_transfer, r_transfer = ped.commit(transfer_amount)
    bit_proofs, _ = range_prover.prove_range(transfer_amount, r_transfer)
    zk_range_valid = range_prover.verify_range(c_transfer, bit_proofs)
    print(f"Confidential transfer amount [0, 2^16) verified via CDS ZK Range Proof? {zk_range_valid}")

    print("\n--- 5. Final Cryptographic State Verification ---")
    print(f"Alice's balance equals 2300? {alice.account.verify_balance(2300)}")
    print(f"Bob's balance equals 1200? {bob.account.verify_balance(1200)}")

    await alice_node.stop()
    await bob_node.stop()
    print("\nAll nodes shut down cleanly. Demo complete.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Privacy-Preserving Multi-Agent Communication Protocol")
    parser.add_argument("--web", action="store_true", help="Launch interactive web visualizer & attack simulator (http://localhost:8000)")
    parser.add_argument("--cli", action="store_true", help="Launch interactive terminal testing interface")
    parser.add_argument("--simulate", action="store_true", help="Run interactive attack and privacy simulation in terminal")
    parser.add_argument("--port", type=int, default=8000, help="Port for web server (default: 8000)")

    args = parser.parse_args()

    if args.web:
        from web_app import run_server
        run_server(args.port)
    elif args.cli:
        from cli import main_cli
        asyncio.run(main_cli())
    elif args.simulate:
        from cli import interactive_attack_simulation
        from privacy_agent_protocol.session import ProtocolSession
        async def _run_sim():
            session = ProtocolSession()
            await session.initialize_defaults()
            await interactive_attack_simulation(session)
            await session.stop()
        asyncio.run(_run_sim())
    else:
        asyncio.run(main())


