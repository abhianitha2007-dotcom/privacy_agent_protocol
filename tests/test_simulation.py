import pytest
import asyncio
from privacy_agent_protocol.session import ProtocolSession

@pytest.mark.asyncio
async def test_session_simulation_full_flow():
    session = ProtocolSession()
    await session.initialize_defaults(base_port=9401)

    try:
        # Run attack simulation: Alice sends 500 to Bob while Eve intercepts
        sim = await session.simulate_attack_transfer(
            sender_name="Alice",
            receiver_name="Bob",
            amount=500,
            message="Secret Alpha Directive",
            attacker_name="Eve"
        )

        assert sim["sender"] == "Alice"
        assert sim["receiver"] == "Bob"
        assert sim["attacker"] == "Eve"
        assert sim["amount"] == 500

        # Phase 1: Sender Generation
        p1 = sim["phase_1_sender"]
        assert p1["zk_range_proof_valid"] is True
        assert p1["one_time_stealth_pk"] is not None

        # Phase 2: Attacker Interception (All 4 attacks blocked)
        p2 = sim["phase_2_attacker"]
        assert p2["all_attacks_blocked"] is True
        assert len(p2["attacks"]) == 4
        for att in p2["attacks"]:
            assert att["blocked"] is True

        # Phase 3: Destination Node Arrival & Unlocking
        p3 = sim["phase_3_destination"]
        assert p3["stealth_scan_success"] is True
        assert p3["is_owner"] is True
        assert p3["stealth_sk_derived"] is True
        assert p3["decrypted_amount"] == 500
        assert p3["decrypted_message"] == "Secret Alpha Directive"

        # Phase 4: Audit & Balance Settlement
        p4 = sim["phase_4_audit"]
        assert p4["sender"]["after"] == 2500
        assert p4["receiver"]["after"] == 1000
        assert p4["attacker"]["after"] == 0
        assert p4["sender_commitment_verified"] is True
        assert p4["receiver_commitment_verified"] is True

    finally:
        await session.stop()

@pytest.mark.asyncio
async def test_session_dynamic_agent_and_transfer():
    session = ProtocolSession()
    await session.initialize_defaults(base_port=9501)


    try:
        # Add new agent Charlie on port 9505
        charlie_info = await session.add_agent("Charlie", initial_balance=1500, port=9505)
        assert charlie_info["name"] == "Charlie"
        assert "Charlie" in session.agents

        # Alice transfers 400 to Charlie
        tx = await session.send_transfer("Alice", "Charlie", 400, "Payment for task")
        assert tx["sender"] == "Alice"
        assert tx["receiver"] == "Charlie"
        assert tx["amount"] == 400
        assert session.agents["Alice"].account.balance == 2600
        assert session.agents["Charlie"].account.balance == 1900

        # Test replay attack on Charlie
        replay_res = await session.test_replay_attack("Charlie", tx["raw_payload_hex"])
        assert replay_res["replay_blocked"] is True
        assert session.agents["Charlie"].account.balance == 1900

    finally:
        await session.stop()

def test_session_anonymous_ring_auth():
    session = ProtocolSession()
    # Test ring signature without starting TCP sockets
    from privacy_agent_protocol.agent.agent import PrivacyAgent
    session.agents["Alice"] = PrivacyAgent("Alice", 1000)
    session.agents["Bob"] = PrivacyAgent("Bob", 500)
    session.authorized_names = {"Alice", "Bob"}

    ring_res = session.test_anonymous_ring_auth("Alice", "challenge-12345")
    assert ring_res["signature_verified"] is True
    assert ring_res["identity_hidden"] is True

@pytest.mark.asyncio
async def test_session_targeted_attack_types():
    session = ProtocolSession()
    await session.initialize_defaults(base_port=9601)

    try:
        attack_types = ["unmask_identity", "decrypt_payload", "steal_funds", "tamper_message", "replay_packet"]
        for att in attack_types:
            res = await session.execute_targeted_attack(
                sender_name="Alice",
                receiver_name="Bob",
                amount=100,
                message=f"Testing {att}",
                attack_type=att,
                attacker_name="Eve"
            )
            assert res["attack"]["blocked"] is True
            assert res["destination"]["status"] == "UNLOCKED & VERIFIED"
            assert res["balances"]["attacker"]["after"] == 0
    finally:
        await session.stop()

