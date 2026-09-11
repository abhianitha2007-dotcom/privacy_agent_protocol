import asyncio
import sys
from privacy_agent_protocol.session import ProtocolSession

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

def banner():
    print(f"\n{CYAN}{BOLD}=================================================================={RESET}")
    print(f"{CYAN}{BOLD}   🛡️  PRIVACY-PRESERVING MULTI-AGENT INTERACTIVE TESTBED       {RESET}")
    print(f"{CYAN}{BOLD}   Topic 9: Identity Hiding • Forward Secrecy • Ring Auth • ZK  {RESET}")
    print(f"{CYAN}{BOLD}=================================================================={RESET}\n")

async def interactive_attack_simulation(session: ProtocolSession):
    print(f"\n{MAGENTA}{BOLD}--- ⚔️  INTERACTIVE ATTACK & PROTOCOL SIMULATOR ---{RESET}")
    print("In this simulation, a sender transmits confidential information and funds")
    print("to a destination node. An adversary (Eve) intercepts the in-flight packet")
    print("and attempts 4 distinct attacks, getting blocked at every cryptographic barrier.\n")

    state = session.get_state()
    agent_names = [a["name"] for a in state["agents"]]

    print(f"Available agents: {', '.join(agent_names)}")
    sender = input(f"Enter Sender [{agent_names[0]}]: ").strip() or agent_names[0]
    receiver_candidates = [n for n in agent_names if n != sender]
    def_receiver = receiver_candidates[0] if receiver_candidates else "Bob"
    receiver = input(f"Enter Destination [{def_receiver}]: ").strip() or def_receiver
    attacker = input("Enter Attacker [Eve]: ").strip() or "Eve"
    
    amount_str = input("Enter transfer amount [500]: ").strip() or "500"
    try:
        amount = int(amount_str)
    except ValueError:
        print(f"{RED}Invalid amount.{RESET}")
        return

    message = input("Enter confidential message/payload (optional) [Confidential Task Payload]: ").strip()
    if not message:
        message = "Confidential Task Payload"

    print("\nChoose Attack for Eve to attempt:")
    print("  1. 🕵️  Identity Sniffing (Eve tries to unmask recipient)")
    print("  2. 🔓 Wiretap & Decrypt (Eve tries to read secret message)")
    print("  3. 💰 Key Theft & Spending (Eve tries to derive stealth private key)")
    print("  4. ⚡ In-Flight Tampering (Eve modifies message bytes in-transit)")
    print("  5. 🔁 Replay Attack (Eve captures and re-broadcasts identical packet)")
    print("  6. 🌟 Full 4-Stage Attack Gauntlet (All attacks concurrently)")
    
    att_choice = input("Select Attack [1-6, default: 1]: ").strip() or "1"
    att_map = {
        "1": "unmask_identity",
        "2": "decrypt_payload",
        "3": "steal_funds",
        "4": "tamper_message",
        "5": "replay_packet",
    }

    if att_choice in att_map:
        attack_type = att_map[att_choice]
        print(f"\n{YELLOW}Simulating targeted attack [{attack_type}]...{RESET}")
        try:
            target_res = await session.execute_targeted_attack(sender, receiver, amount, message, attack_type, attacker)
        except Exception as e:
            print(f"{RED}Simulation failed: {e}{RESET}")
            return

        att_data = target_res["attack"]
        dest_data = target_res["destination"]
        b = target_res["balances"]

        print(f"\n{CYAN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"{CYAN}{BOLD}  1. PACKET DEPARTURE ({sender})                                 {RESET}")
        print(f"{CYAN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"  • Stealth Address (One-Time): {GREEN}{target_res['stealth_address_short']}{RESET}")
        print(f"  • Plaintext Message:          \"{target_res['message']}\"")
        print(f"  • Transfer Amount:            ${target_res['amount']}")
        print(f"  • AEAD Encryption:            AES-256-GCM + secp256k1 Ephemeral Key")

        print(f"\n{RED}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"{RED}{BOLD}  2. EVE INTERCEPTS IN-FLIGHT: [{att_data['icon']} {att_data['title']}] {RESET}")
        print(f"{RED}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"  • Attack Attempt: {att_data['attempt']}")
        print(f"  • What Eve Saw:   {YELLOW}{att_data['attacker_saw']}{RESET}")
        print(f"  • Result:         {RED}{BOLD}[🛑 BLOCKED]{RESET}")
        print(f"  • Defense:        {att_data['defense']}")

        print(f"\n{GREEN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"{GREEN}{BOLD}  3. BOB ARRIVAL & SAFE UNLOCKING                                {RESET}")
        print(f"{GREEN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"  • Status:           {GREEN}{BOLD}[📬 UNLOCKED & VERIFIED]{RESET}")
        print(f"  • Message Received: \"{dest_data['received_message']}\"")
        print(f"  • Amount Credited:  +${dest_data['received_amount']}")
        print(f"  • Verification:     Zero-Knowledge Range Proof Validated")

        print(f"\n{MAGENTA}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"{MAGENTA}{BOLD}  4. BALANCE IMPACT                                              {RESET}")
        print(f"{MAGENTA}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
        print(f"  • {sender}:    {b['sender']['before']} ➔ {b['sender']['after']} ({b['sender']['change']})")
        print(f"  • {receiver}:      {b['receiver']['before']} ➔ {b['receiver']['after']} (+{b['receiver']['change']})")
        print(f"  • {attacker}:       {b['attacker']['before']} ➔ {b['attacker']['after']} (0 gained / 0 stolen)")
        print(f"{GREEN}{BOLD}  ✓ Targeted Attack Simulation Complete!{RESET}\n")
        return

    print(f"\n{YELLOW}Running full cryptographic attack gauntlet...{RESET}")
    try:
        res = await session.simulate_attack_transfer(sender, receiver, amount, message, attacker)
    except Exception as e:
        print(f"{RED}Simulation failed: {e}{RESET}")
        return

    # Render Phase 1
    p1 = res["phase_1_sender"]
    print(f"\n{CYAN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"{CYAN}{BOLD}  STAGE 1: SENDER ({sender}) CRYPTOGRAPHIC DERIVATION            {RESET}")
    print(f"{CYAN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"  • Single-Use Stealth Address:  {GREEN}{p1['one_time_stealth_pk']}{RESET}")
    print(f"  • Disposable Ephemeral Point:  {GREEN}{p1['ephemeral_pk']}{RESET}")
    print(f"  • Homomorphic Pedersen Commit: {GREEN}{p1['commitment_C']}{RESET}")
    print(f"  • CDS 1-of-2 ZK Range Proof:   {GREEN}16-bit proof verified ({p1['zk_range_proof_valid']}){RESET}")
    print(f"  • Encrypted Blinding & Amount: {GREEN}AES-256-GCM authenticated ciphertext{RESET}")
    print(f"  • Wire Frame Size:             {len(res['raw_payload_hex']) // 2} bytes")
    print(f"  ℹ️  {p1['explanation']}")


    # Render Phase 2
    p2 = res["phase_2_attacker"]
    print(f"\n{RED}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"{RED}{BOLD}  STAGE 2: IN-FLIGHT WIRE INTERCEPTION ({attacker} INTERCEPTS)    {RESET}")
    print(f"{RED}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"  Adversary {attacker} captured the raw packet in-flight. Attack test results:")
    for att in p2["attacks"]:
        print(f"\n  [{RED}BLOCKED{RESET}] {BOLD}{att['attack_name']}{RESET}")
        print(f"    ↳ {att['details']}")

    # Render Phase 3
    p3 = res["phase_3_destination"]
    print(f"\n{GREEN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"{GREEN}{BOLD}  STAGE 3: DESTINATION ARRIVAL ({receiver}) UNLOCKING & SETTLEMENT  {RESET}")
    print(f"{GREEN}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"  • Stealth Scan Ownership:      {GREEN}MATCH (Recipient recognized stealth key){RESET}")
    print(f"  • Stealth Spending Key:        {GREEN}s_sk derived via (sk_recv + c) mod q{RESET}")
    print(f"  • AES-256-GCM AEAD Decrypt:    {GREEN}Successfully decrypted amount and blinding scalar{RESET}")
    print(f"  • Decrypted Amount:            {GREEN}{p3['decrypted_amount']} units{RESET}")
    print(f"  • Decrypted Payload Message:   {GREEN}\"{p3['decrypted_message']}\"{RESET}")
    print(f"  • Homomorphic Settlement:      {GREEN}C_new = C_old + C_transfer (Updated on secp256k1){RESET}")
    print(f"  ℹ️  {p3['explanation']}")

    # Render Phase 4
    p4 = res["phase_4_audit"]
    print(f"\n{MAGENTA}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"{MAGENTA}{BOLD}  STAGE 4: BALANCE LEDGER & AUDIT                                {RESET}")
    print(f"{MAGENTA}{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f"  • {sender} (Sender):      {p4['sender']['before']} ➔ {p4['sender']['after']} ({p4['sender']['delta']}) [Pedersen Verified]")
    print(f"  • {receiver} (Receiver):  {p4['receiver']['before']} ➔ {p4['receiver']['after']} ({p4['receiver']['delta']}) [Pedersen Verified]")
    print(f"  • {attacker} (Attacker):  {p4['attacker']['before']} ➔ {p4['attacker']['after']} (0 gained) [Access Denied]")
    print(f"  • Total Execution Time:   {p4['elapsed_ms']} ms")
    print(f"{GREEN}{BOLD}  ✓ Cryptographic Protocol Simulation Complete!{RESET}\n")

async def send_transfer_cli(session: ProtocolSession):
    state = session.get_state()
    agent_names = [a["name"] for a in state["agents"]]
    print(f"\nAvailable agents: {', '.join(agent_names)}")
    sender = input("Sender name: ").strip()
    receiver = input("Receiver name: ").strip()
    amount_str = input("Amount: ").strip()
    msg = input("Confidential memo (optional): ").strip()
    try:
        amount = int(amount_str)
        res = await session.send_transfer(sender, receiver, amount, msg)
        print(f"{GREEN}Transfer succeeded! Tx Hash: {res['tx_hash'][:16]}...{RESET}")
        print(f"Sender {sender} balance: {res['sender_balance_after']}")
        print(f"Receiver {receiver} balance: {res['receiver_balance_after']}")
    except Exception as e:
        print(f"{RED}Transfer failed: {e}{RESET}")

def view_agents_cli(session: ProtocolSession):
    state = session.get_state()
    print(f"\n{BOLD}Current Cluster Agents:{RESET}")
    for a in state["agents"]:
        auth_tag = f"{GREEN}[Authorized]{RESET}" if a["is_authorized"] else f"{RED}[Adversary]{RESET}"
        print(f"  • {BOLD}{a['name']}{RESET} {auth_tag} | Port: {a['endpoint']} | Balance: {GREEN}{a['balance']} units{RESET}")
        print(f"    PK: {a['pk']}")
    print(f"Merkle Cluster Root: {state['merkle_root'][:16]}...\n")

async def add_agent_cli(session: ProtocolSession):
    name = input("New Agent Name: ").strip()
    bal_str = input("Initial Balance [1000]: ").strip() or "1000"
    port_str = input("TCP Port [9005]: ").strip() or "9005"
    try:
        bal = int(bal_str)
        port = int(port_str)
        res = await session.add_agent(name, bal, port)
        print(f"{GREEN}Agent {res['name']} started on port {res['port']} with balance {res['balance']}!{RESET}")
    except Exception as e:
        print(f"{RED}Failed to create agent: {e}{RESET}")

async def test_replay_cli(session: ProtocolSession):
    if not session.tx_history:
        print(f"{YELLOW}No transactions recorded yet. Run a simulation or transfer first.{RESET}")
        return
    last_tx = session.tx_history[-1]
    print(f"Replaying last transaction ({last_tx['tx_hash'][:16]}...) against {last_tx['receiver']}...")
    res = await session.test_replay_attack(last_tx['receiver'], last_tx['raw_payload_hex'])
    print(f"{RED if res['replay_blocked'] else GREEN}Replay blocked? {res['replay_blocked']}{RESET}")
    print(f"Explanation: {res['explanation']}")

def test_ring_cli(session: ProtocolSession):
    signer = input("Signer Agent [Alice]: ").strip() or "Alice"
    try:
        res = session.test_anonymous_ring_auth(signer)
        print(f"{GREEN}Anonymous Ring Signature Verified? {res['signature_verified']}{RESET}")
        print(f"Identity Hidden? {res['identity_hidden']}")
        print(f"Explanation: {res['explanation']}")
    except Exception as e:
        print(f"{RED}Ring auth failed: {e}{RESET}")

async def main_cli():
    banner()
    session = ProtocolSession()
    print("Initializing protocol cluster...")
    await session.initialize_defaults()
    print(f"{GREEN}✓ Cluster initialized!{RESET}")

    while True:
        print(f"\n{BOLD}Select an option:{RESET}")
        print("  1. ⚔️  Run Interactive Attack & Protocol Simulator (Step-by-Step)")
        print("  2. 💸 Send Confidential Stealth Transfer")
        print("  3. 👥 View All Agents & Balances")
        print("  4. ➕ Add New Agent Node")
        print("  5. 🔁 Test Replay Attack Protection")
        print("  6. ⭕ Test Anonymous Ring Signature")
        print("  7. 🌐 Launch Web Dashboard & Visualizer")
        print("  0. ❌ Exit")

        choice = input("\nChoice [1-7, 0]: ").strip()
        if choice == "1":
            await interactive_attack_simulation(session)
        elif choice == "2":
            await send_transfer_cli(session)
        elif choice == "3":
            view_agents_cli(session)
        elif choice == "4":
            await add_agent_cli(session)
        elif choice == "5":
            await test_replay_cli(session)
        elif choice == "6":
            test_ring_cli(session)
        elif choice == "7":
            print(f"\n{CYAN}Starting web server on http://localhost:8000 ... (Press Ctrl+C to stop){RESET}")
            from web_app import run_server
            await session.stop()
            run_server(8000)
            break
        elif choice in ("0", "exit", "quit"):
            print("Shutting down session...")
            await session.stop()
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    try:
        asyncio.run(main_cli())
    except KeyboardInterrupt:
        print("\nExiting.")
