# Privacy-Preserving Multi-Agent Communication Protocol 

A research-grade, asynchronous multi-agent peer-to-peer (P2P) networking and cryptographic protocol strictly adhering to the four core pillars of **Topic 9**: **Identity Hiding**, **Forward Secrecy**, **Anonymous Authentication**, and **Authorization**.

---

## Technical Features & Core Cryptography

* **Identity Hiding (One-Time Stealth Addresses)**: Recipients scan single-use stealth public keys ($P_{\text{stealth}} = PK_{\text{recipient}} + c \cdot G$) for every transfer, preventing network observers from linking transaction outputs to static node identities.
* **Forward Secrecy & AEAD (Ephemeral ECDH + AES-256-GCM)**: Symmetric encryption and shared scalar derivations utilize disposable ephemeral Elliptic Curve Diffie-Hellman keypairs ($(e_{\text{sk}}, E_{\text{pk}})$) expanded via HKDF-SHA256 into AES-256-GCM AEAD authenticated ciphers, guaranteeing forward secrecy and ciphertext integrity.
* **Anonymous Authentication (Spontaneous Anonymous Group Ring Signatures)**: Nodes authenticate cluster membership using Schnorr / SAG Ring Signatures over authorized public keys without revealing their identity slot or static public key.
* **Cluster Authorization (Merkle Trees)**: Maintains verifiable cluster rosters through cryptographic Merkle inclusion paths ($Root = \text{SHA256}(\dots)$).
* **Confidential Balance Settlement (Pedersen Commitments)**: Hides transfer amounts using homomorphic commitments ($C = v \cdot G + r \cdot H$) on the `secp256k1` curve with a verifiable Nothing-Up-My-Sleeve (NUMS) independent generator $H$.
* **Value Integrity (CDS 1-of-2 ZK Range Proofs)**: Cramer-Damgård-Schoenmakers disjunctive zero-knowledge proofs enforce that committed values decompose into valid bits ($b_i \in \{0, 1\}$) and remain within $[0, 2^{16})$, preventing negative minting or underflow attacks.
* **Autonomous Wire-Level Stealth Scanning**: Asynchronous TCP peer sockets autonomously inspect wire transfers, scan for stealth key ownership, and settle funds with built-in replay protection.
* **Interactive Attack & Protocol Simulator**: Interactive testbed simulating active Man-in-the-Middle (MitM) wire sniffing, testing 4 intrusion vectors (Identity Unmasking, AEAD Decryption, Stealth Key Theft, Packet Tampering/Replay) and showing how each is mathematically blocked.

---

## Testing & Interactive Interfaces

### 1. Privacy Protocol Simulator (Virtual Labs Edition)
Launch the browser simulator (zero extra dependencies):
```bash
python3 main.py --web
# or
python3 web_app.py
```
Open **[http://localhost:8000](http://localhost:8000)** in your browser:
* **🔬 Protocol Simulator Tab**: Virtual Labs style sequence timing diagram with vertical lifelines (Alice, Eve, Bob), a round 3D PING button, real-time timer, and numbered communication log tracking transmissions, blocked attacks, and homomorphic settlements.
* **📋 Cryptographic Ledger & Audit Tab**: Neat, high-contrast cards displaying verified Pedersen commitment balances, single-use stealth public keys, CDS ZK Range Proof validations, and cluster Merkle roots.
* **🤖 Protocol Assistant Bot Tab**: Interactive AI assistant answering questions on Topic 9 cryptography (stealth addresses, forward secrecy, CDS range proofs, ring auth) and explaining why attacks fail.


---

### 2. Interactive Terminal CLI
Run the interactive terminal menu system:
```bash
python3 main.py --cli
# or
python3 cli.py
```

---

### 3. Direct Attack Simulation in Terminal
Run the step-by-step cryptographic attack simulation directly in the command line:
```bash
python3 main.py --simulate
```

---

### 4. Standard Automated Protocol Demo
Run the baseline automated demonstration:
```bash
python3 main.py
```

---

### 5. Automated Pytest Suite
Run unit, integration, and simulation tests:
```bash
pytest -v
```

---

## Directory Structure

```text
privacy_agent_protocol/
│
├── main.py                          # Multi-mode entry point (--web, --cli, --simulate)
├── web_app.py                       # Interactive Web Visualizer & REST backend
├── cli.py                           # Interactive terminal testing interface
├── README.md                        # Protocol documentation & architecture
├── pyproject.toml                   # Project packaging & dependency specifications
│
├── privacy_agent_protocol/          # Core package
│   ├── __init__.py
│   ├── session.py                   # Dynamic cluster orchestrator & attack simulator
│   ├── agent/                       # High-level agent orchestration
│   │   └── agent.py                 # PrivacyAgent with autonomous scanning & ring auth
│   ├── crypto/                      # Core elliptic curve & stealth primitives
│   │   ├── pedersen.py              # Canonical NUMS Pedersen Commitments
│   │   ├── commitment.py            # Re-export alias for pedersen module
│   │   ├── ecdh.py                  # Ephemeral ECDH & AES-256-GCM AEAD encryption
│   │   └── stealth.py               # One-time stealth address generation & derivation
│   ├── network/                     # Asynchronous P2P transport
│   │   ├── cluster.py               # Peer registry & routing table
│   │   ├── node.py                  # Asyncio TCP socket server
│   │   └── serializer.py            # Binary MessagePack framing with wire metadata
│   ├── state/                       # Private account & commitment vault
│   │   └── account.py               # Homomorphic Pedersen commitment account
│   └── zk/                          # Zero-knowledge proof engines
│       ├── merkle.py                # Merkle tree cluster membership
│       ├── proofs.py                # NIZK opening proofs
│       ├── range_proofs.py          # CDS 1-of-2 disjunctive ZK range proofs
│       └── ring.py                  # Spontaneous Anonymous Group (SAG) ring signatures
│
└── tests/                           # Automated Pytest suite
    ├── test_protocol.py             # Unit and end-to-end integration tests
    └── test_simulation.py           # Attack simulation and dynamic agent tests
```
