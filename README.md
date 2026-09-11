# Privacy-Preserving Multi-Agent Communication Protocol (Topic 9)

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

---

## Directory Structure

```text
privacy_agent_protocol/
│
├── main.py                          # Integrated protocol execution demo
├── README.md                        # Protocol documentation & architecture
├── pyproject.toml                   # Project packaging & dependency specifications
│
├── privacy_agent_protocol/          # Core package
│   ├── __init__.py
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
│   │   └── serializer.py            # Binary MessagePack framing with wire-level stealth metadata
│   └── zk/                          # Zero-knowledge proof engines
│       ├── merkle.py                # Merkle tree cluster membership
│       ├── proofs.py                # NIZK opening proofs
│       ├── range_proofs.py          # CDS 1-of-2 disjunctive ZK range proofs
│       └── ring.py                  # Spontaneous Anonymous Group (SAG) ring signatures
│
└── tests/                           # Automated Pytest suite
    └── test_protocol.py             # Unit and end-to-end integration tests
```

---

## Running the Protocol

### Run Automated Test Suite
```bash
pytest -v
```

### Run Protocol Execution Demo
```bash
python3 main.py
```

