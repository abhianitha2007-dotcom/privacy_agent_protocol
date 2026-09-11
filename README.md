# Privacy-Preserving Multi-Agent Communication Protocol (Topic 9)

A research-grade, asynchronous multi-agent peer-to-peer (P2P) networking and cryptographic protocol strictly adhering to the four core pillars of **Topic 9**: **Identity Hiding**, **Forward Secrecy**, **Anonymous Authentication**, and **Authorization**.

---

## Technical Features & Core Cryptography

* **Identity Hiding (One-Time Stealth Addresses)**: Recipients generate single-use stealth public keys ($P_{\text{stealth}} = PK_{\text{recipient}} + c \cdot G$) for every transfer, preventing network observers from linking transaction outputs to static node identities.
* **Forward Secrecy (Ephemeral ECDH)**: Symmetric encryption and shared scalar derivations utilize disposable ephemeral Elliptic Curve Diffie-Hellman keypairs ($(e_{\text{sk}}, E_{\text{pk}})$), ensuring past communications remain uncompromised if long-term keys are exposed.
* **Anonymous Cluster Authorization (Merkle Trees)**: Nodes prove network authority using zero-knowledge Merkle inclusion paths ($Root = \text{SHA256}(\dots)$) without exposing their identity slot or index in the cluster.
* **Confidential Balance Settlement (Pedersen Commitments)**: Hides transfer amounts using homomorphic commitments ($C = v \cdot G + r \cdot H$) on the `secp256k1` curve.
* **Value Integrity (ZK Range Proofs)**: Bit-decomposition zero-knowledge range proofs enforce that transaction values remain strictly within $[0, 2^{16})$, preventing negative minting or overflow attacks.

---

## Directory Structure

```text
privacy_agent_protocol/
│
├── main.py                          # Integrated protocol execution demo
├── README.md                        # Protocol documentation & architecture
│
├── privacy_agent_protocol/          # Core package
│   ├── __init__.py
│   ├── agent/                       # High-level agent orchestration
│   │   └── agent.py
│   ├── crypto/                      # Core elliptic curve & stealth primitives
│   │   ├── commitment.py            # Homomorphic Pedersen Commitments
│   │   ├── ecdh.py                  # Ephemeral ECDH & scalar encryption
│   │   └── stealth.py               # One-time stealth address generation
│   ├── network/                     # Asynchronous P2P transport
│   │   ├── cluster.py               # Peer registry & routing table
│   │   ├── node.py                  # Asyncio TCP socket server
│   │   └── serializer.py            # Binary MessagePack framing
│   └── zk/                          # Zero-knowledge proof engines
│       ├── merkle.py                # Merkle tree cluster membership
│       ├── proofs.py                # NIZK opening proofs
│       └── range_proofs.py          # Bit-decomposition ZK range proofs
│
└── tests/                           # Automated Pytest suite
    └── test_protocol.py
