# Privacy-Preserving Multi-Agent Communication

**Local Python research application with agent-to-agent encrypted messages, attack reenactment, and cryptographic security auditing.** Includes the complete responsive frontend, backend, tests, and preview images. The former “Cipher Atlas” branding and decorative mottos have been removed from all pages except the Protocol Assistant, where the original explanatory presentation is retained.

## Run the application

Requires Python 3.10+ and a local browser. No npm, Node.js, external services, browser extensions, JavaScript build, or API keys are required.

```bash
python -m pip install -r requirements.txt
python main.py --web --port 8000
```

Open **http://127.0.0.1:8000** on the same computer. Do **not** open `frontend/index.html` directly, because the UI depends on its local Python API. Keep the server on localhost; it has no browser login or user authorization.

Additional CLI modes:

```bash
python main.py --simulate
python main.py --cli
```

## The five integrated pages

1. **System Overview:** live Python status, agent/message/experiment counts, baseline network illustration, and direct links to the combined workspace.
2. **Communication & Attack Simulator:** a single workspace combining the former Attack Chamber and Secure Communication & Agent Management pages. Create up to 12 local agents, see every registered trusted agent in a responsive animated topology, choose the sender and receiver, type your own message, send it over local TCP, inspect a signed delivery receipt, and choose any recent delivered message as the target for one of six attack reenactments. Run, pause, step, reset, and speed controls remain supported.
3. **Cryptographic Operations & Security Audit:** detailed, searchable entries for agent registration, encrypted messages, and every attack experiment. View Ed25519/X25519 public keys, fingerprints, ephemeral public keys, nonces, AES-GCM authentication tags, ciphertext, signatures, signed receipts, individual validation steps, rejection codes, and result explanations. Includes type filters, plaintext opt-in for messages in the current process, and **full-history metadata exports in JSON and CSV**.
4. **Experiment Archive:** original experiment charts, attack statistics, result history, and recent event journal, preserved rather than replaced or duplicated.
5. **Protocol Assistant:** original local deterministic explainer retained. It does not use a remote model or cloud API.

**Financial features remain completely removed**: no accounts, balances, credit transfers, payments, settlements, or transaction APIs.

## Real messages and linked experiments

To run an attack on your own communication:

1. Open **Communication & Attack Simulator**.
2. Add an agent, or select two existing trusted agents (e.g., Alice and Bob).
3. Type any text up to 4,096 UTF-8 bytes and send it.
4. Choose the delivered message in **Target Delivered Message** (the last sent message is selected automatically).
5. Select tampering, replay, impersonation, unauthorized decryption, oversized packet, or flooding, then select **Run Experiment**.
6. Open **Cryptographic Operations & Security Audit** to find the communication and attack by their shared target message ID, with full public cryptographic metadata and per-operation results.

**Important distinction:** A selected attack reenacts the user's message *content and sender/receiver roles* using new **isolated test keys and agents**. It does not modify or resend the original live packet. The backend performs actual cryptographic checks within that isolated experiment, while graphical animation simply explains the observed result. The protected/vulnerable toggle never disables real security: unprotected outcomes are clearly labeled **hypothetical**.

## Audit log and privacy

- The running web application saves audit metadata to `data/security_audit.jsonl` (created on first run; file permissions set to 0600 on Unix). Audit history survives restarts and is append-only under normal operation.
- The inspector shows the **250 most recent entries** by default; **JSON/CSV exports include all recorded metadata entries**.
- Agent-registration records contain public signing/encryption keys and fingerprints, never private keys.
- Each message records cipher metadata, recipient information, signatures, receipt checks, status and full security-operation timeline.
- Each attack records the target message ID, attack type, isolated test packet public data, defense results, and every scenario-specific stage.
- **Plaintext is excluded** from persistent audit files and exported metadata. The inspector's optional **Reveal local-session message plaintext** control shows plaintext only for live message records held in the current process; it is not persisted or exported.
- Inboxes contain decrypted local demonstration messages. Any process or local user with access to the web interface can view them. **Do not use real-world confidential data**.
- The current agent roster, decrypted inboxes, and selectable message snapshots are in memory and are reset at restart. The audit metadata itself persists, but old packets cannot be replayed as selectable live targets after restart.
- To reset the audit **metadata** manually, stop the application and delete `data/security_audit.jsonl`. Do not delete the whole application folder.

## Tests

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
```

Tests cover end-to-end local TCP messaging, signed receipts, packet validation, all six isolated attack defenses, user-selected message targeting, encrypted message and attack auditing, public-key records, private-secret exclusion, durable audit metadata, and HTTP/web integration. Browser controls were also exercised in Chromium using locally bridged Python API requests; the final frontend is plain HTML/CSS/JS requiring no build tools.

## Protocol implementation and limitations

| Purpose | Implemented mechanism |
|---|---|
| Sender identity | Ed25519 signatures validated against locally pinned public keys |
| Receiver confidentiality | Ephemeral sender X25519 + recipient static X25519 key agreement |
| Symmetric key derivation | HKDF-SHA256 |
| Encryption and integrity | AES-256-GCM, authenticated additional data |
| Replay defense | Message-ID cache + five-minute clock-skew window, in-memory |
| Flood control | Sliding-window sender rate limit |
| Frame-size defense | 4,096-byte plaintext limit and bounded TCP network frames |
| Delivery acknowledgement | Independently signed recipient receipt |

The system is a **local research demonstration, not a production-secure or anonymous messaging service**. The web UI has no authorization or authentication; anyone able to reach it locally can act as any trusted demo agent. First-contact trust is locally provisioned, not independently authenticated. Sender/recipient metadata is visible. Static recipient keys do not give full forward secrecy, and replay state does not survive restarts. Local rate/size limits are not comprehensive distributed denial-of-service mitigation. Attack simulations illustrate individual checks; they do not prove broad protocol security.

## Source map

```text
main.py                     Web, CLI, and demonstration entry points
web_app.py                  Loopback-only local HTTP API and static server
frontend/index.html         Five-page single-application interface
frontend/styles.css         Original editorial design, mobile styling and attack animations
frontend/app.js             Dynamic agent network, communication, attack controls, audit inspector
privacy_agent_protocol/
  agent/agent.py            Signing, decrypt, trusted peer checks, replay/rate defense
  crypto/secure_message.py  X25519, HKDF-SHA256, AES-256-GCM and Ed25519
  network/node.py           Local TCP with bounded frames and receipts
  network/serializer.py     Strict MessagePack packet schema
  network/cluster.py        Peer registration and local networking helpers
  session.py                Agent lifecycle, messaging, attack reenactments, audit history
tests/                      Automated Python and HTTP regression tests
previews/                   Updated desktop, mobile, unified workspace and audit screenshots
FIXES_AND_LIMITATIONS.md     Summary and limitations
```
