# Completed implementation changes — Security Lab v3

## Changes requested from the four screenshots

- Replaced **Cipher Atlas** branding in the site title, sidebar, server labels, and visible pages with **Privacy-Preserving Multi-Agent Communication / Secure Communication Lab**.
- Removed giant mottos on System Overview, Attack Simulator, Cryptography, and Experiment Archive. Kept the Protocol Assistant presentation essentially unchanged.
- Replaced the Observatory hero's motto with a functional System Overview, live Python engine status, metrics, topology and workspace link; removed decorative quote ribbon and other slogans.
- Combined sections **2 (Attack Chamber)** and **3 (Secure Communication & Agent Management)** into **Communication & Attack Simulator** with live agent registration, selectable sender/recipient, user-authored encrypted messages, live topology, signed receipt, inbox and attack targeting.
- Changed attack experiments from generic isolated sample input to **selectable, message-linked isolated reenactments**. The record links to the user's message ID and uses the same sender, receiver and plaintext, but *new isolated test keys*: it does not damage, alter or disable real live messages.
- Replaced static Crypto Anatomy with **Cryptographic Operations & Security Audit**: public keys, fingerprints, ciphertext, nonce, tag, signature, verified receipt, full message checks, per-attack steps, search/filter, optional local plaintext and complete-history metadata export.
- Preserved **Experiment Archive** and **Protocol Assistant** (except page numbering and obsolete brand text).
- Added per-session local JSONL audit metadata with automatic archival and regression tests, while retaining the underlying cryptography and replay/rate defenses.

## Security model / limitations

- No browser account authentication. Run **only** on loopback and never with confidential real-world messages.
- The web-facing audit metadata is available to any local client. Private keys, symmetric keys, shared secrets, and normally plaintext are **not** recorded. Opted-in plaintext is accessible only from the current running process; exports always omit it.
- Audit metadata survives restarts but **agent private keys, live message snapshots, inboxes, and replay state do not**. Never interpret old audit public keys as the current trusted identities.
- Attack visualizations are illustrative; actual cryptography verifies signatures, authentication tags and replay/rate limits in **isolated** test agents. Hypothetical vulnerable-mode claims are never actually executed.
- This project has no independently authenticated trust bootstrap, anonymous identities, full forward secrecy, persistent replay defense, strong application authorization, or comprehensive DoS protection.

Run tests with `python -m pytest -q`. See README.md for command-line and browser instructions.


## Follow-up revisions (2026-11-23)
- New agents enter a visible placement mode; clicking the network positions them. Existing nodes support drag-and-drop and keyboard arrow moves. Coordinates are stored in browser localStorage, not in the cryptographic trust directory.
- The simulator draws the entire registered network, with chosen sender and recipient highlighted alongside Eve. Attack-specific animated paths and overlays are displayed without hiding other agents.
- Security Audit displays only the current localhost server run. Older log metadata is moved to `data/previous_sessions/` automatically on server initialization; it is excluded from the new session counts and exports.
- The Protocol Assistant answers dynamic questions about live agents, messages and experiments, and retrieves relevant implementation facts rather than requiring only fixed keyword phrases. Optional local Ollama support is strictly opt-in and uses localhost.
