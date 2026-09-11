import asyncio
import json
import socket
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from privacy_agent_protocol.session import ProtocolSession

_SESSION = None
_LOOP = None

def get_session():
    global _SESSION, _LOOP
    if _SESSION is None:
        _SESSION = ProtocolSession()
        _LOOP = asyncio.new_event_loop()

        def run_async_loop(loop):
            asyncio.set_event_loop(loop)
            loop.run_forever()

        threading.Thread(target=run_async_loop, args=(_LOOP,), daemon=True).start()
        # Non-blocking initialization
        asyncio.run_coroutine_threadsafe(_SESSION.initialize_defaults(), _LOOP).result(timeout=5)
    return _SESSION, _LOOP

def answer_bot_query(query: str, session: ProtocolSession) -> str:
    q = query.lower()
    state = session.get_state()
    if "why" in q and ("blocked" in q or "eve" in q or "fail" in q):
        return (
            "🛡️ **Why Eve Was Blocked:**\n\n"
            "1. **Identity Hiding (Stealth Addresses)**: The transfer uses a one-time public key "
            "P_stealth = PK_Bob + Hash(r * PK_Bob)*G. Network observers see only random curve points; "
            "Eve cannot link this address to Bob without Bob's private scalar.\n\n"
            "2. **Forward Secrecy (ECDH + AEAD)**: Alice & Bob establish an ephemeral ECDH shared key "
            "expanded via HKDF-SHA256 into an AES-256-GCM key. Eve's forged decryption fails the "
            "poly1305/GCM authentication tag check (InvalidTag error).\n\n"
            "3. **Key Theft Prevention**: To spend funds, an agent must prove s_sk * G == P_stealth. "
            "Eve cannot compute s_sk = sk_Bob + Hash(r * PK_Bob) because she doesn't possess Bob's private key.\n\n"
            "4. **Replay Protection**: The node tracks processed transaction hashes; duplicate payloads are rejected."
        )
    elif "stealth" in q:
        return (
            "🔑 **One-Time Stealth Addresses (secp256k1):**\n\n"
            "For every transaction, the sender generates a disposable scalar r and ephemeral point R = r*G. "
            "The shared secret is c = Hash(r * PK_Recipient). The recipient's stealth destination is "
            "P_stealth = PK_Recipient + c*G.\n\n"
            "Only the recipient (possessing private key sk) can compute the spending key: "
            "s_sk = sk + c (mod n) such that s_sk * G = P_stealth."
        )
    elif "pedersen" in q or "commitment" in q or "homomorphic" in q:
        return (
            "⚖️ **Homomorphic Pedersen Commitments:**\n\n"
            "Account balances and transfers are represented as C = v*G + r*H, where H is a NUMS "
            "(Nothing-Up-My-Sleeve) generator. Settlement occurs homomorphically:\n"
            "  C_new = C_current + C_transfer\n"
            "This settles the balance mathematically on-wire without ever revealing the plaintext amount v!"
        )
    elif "range" in q or "zk" in q or "cds" in q:
        return (
            "📐 **CDS 1-of-2 ZK Range Proofs:**\n\n"
            "To prevent negative amount inflation and field underflow attacks, the sender proves that "
            "the transferred value lies within [0, 2^16). We decompose the amount into 16 binary bits and construct "
            "a Cramer-Damgård-Schoenmakers (CDS) 1-of-2 disjunctive proof for each bit being in {0, 1}."
        )
    elif "ring" in q or "anonymous auth" in q:
        return (
            "⭕ **Anonymous Ring Authentication (SAG):**\n\n"
            "Nodes authenticate membership using Spontaneous Anonymous Group (SAG) ring signatures over "
            "the cluster's public keys. The verifier confirms a legitimate cluster member authorized the message, "
            "while the actual signer's identity remains unconditionally untraceable."
        )
    elif "balance" in q or "nodes" in q or "agents" in q:
        agents_summary = ", ".join([f"{a['name']}: {a['balance']} units" for a in state["agents"]])
        return f"📊 **Active Cluster State:**\n\nNodes: {agents_summary}\nMerkle Root: {state['merkle_root'][:16]}..."
    else:
        return (
            "🤖 **Protocol Assistant Bot:**\n\n"
            "I can explain Topic 9 cryptographic mechanisms: stealth addresses, forward secrecy, "
            "Pedersen commitments, CDS ZK range proofs, or why an attacker was blocked! "
            "Try clicking one of the quick prompt chips above."
        )

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Topic 9: Privacy Protocol Simulator</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: rgba(17, 24, 39, 0.85);
      --card-border: rgba(255, 255, 255, 0.08);
      --primary: #06b6d4;
      --primary-hover: #0891b2;
      --accent: #8b5cf6;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --text: #f3f4f6;
      --text-dim: #9ca3af;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 0%, #172554 0%, #0b0f19 75%);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      min-height: 100vh;
      padding-bottom: 40px;
    }

    /* Top Sticky Header */
    header {
      background: rgba(11, 15, 25, 0.85);
      backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--card-border);
      position: sticky;
      top: 0;
      z-index: 100;
      padding: 14px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-icon {
      font-size: 28px;
      filter: drop-shadow(0 0 8px rgba(6, 182, 212, 0.5));
    }
    .brand-title {
      font-size: 20px;
      font-weight: 700;
      background: linear-gradient(135deg, #38bdf8, #818cf8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: 0.3px;
    }
    .brand-sub {
      font-size: 12px;
      color: var(--text-dim);
    }
    .status-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #34d399;
      font-size: 13px;
      padding: 6px 14px;
      border-radius: 9999px;
      font-family: var(--font-mono);
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 8px #10b981;
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

    /* Navigation Bar */
    .nav-tabs {
      display: flex;
      gap: 8px;
      padding: 18px 28px 0 28px;
      max-width: 1400px;
      margin: 0 auto;
      overflow-x: auto;
    }
    .tab-btn {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--card-border);
      color: var(--text-dim);
      padding: 10px 20px;
      border-radius: 10px 10px 0 0;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
      white-space: nowrap;
    }
    .tab-btn:hover {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text);
    }
    .tab-btn.active {
      background: var(--card-bg);
      border-bottom: 2px solid var(--primary);
      color: var(--primary);
    }

    main {
      max-width: 1400px;
      margin: 0 auto;
      padding: 20px 28px;
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.25s ease-in; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }

    /* Cards */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 24px;
      backdrop-filter: blur(10px);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
      margin-bottom: 20px;
    }
    .card-title {
      font-size: 18px;
      font-weight: 700;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    /* Form Controls */
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 16px;
    }
    .form-group {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .form-label {
      font-size: 13px;
      color: var(--text-dim);
      font-weight: 600;
    }
    select, input {
      background: #1e293b;
      border: 1px solid rgba(255, 255, 255, 0.15);
      border-radius: 8px;
      padding: 10px 14px;
      color: var(--text);
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }
    select:focus, input:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.25);
    }
    .btn {
      background: var(--primary);
      color: #0b0f19;
      font-weight: 700;
      padding: 12px 24px;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-size: 14px;
      transition: all 0.2s;
    }
    .btn:hover {
      background: var(--primary-hover);
      box-shadow: 0 0 16px rgba(6, 182, 212, 0.4);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text);
      border: 1px solid var(--card-border);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.14);
      box-shadow: none;
    }
    .btn-transmit {
      background: linear-gradient(135deg, #10b981, #059669);
      color: white;
      font-weight: 800;
      font-size: 15px;
      padding: 12px 28px;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      box-shadow: 0 4px 14px rgba(16, 185, 129, 0.35);
      transition: all 0.2s;
    }
    .btn-transmit:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(16, 185, 129, 0.5);
    }
    .btn-transmit:disabled {
      opacity: 0.5;
      cursor: not-allowed;
      transform: none;
    }

    /* VISUAL PROTOCOL SEQUENCE SIMULATOR */
    .simulator-workspace {
      display: grid;
      grid-template-columns: 1fr 340px;
      gap: 20px;
      margin-bottom: 24px;
    }
    @media (max-width: 1024px) {
      .simulator-workspace { grid-template-columns: 1fr; }
    }

    /* Diagram Stage */
    .diagram-panel {
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      position: relative;
      min-height: 460px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
    }
    .lifelines-header {
      display: flex;
      justify-content: space-between;
      padding: 0 40px;
      margin-bottom: 16px;
      position: relative;
      z-index: 2;
    }
    .lifeline-pill {
      padding: 8px 18px;
      border-radius: 8px;
      font-weight: 700;
      font-size: 13px;
      display: flex;
      align-items: center;
      gap: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    .node-alice-pill {
      background: rgba(6, 182, 212, 0.15);
      border: 1px solid rgba(6, 182, 212, 0.5);
      color: #38bdf8;
    }
    .node-eve-pill {
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.5);
      color: #f87171;
    }
    .node-bob-pill {
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.5);
      color: #34d399;
    }

    .lifelines-canvas {
      position: relative;
      flex: 1;
      min-height: 380px;
    }
    .lifeline-line {
      position: absolute;
      top: 0;
      bottom: 0;
      width: 2px;
      background: rgba(255, 255, 255, 0.15);
      z-index: 1;
    }
    .lifeline-line.line-alice { left: 16%; }
    .lifeline-line.line-eve { left: 50%; border-left: 2px dashed rgba(239, 68, 68, 0.3); background: transparent; }
    .lifeline-line.line-bob { left: 84%; }

    /* Animated Transmission Sequence Rows */
    .seq-row {
      position: relative;
      height: 64px;
      margin-bottom: 12px;
      z-index: 5;
    }
    .seq-arrow {
      position: absolute;
      top: 26px;
      height: 2px;
      background: #38bdf8;
      box-shadow: 0 0 8px rgba(56, 189, 248, 0.6);
      transition: width 0.6s ease-in-out;
    }
    .seq-arrow::after {
      content: '';
      position: absolute;
      right: 0;
      top: -4px;
      width: 0; height: 0;
      border-top: 5px solid transparent;
      border-bottom: 5px solid transparent;
      border-left: 8px solid #38bdf8;
    }
    .seq-arrow.blocked-arrow {
      background: var(--danger) !important;
      box-shadow: 0 0 10px rgba(239, 68, 68, 0.7);
    }
    .seq-arrow.blocked-arrow::after {
      border-left: 8px solid var(--danger) !important;
    }
    .seq-arrow.deliver-arrow {
      background: var(--success) !important;
      box-shadow: 0 0 10px rgba(16, 185, 129, 0.7);
    }
    .seq-arrow.deliver-arrow::after {
      border-left: 8px solid var(--success) !important;
    }
    .seq-arrow.settle-arrow {
      border-top: 2px dashed #a855f7;
      background: transparent;
      box-shadow: none;
    }
    .seq-arrow.settle-arrow::after {
      border-left: 8px solid #a855f7;
    }
    .seq-label {
      position: absolute;
      top: 4px;
      font-size: 11px;
      font-weight: 700;
      font-family: var(--font-mono);
      background: rgba(11, 15, 25, 0.9);
      padding: 3px 8px;
      border-radius: 4px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      white-space: nowrap;
    }

    /* Blocked Attack Badge Mark */
    .blocked-badge-mark {
      position: absolute;
      top: -12px;
      left: calc(50% - 38px);
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid #ef4444;
      color: #fca5a5;
      font-size: 11px;
      font-weight: 800;
      padding: 2px 8px;
      border-radius: 4px;
      letter-spacing: 0.5px;
      animation: pulse 1.5s infinite;
    }

    /* Right Column: Timer & Communication Log */
    .log-panel {
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      height: 100%;
    }
    .log-timer-box {
      background: rgba(6, 182, 212, 0.1);
      border: 1px solid rgba(6, 182, 212, 0.3);
      padding: 10px 14px;
      border-radius: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }
    .timer-val {
      font-family: var(--font-mono);
      font-size: 18px;
      font-weight: 700;
      color: #38bdf8;
    }
    .comm-log-title {
      font-size: 13px;
      font-weight: 700;
      color: var(--text-dim);
      margin-bottom: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .comm-log-list {
      flex: 1;
      list-style: none;
      overflow-y: auto;
      max-height: 380px;
      padding-right: 4px;
      font-family: var(--font-mono);
      font-size: 12px;
    }
    .comm-log-list li {
      padding: 8px 10px;
      background: rgba(0, 0, 0, 0.25);
      border-left: 3px solid #38bdf8;
      border-radius: 4px;
      margin-bottom: 8px;
      line-height: 1.4;
    }
    .comm-log-list li.log-blocked {
      border-left-color: #ef4444;
      background: rgba(239, 68, 68, 0.1);
      color: #fca5a5;
    }
    .comm-log-list li.log-success {
      border-left-color: #10b981;
      background: rgba(16, 185, 129, 0.1);
      color: #86efac;
    }

    /* Crisp Cryptographic Audit Cards */
    .audit-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 16px;
      margin-top: 20px;
    }
    .audit-card {
      background: rgba(30, 41, 59, 0.5);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 18px;
    }
    .audit-card.attacker-audit {
      border-color: rgba(239, 68, 68, 0.3);
      background: rgba(239, 68, 68, 0.04);
    }
    .audit-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }
    .audit-node-name {
      font-size: 16px;
      font-weight: 700;
    }
    .audit-badge {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 6px;
      text-transform: uppercase;
    }
    .badge-verified { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .badge-blocked { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .audit-balance-line {
      font-size: 14px;
      color: var(--text);
      margin-bottom: 6px;
    }
    .audit-balance-diff {
      font-size: 18px;
      font-weight: 700;
      margin-bottom: 8px;
    }
    .crypto-field {
      font-family: var(--font-mono);
      font-size: 11px;
      background: rgba(0, 0, 0, 0.35);
      padding: 6px 10px;
      border-radius: 6px;
      margin-top: 6px;
      color: #93c5fd;
      word-break: break-all;
    }

    /* Transfer Studio & Node Cards */
    .agent-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
      margin-top: 16px;
    }
    .agent-card {
      background: rgba(30, 41, 59, 0.5);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 18px;
      position: relative;
    }
    .agent-card.attacker {
      border-color: rgba(239, 68, 68, 0.4);
      background: rgba(239, 68, 68, 0.04);
    }
    .log-terminal {
      background: #000;
      border-radius: 8px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      max-height: 280px;
      overflow-y: auto;
      color: #a7f3d0;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }

    /* PROTOCOL ASSISTANT BOT */
    .bot-window {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      min-height: 300px;
      max-height: 420px;
      overflow-y: auto;
      margin-bottom: 16px;
      font-size: 14px;
      line-height: 1.6;
      white-space: pre-wrap;
    }
    .bot-chips {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }
    .bot-chip {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 20px;
      padding: 6px 14px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      color: #cbd5e1;
      transition: all 0.2s;
    }
    .bot-chip:hover {
      background: rgba(6, 182, 212, 0.15);
      border-color: var(--primary);
      color: #38bdf8;
    }
    .bot-input-row {
      display: flex;
      gap: 10px;
    }
    .bot-input-row input {
      flex: 1;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span class="brand-icon">🛡️</span>
      <div>
        <div class="brand-title">Privacy Protocol Simulator</div>
        <div class="brand-sub">Privacy-Preserving Multi-Agent Protocol • secp256k1 Stealth Addresses • Ephemeral ECDH • Pedersen Commitments • CDS ZK Range Proofs</div>
      </div>
    </div>
    <div class="status-pill">
      <div class="pulse-dot"></div>
      <span id="clusterStatusText">Cluster Online</span>
    </div>
  </header>

  <nav class="nav-tabs">
    <button class="tab-btn active" onclick="switchTab('tab-sim', this)">⚡ Attack Simulator</button>
    <button class="tab-btn" onclick="switchTab('tab-transfer', this)">💸 Transfer Studio</button>
    <button class="tab-btn" onclick="switchTab('tab-cluster', this)">👥 Cluster Nodes</button>
    <button class="tab-btn" onclick="switchTab('tab-lab', this)">🔬 Security & Crypto Lab</button>
    <button class="tab-btn" onclick="switchTab('tab-bot', this)">🤖 Protocol Assistant Bot</button>
  </nav>

  <main>
    <!-- TAB 1: PROTOCOL & ATTACK SIMULATOR -->
    <div id="tab-sim" class="tab-content active">
      <div class="card">
        <div class="card-title">⚡ Interactive Sequence Protocol & Attack Simulator</div>
        <p style="color: var(--text-dim); font-size: 14px; margin-bottom: 20px;">
          Select a targeted attack scenario, launch confidential transmission from <strong>Alice</strong> to <strong>Bob</strong>, 
          and visually observe how the adversary <strong>Eve</strong> intercepts in-flight on the wire but is mathematically blocked by zero-knowledge and cryptographic barriers!
        </p>

        <!-- Controls Form -->
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label">Sender Node</label>
            <select id="simSender">
              <option value="Alice">Alice (Sender)</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Destination Node</label>
            <select id="simReceiver">
              <option value="Bob">Bob (Destination)</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">In-Flight Adversary</label>
            <select id="simAttacker">
              <option value="Eve">Eve (Intercepting MitM)</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Attack Type</label>
            <select id="simAttackType">
              <option value="unmask_identity">1. 🕵️ Identity Sniffing (De-anonymization)</option>
              <option value="decrypt_payload">2. 🔓 Wiretap & Decrypt (AEAD Forward Secrecy)</option>
              <option value="steal_funds">3. 🔑 Private Key Theft (Spend Authority)</option>
              <option value="tamper_message">4. ✏️ In-Flight Tamper (Integrity Corruption)</option>
              <option value="replay_packet">5. 🔁 Replay Attack (Past Packet Replay)</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Transfer Amount (Units)</label>
            <input type="number" id="simAmount" value="500" min="1" max="5000" />
          </div>
        </div>

        <div class="form-group" style="margin-bottom: 20px;">
          <label class="form-label">Confidential Payload Note</label>
          <input type="text" id="simMemo" value="Mission Directive Alpha: Authorized Task Settlement" />
        </div>

        <div style="display: flex; gap: 14px; align-items: center; flex-wrap: wrap;">
          <button class="btn-transmit" id="btnRunAttack" onclick="triggerTargetedAttack()">
            ⚡ PING / TRANSMIT PACKET
          </button>
          <button class="btn btn-secondary" onclick="triggerFullMultiStageSim()">
            🚀 Run Comprehensive 4-Stage Audit
          </button>
          <button class="btn btn-secondary" onclick="resetSimulatorCanvas()">
            🔄 Reset Diagram & Log
          </button>
        </div>
      </div>

      <!-- VISUAL SEQUENCE DIAGRAM & COMMUNICATION LOG -->
      <div class="simulator-workspace">
        <!-- Center Lifelines Stage -->
        <div class="diagram-panel">
          <div class="lifelines-header">
            <div class="lifeline-pill node-alice-pill">🔵 Alice (Sender)</div>
            <div class="lifeline-pill node-eve-pill">🔴 Eve (Adversary MitM)</div>
            <div class="lifeline-pill node-bob-pill">🟢 Bob (Destination)</div>
          </div>

          <div class="lifelines-canvas" id="canvasContainer">
            <div class="lifeline-line line-alice"></div>
            <div class="lifeline-line line-eve"></div>
            <div class="lifeline-line line-bob"></div>

            <!-- Dynamic animated sequence message rows inserted here -->
            <div id="sequenceRows"></div>
          </div>
        </div>

        <!-- Right Column: Real-Time Timer & Communication Log -->
        <div class="log-panel">
          <div class="log-timer-box">
            <span style="font-size: 13px; font-weight: 700; color: var(--text-dim);">TIMING CLOCK</span>
            <span class="timer-val" id="timerDisplay">Timer: 00:00</span>
          </div>

          <div class="comm-log-title">Communication Log:</div>
          <ul class="comm-log-list" id="commLogList">
            <li><strong>1. SYSTEM @ 00:00:</strong> Nodes Alice, Eve, Bob synchronized. Ready for transmission.</li>
          </ul>
        </div>
      </div>

      <!-- CRISP CRYPTOGRAPHIC AUDIT CARDS -->
      <div class="card">
        <div class="card-title">📋 Cryptographic Ledger & Defense Audit</div>
        <p style="color: var(--text-dim); font-size: 13px; margin-bottom: 16px;">
          Mathematical audit proving sender deduction, recipient crediting, zero funds gained by attacker, and homomorphic validity.
        </p>

        <div class="audit-grid">
          <!-- Sender Audit -->
          <div class="audit-card">
            <div class="audit-header">
              <span class="audit-node-name" style="color: #38bdf8;">Alice (Sender)</span>
              <span class="audit-badge badge-verified">DEDUCTED</span>
            </div>
            <div class="audit-balance-line">Balance Settlement:</div>
            <div class="audit-balance-diff" style="color: #38bdf8;" id="auditAliceDiff">3000 units</div>
            <div class="crypto-field" id="auditAliceDetails">Pedersen Commitment: Verified Valid</div>
          </div>

          <!-- Attacker Audit -->
          <div class="audit-card attacker-audit">
            <div class="audit-header">
              <span class="audit-node-name" style="color: #f87171;">Eve (Attacker)</span>
              <span class="audit-badge badge-blocked">BLOCKED (0 GAINED)</span>
            </div>
            <div class="audit-balance-line">Balance Settlement:</div>
            <div class="audit-balance-diff" style="color: #f87171;" id="auditEveDiff">0 units (Unauthorized)</div>
            <div class="crypto-field" id="auditEveDetails">Defense: Confidentiality Intact</div>
          </div>

          <!-- Destination Audit -->
          <div class="audit-card">
            <div class="audit-header">
              <span class="audit-node-name" style="color: #34d399;">Bob (Destination)</span>
              <span class="audit-badge badge-verified">CREDITED</span>
            </div>
            <div class="audit-balance-line">Balance Settlement:</div>
            <div class="audit-balance-diff" style="color: #34d399;" id="auditBobDiff">500 units</div>
            <div class="crypto-field" id="auditBobDetails">Stealth Address: Scanned & Unlocked</div>
          </div>
        </div>

        <!-- Cryptographic Proof Inspector Bar -->
        <div style="margin-top: 16px; display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px;">
          <div class="crypto-field">
            <strong>One-Time Stealth PK:</strong> <span id="auditStealthPk">secp256k1 Point (Pending)</span>
          </div>
          <div class="crypto-field">
            <strong>Ephemeral ECDH Point (E_pk):</strong> <span id="auditEphemeralPk">Pending</span>
          </div>
          <div class="crypto-field">
            <strong>CDS ZK Range Proof:</strong> <span style="color: #34d399;">16-bit Disjunctive [0, 2^16) Valid</span>
          </div>
          <div class="crypto-field">
            <strong>Cluster Merkle Root:</strong> <span id="auditMerkleRoot">Loading...</span>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: TRANSFER STUDIO -->
    <div id="tab-transfer" class="tab-content">
      <div class="card">
        <div class="card-title">💸 Direct Confidential P2P Transfer Studio</div>
        <p style="color: var(--text-dim); font-size: 14px; margin-bottom: 20px;">
          Execute live stealth transfers over actual TCP sockets between registered nodes in the cluster.
        </p>
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label">Sender</label>
            <select id="transferSender"></select>
          </div>
          <div class="form-group">
            <label class="form-label">Receiver</label>
            <select id="transferReceiver"></select>
          </div>
          <div class="form-group">
            <label class="form-label">Amount</label>
            <input type="number" id="transferAmount" value="250" />
          </div>
          <div class="form-group">
            <label class="form-label">Confidential Memo</label>
            <input type="text" id="transferMessage" placeholder="Optional memo" value="Direct Socket Settlement" />
          </div>
        </div>
        <button class="btn" onclick="sendDirectTransfer()">⚡ Execute Socket Transfer</button>
      </div>

      <div class="card">
        <div class="card-title">📜 Wire Transaction History</div>
        <div id="txHistoryContainer" style="font-size: 13px;">No transactions yet.</div>
      </div>
    </div>

    <!-- TAB 3: CLUSTER MANAGEMENT -->
    <div id="tab-cluster" class="tab-content">
      <div class="card">
        <div class="card-title">👥 Active Cluster Agents</div>
        <p style="color: var(--text-dim); font-size: 14px; margin-bottom: 16px;">
          Nodes authorized within the cluster Merkle tree participate in anonymous ring authentication and stealth transactions.
        </p>
        <div class="agent-grid" id="clusterAgentsGrid"></div>
      </div>

      <div class="card">
        <div class="card-title">➕ Spawn New Cluster Agent</div>
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label">Agent Name</label>
            <input type="text" id="newAgentName" placeholder="e.g. Charlie" />
          </div>
          <div class="form-group">
            <label class="form-label">Initial Balance</label>
            <input type="number" id="newAgentBalance" value="1000" />
          </div>
          <div class="form-group">
            <label class="form-label">TCP Port</label>
            <input type="number" id="newAgentPort" value="9004" />
          </div>
        </div>
        <button class="btn" onclick="createNewAgent()">Create & Launch Node</button>
      </div>
    </div>

    <!-- TAB 4: SECURITY & CRYPTO LAB -->
    <div id="tab-lab" class="tab-content">
      <div class="card">
        <div class="card-title">🔬 Security & Cryptographic Verification Lab</div>
        <p style="color: var(--text-dim); font-size: 14px; margin-bottom: 20px;">
          Test low-level cryptographic defenses against replay attacks and verify Spontaneous Anonymous Group (SAG) Ring Signatures.
        </p>
        <div style="display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px;">
          <button class="btn btn-secondary" onclick="testReplayAttack()">🔁 Test Replay Attack on Captured Wire Packet</button>
          <button class="btn btn-secondary" onclick="testRingAuth()">⭕ Test Anonymous Ring Signature Auth</button>
        </div>
        <div id="labResultBox" style="display: none;" class="card">
          <div class="card-title" id="labResultTitle"></div>
          <p id="labResultText" style="font-size: 13px; margin-top: 6px;"></p>
        </div>
      </div>

      <div class="card">
        <div class="card-title">📟 Live Cryptographic Protocol Logs</div>
        <div class="log-terminal" id="liveLogs"></div>
      </div>
    </div>

    <!-- TAB 5: PROTOCOL ASSISTANT BOT -->
    <div id="tab-bot" class="tab-content">
      <div class="card">
        <div class="card-title">🤖 Protocol Assistant Bot</div>
        <p style="color: var(--text-dim); font-size: 14px; margin-bottom: 16px;">
          Ask questions about Topic 9 cryptography, zero-knowledge range proofs, homomorphic Pedersen commitments, or attack defenses.
        </p>

        <div class="bot-chips">
          <button class="bot-chip" onclick="askBotPrompt('Why was Eve blocked from getting the data?')">Why was Eve blocked?</button>
          <button class="bot-chip" onclick="askBotPrompt('How do One-Time Stealth Addresses work?')">How do Stealth Addresses work?</button>
          <button class="bot-chip" onclick="askBotPrompt('Explain Pedersen Commitments and homomorphic balance')">Explain Pedersen Commitments</button>
          <button class="bot-chip" onclick="askBotPrompt('What is a CDS 1-of-2 ZK Range Proof?')">Explain ZK Range Proofs</button>
          <button class="bot-chip" onclick="askBotPrompt('What is Anonymous Ring Authentication?')">Explain Ring Signatures</button>
          <button class="bot-chip" onclick="askBotPrompt('What are the current cluster balances?')">Current Cluster State</button>
        </div>

        <div class="bot-window" id="botChatWindow">🤖 Hello! I am your Topic 9 Protocol Assistant Bot. Click a question above or type below to learn how our multi-agent protocol defends against attacks!</div>

        <div class="bot-input-row">
          <input type="text" id="botTextInput" placeholder="Ask about stealth addresses, ECDH, Pedersen commitments, or attacks..." onkeydown="if(event.key==='Enter') submitBotQuery()" />
          <button class="btn" onclick="submitBotQuery()">Send Question</button>
        </div>
      </div>
    </div>
  </main>

  <script>
    let currentState = null;
    let timerSeconds = 0;
    let timerInterval = null;
    let seqCounter = 0;

    function switchTab(tabId, el) {
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      const target = document.getElementById(tabId);
      if (target) target.classList.add('active');
      if (el) el.classList.add('active');
    }

    function formatClock(sec) {
      const m = String(Math.floor(sec / 60)).padStart(2, '0');
      const s = String(sec % 60).padStart(2, '0');
      return `${m}:${s}`;
    }

    function startTimerIfNeeded() {
      if (!timerInterval) {
        timerInterval = setInterval(() => {
          timerSeconds++;
          document.getElementById('timerDisplay').textContent = `Timer: ${formatClock(timerSeconds)}`;
        }, 1000);
      }
    }

    function appendCommLog(text, logType = 'normal') {
      const list = document.getElementById('commLogList');
      const li = document.createElement('li');
      if (logType === 'blocked') li.className = 'log-blocked';
      else if (logType === 'success') li.className = 'log-success';
      const num = list.children.length + 1;
      li.innerHTML = `<strong>${num}.</strong> ${text} <span style="opacity: 0.7;">@ ${formatClock(timerSeconds)}</span>`;
      list.appendChild(li);
      list.scrollTop = list.scrollHeight;
    }

    function resetSimulatorCanvas() {
      document.getElementById('sequenceRows').innerHTML = '';
      document.getElementById('commLogList').innerHTML = `<li><strong>1. SYSTEM @ 00:00:</strong> Diagram reset. Ready for transmission.</li>`;
      timerSeconds = 0;
      document.getElementById('timerDisplay').textContent = 'Timer: 00:00';
      if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
      }
    }

    async function fetchState() {
      try {
        const res = await fetch('/api/state');
        currentState = await res.json();
        updateUI();
      } catch (err) {
        console.error("State poll error:", err);
      }
    }

    function updateUI() {
      if (!currentState) return;

      // Status pill
      const pill = document.getElementById('clusterStatusText');
      if (pill) {
        pill.textContent = `${currentState.agents.length} Nodes Active | Root: ${currentState.merkle_root.slice(0, 12)}...`;
      }

      // Populate Selects
      const simSender = document.getElementById('simSender');
      const simReceiver = document.getElementById('simReceiver');
      const simAttacker = document.getElementById('simAttacker');
      const transferSender = document.getElementById('transferSender');
      const transferReceiver = document.getElementById('transferReceiver');

      const agents = currentState.agents;
      const populate = (sel, filterFn, defVal) => {
        if (!sel) return;
        const prev = sel.value;
        sel.innerHTML = '';
        agents.filter(filterFn).forEach(a => {
          const opt = document.createElement('option');
          opt.value = a.name;
          opt.textContent = `${a.name} (Bal: ${a.balance})`;
          sel.appendChild(opt);
        });
        if (prev && sel.querySelector(`option[value="${prev}"]`)) {
          sel.value = prev;
        } else if (defVal) {
          sel.value = defVal;
        }
      };

      populate(simSender, a => a.name !== 'Eve', 'Alice');
      populate(simReceiver, a => a.name !== 'Eve', 'Bob');
      populate(simAttacker, a => a.name === 'Eve' || a.name.toLowerCase().includes('eve'), 'Eve');
      populate(transferSender, () => true, 'Alice');
      populate(transferReceiver, () => true, 'Bob');

      // Cluster Grid
      const clusterGrid = document.getElementById('clusterAgentsGrid');
      if (clusterGrid) {
        clusterGrid.innerHTML = '';
        agents.forEach(a => {
          const isAttacker = a.name === 'Eve';
          const card = document.createElement('div');
          card.className = `agent-card ${isAttacker ? 'attacker' : ''}`;
          card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
              <strong style="font-size: 16px;">${a.name}</strong>
              <span class="audit-badge ${isAttacker ? 'badge-blocked' : 'badge-verified'}">${isAttacker ? 'Adversary' : 'Cluster Node'}</span>
            </div>
            <div style="font-size: 13px; color: var(--text-dim); margin-bottom: 6px;">Socket: <code>${a.endpoint}</code></div>
            <div style="font-size: 18px; font-weight: 700; color: #34d399; margin-bottom: 8px;">
              ${a.balance} <span style="font-size: 12px; color: var(--text-dim);">units (Pedersen Verified)</span>
            </div>
            <div class="crypto-field" style="font-size: 11px;">PK: ${a.pk}</div>
          `;
          clusterGrid.appendChild(card);
        });
      }

      // Logs
      const logsBox = document.getElementById('liveLogs');
      if (logsBox && currentState.recent_logs) {
        logsBox.innerHTML = currentState.recent_logs.map(l => `<div>[${l.time_str}] [${l.category}] ${l.message}</div>`).join('');
        logsBox.scrollTop = logsBox.scrollHeight;
      }

      // History
      const histBox = document.getElementById('txHistoryContainer');
      if (histBox && currentState.recent_transactions) {
        if (currentState.recent_transactions.length === 0) {
          histBox.innerHTML = '<span style="color: var(--text-dim)">No transactions yet.</span>';
        } else {
          histBox.innerHTML = currentState.recent_transactions.map(tx => `
            <div class="audit-card" style="margin-bottom: 8px;">
              <div style="display: flex; justify-content: space-between;">
                <strong>${tx.sender} ➔ ${tx.receiver} : ${tx.amount} units</strong>
                <span style="color: var(--text-dim);">${tx.time_str}</span>
              </div>
              <div class="crypto-field">Hash: ${tx.tx_hash}</div>
              <div class="crypto-field">Stealth PK: ${tx.stealth_pk}</div>
            </div>
          `).join('');
        }
      }

      // Audit info
      const aNode = agents.find(x => x.name === 'Alice');
      const bNode = agents.find(x => x.name === 'Bob');
      const eNode = agents.find(x => x.name === 'Eve');
      if (aNode) document.getElementById('auditAliceDiff').textContent = aNode.balance + ' units';
      if (bNode) document.getElementById('auditBobDiff').textContent = bNode.balance + ' units';
      if (eNode) document.getElementById('auditEveDiff').textContent = eNode.balance + ' units (0 gained)';
      if (currentState.merkle_root) document.getElementById('auditMerkleRoot').textContent = currentState.merkle_root.slice(0, 16) + '...';
    }

    // 1. TARGETED ATTACK SIMULATION (Visual Lifeline Arrows + Real-time Animation)
    async function triggerTargetedAttack() {
      const btn = document.getElementById('btnRunAttack');
      btn.disabled = true;

      const sender = document.getElementById('simSender').value;
      const receiver = document.getElementById('simReceiver').value;
      const amount = parseInt(document.getElementById('simAmount').value, 10) || 500;
      const attackType = document.getElementById('simAttackType').value;
      const memo = document.getElementById('simMemo').value || 'Mission Directive';

      startTimerIfNeeded();
      seqCounter++;
      const pId = seqCounter;
      const container = document.getElementById('sequenceRows');

      // STAGE 1: Alice -> Eve Wire Transmission
      const r1 = document.createElement('div');
      r1.className = 'seq-row';
      r1.innerHTML = `
        <div class="seq-label" style="left: 17%; color: #38bdf8;">PING_${pId}: (P_stealth + Encrypted C)</div>
        <div class="seq-arrow" style="left: 16%; width: 34%;"></div>
      `;
      container.appendChild(r1);
      appendCommLog(`PING_${pId}: Alice transmitted stealth packet (Amount: ${amount}) across TCP wire.`);

      try {
        const res = await fetch('/api/attack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            sender: sender,
            receiver: receiver,
            amount: amount,
            message: memo,
            attack_type: attackType
          })
        });
        const data = await res.json();
        if (data.error) {
          alert('Attack Simulation Error: ' + data.error);
          btn.disabled = false;
          return;
        }

        // STAGE 2: Eve Interception & Defense Block
        setTimeout(() => {
          const r2 = document.createElement('div');
          r2.className = 'seq-row';
          r2.innerHTML = `
            <div class="seq-label" style="left: 45%; color: #f87171;">ATTACK_${pId}: ${data.attack.title}</div>
            <div class="seq-arrow blocked-arrow" style="left: 48%; width: 4%;">
              <span class="blocked-badge-mark">BLOCKED!</span>
            </div>
          `;
          container.appendChild(r2);
          appendCommLog(`ATTACK_${pId}: Eve intercepted wire packet. Attempted: ${data.attack.title} ───> BLOCKED! (${data.attack.defense})`, 'blocked');

          // STAGE 3: Secure Delivery to Bob
          setTimeout(() => {
            const r3 = document.createElement('div');
            r3.className = 'seq-row';
            r3.innerHTML = `
              <div class="seq-label" style="left: 54%; color: #34d399;">DELIVER_${pId}: Verified Recipient</div>
              <div class="seq-arrow deliver-arrow" style="left: 50%; width: 34%;"></div>
            `;
            container.appendChild(r3);
            appendCommLog(`DELIVER_${pId}: Bob scanned stealth key with private scalar & unlocked message: "${data.destination.received_message}"`, 'success');

            // STAGE 4: Return Acknowledgment & Settlement
            setTimeout(() => {
              const r4 = document.createElement('div');
              r4.className = 'seq-row';
              r4.innerHTML = `
                <div class="seq-label" style="left: 40%; color: #c084fc;">PONG_${pId}: Homomorphic Balance Settled</div>
                <div class="seq-arrow settle-arrow" style="left: 16%; width: 68%;"></div>
              `;
              container.appendChild(r4);
              appendCommLog(`PONG_${pId}: Settlement complete: Bob (+${amount}), Alice (-${amount}), Eve (0 gained).`, 'success');

              // Update Audit Cards
              document.getElementById('auditStealthPk').textContent = data.stealth_address_short;
              document.getElementById('auditEphemeralPk').textContent = "e*G Derived on secp256k1";
              document.getElementById('auditAliceDiff').textContent = `${data.balances.sender.after} units (${data.balances.sender.delta})`;
              document.getElementById('auditBobDiff').textContent = `${data.balances.receiver.after} units (${data.balances.receiver.delta})`;
              document.getElementById('auditEveDiff').textContent = `${data.balances.attacker.after} units (${data.balances.attacker.delta || '0 gained'})`;
              document.getElementById('auditEveDetails').textContent = `Eve Blocked: ${data.attack.defense}`;

              btn.disabled = false;
              fetchState();
            }, 550);
          }, 550);
        }, 550);

      } catch (err) {
        alert('Transmission failed: ' + err);
        btn.disabled = false;
      }
    }

    // 2. FULL 4-STAGE AUDIT SIMULATION
    async function triggerFullMultiStageSim() {
      const sender = document.getElementById('simSender').value;
      const receiver = document.getElementById('simReceiver').value;
      const attacker = document.getElementById('simAttacker').value;
      const amount = parseInt(document.getElementById('simAmount').value, 10) || 500;
      const memo = document.getElementById('simMemo').value || 'Autonomous Agent Task Settlement Alpha-1';

      startTimerIfNeeded();
      appendCommLog(`[AUDIT]: Running comprehensive 4-stage intrusion verification...`);

      try {
        const res = await fetch('/api/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sender, receiver, attacker, amount, message: memo })
        });
        const data = await res.json();
        if (data.error) {
          alert('Error: ' + data.error);
          return;
        }

        appendCommLog(`Stage 1 (Sender): Derived P_stealth, C_transfer, and 16-bit CDS ZK range proof.`, 'success');
        data.phase_2_attacker.attacks.forEach(att => {
          appendCommLog(`Stage 2 (Eve Attempt): ${att.attack_name} ───> BLOCKED (${att.details})`, 'blocked');
        });
        appendCommLog(`Stage 3 (Destination): Bob verified proof and decrypted payload: "${data.phase_3_destination.decrypted_message}"`, 'success');
        appendCommLog(`Stage 4 (Audit): Balances updated. Attacker funds unchanged.`, 'success');

        document.getElementById('auditStealthPk').textContent = data.phase_1_sender.one_time_stealth_pk;
        document.getElementById('auditEphemeralPk').textContent = data.phase_1_sender.ephemeral_pk;
        document.getElementById('auditAliceDiff').textContent = `${data.phase_4_audit.sender.after} units (${data.phase_4_audit.sender.delta})`;
        document.getElementById('auditBobDiff').textContent = `${data.phase_4_audit.receiver.after} units (${data.phase_4_audit.receiver.delta})`;
        document.getElementById('auditEveDiff').textContent = `${data.phase_4_audit.attacker.after} units (0 gained)`;
        fetchState();
      } catch (err) {
        alert('Simulation execution failed: ' + err);
      }
    }

    // Direct Transfer
    async function sendDirectTransfer() {
      const payload = {
        sender: document.getElementById('transferSender').value,
        receiver: document.getElementById('transferReceiver').value,
        amount: parseInt(document.getElementById('transferAmount').value, 10),
        message: document.getElementById('transferMessage').value,
      };
      const res = await fetch('/api/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (data.error) alert('Error: ' + data.error);
      else {
        alert(`Transfer Succeeded! Tx Hash: ${data.tx_hash.slice(0, 16)}...`);
        fetchState();
      }
    }

    // Create Agent
    async function createNewAgent() {
      const name = document.getElementById('newAgentName').value.trim();
      const balance = parseInt(document.getElementById('newAgentBalance').value, 10);
      const port = parseInt(document.getElementById('newAgentPort').value, 10);
      if (!name || isNaN(balance) || isNaN(port)) {
        alert('Please fill out all fields.');
        return;
      }
      const res = await fetch('/api/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, balance, port }),
      });
      const data = await res.json();
      if (data.error) alert('Error: ' + data.error);
      else {
        alert(`Agent ${name} started on port ${port}!`);
        fetchState();
      }
    }

    // Replay Attack Test
    async function testReplayAttack() {
      if (!currentState.recent_transactions.length) {
        alert('Run a transaction or simulation first to produce a captured wire packet!');
        return;
      }
      const lastTx = currentState.recent_transactions[0];
      const res = await fetch('/api/replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: 'Bob', payload_hex: lastTx.raw_payload_hex }),
      });
      const data = await res.json();
      const box = document.getElementById('labResultBox');
      box.style.display = 'block';
      document.getElementById('labResultTitle').innerHTML = `🔁 Replay Attack Result: <span style="color: #ef4444;">${data.defense_status}</span>`;
      document.getElementById('labResultText').textContent = data.details;
      fetchState();
    }

    // Anonymous Ring Signature Test
    async function testRingAuth() {
      const res = await fetch('/api/ring-auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ signer: 'Alice', challenge: 'cluster-session-auth' }),
      });
      const data = await res.json();
      const box = document.getElementById('labResultBox');
      box.style.display = 'block';
      document.getElementById('labResultTitle').innerHTML = `⭕ Anonymous Ring Auth: <span style="color: #10b981;">VERIFIED (${data.signature_valid})</span>`;
      document.getElementById('labResultText').textContent = `${data.explanation} | Cluster Signers: ${data.cluster_ring_size}`;
      fetchState();
    }

    // Protocol Assistant Bot
    async function submitBotQuery() {
      const input = document.getElementById('botTextInput');
      const query = input.value.trim();
      if (!query) return;
      input.value = '';

      const win = document.getElementById('botChatWindow');
      win.textContent += `\\n\\n👤 You: ${query}\\n`;

      try {
        const res = await fetch('/api/bot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query })
        });
        const data = await res.json();
        win.textContent += `\\n🤖 Bot: ${data.answer}`;
        win.scrollTop = win.scrollHeight;
      } catch (err) {
        win.textContent += `\\n🤖 Bot: Error communicating with assistant.`;
      }
    }

    function askBotPrompt(text) {
      document.getElementById('botTextInput').value = text;
      submitBotQuery();
    }

    // Initialize
    fetchState();
    setInterval(fetchState, 3000);
  </script>
</body>
</html>
"""

class ProtocolHTTPHandler(BaseHTTPRequestHandler):
    def address_string(self):
        # FAST: Disables reverse DNS lookup which causes multi-second hangs in WSL/Windows
        return self.client_address[0]

    def log_message(self, format, *args):
        # Quick non-blocking log
        pass

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
        self.end_headers()

    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        elif parsed.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        session, loop = get_session()
        if parsed.path == "/api/state":
            state = session.get_state()
            self._send_json(state)
        elif parsed.path == "/api/logs":
            self._send_json({"logs": session.logs})
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        session, loop = get_session()
        parsed = urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len)
        try:
            req_data = json.loads(post_body.decode("utf-8")) if post_body else {}
        except Exception:
            req_data = {}

        try:
            if parsed.path == "/api/bot":
                query = req_data.get("query", "")
                ans = answer_bot_query(query, session)
                self._send_json({"answer": ans})

            elif parsed.path == "/api/attack":
                sender = req_data.get("sender", "Alice")
                receiver = req_data.get("receiver", "Bob")
                amount = int(req_data.get("amount", 500))
                message = req_data.get("message", "Mission Directive")
                attack_type = req_data.get("attack_type", "unmask_identity")
                fut = asyncio.run_coroutine_threadsafe(
                    session.execute_targeted_attack(sender, receiver, amount, message, attack_type), loop
                )
                res = fut.result(timeout=10)
                self._send_json(res)

            elif parsed.path == "/api/simulate":
                sender = req_data.get("sender", "Alice")
                receiver = req_data.get("receiver", "Bob")
                attacker = req_data.get("attacker", "Eve")
                amount = int(req_data.get("amount", 500))
                message = req_data.get("message", "")
                fut = asyncio.run_coroutine_threadsafe(
                    session.simulate_attack_transfer(sender, receiver, amount, message, attacker), loop
                )
                res = fut.result(timeout=10)
                self._send_json(res)

            elif parsed.path == "/api/transfer":
                sender = req_data.get("sender", "Alice")
                receiver = req_data.get("receiver", "Bob")
                amount = int(req_data.get("amount", 250))
                message = req_data.get("message", "")
                fut = asyncio.run_coroutine_threadsafe(
                    session.send_transfer(sender, receiver, amount, message), loop
                )
                res = fut.result(timeout=10)
                self._send_json(res)

            elif parsed.path == "/api/agents":
                name = req_data["name"]
                balance = int(req_data["balance"])
                port = int(req_data["port"])
                fut = asyncio.run_coroutine_threadsafe(
                    session.add_agent(name, balance, port), loop
                )
                res = fut.result(timeout=10)
                self._send_json(res)

            elif parsed.path == "/api/replay":
                target = req_data.get("target", "Bob")
                payload_hex = req_data.get("payload_hex", "")
                fut = asyncio.run_coroutine_threadsafe(
                    session.test_replay_attack(target, payload_hex), loop
                )
                res = fut.result(timeout=10)
                self._send_json(res)

            elif parsed.path == "/api/ring-auth":
                signer = req_data.get("signer", "Alice")
                challenge = req_data.get("challenge", "cluster-session-auth")
                res = session.test_anonymous_ring_auth(signer, challenge)
                self._send_json(res)

            else:
                self.send_error(404, "Not Found")
        except Exception as e:
            self._send_json({"error": str(e)}, status=400)

def run_server(port: int = 8000, host: str = "0.0.0.0"):
    session, loop = get_session()
    
    ports_to_try = [port, 8080, 8001, 8888, 5000]
    httpd = None
    actual_port = port

    for p in ports_to_try:
        try:
            server_address = (host, p)
            httpd = ThreadingHTTPServer(server_address, ProtocolHTTPHandler)
            actual_port = p
            break
        except OSError:
            continue

    if httpd is None:
        raise OSError(f"Could not bind HTTP server on any port in {ports_to_try}")

    print("==================================================================")
    print("  🛡️  Privacy Protocol Simulator Running!")
    print(f"  🔗  Local URL:        http://localhost:{actual_port}")
    print(f"  🔗  Network Address:  http://127.0.0.1:{actual_port}")
    print("==================================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down web server...")
    finally:
        asyncio.run_coroutine_threadsafe(session.stop(), loop).result()

if __name__ == "__main__":
    import sys
    port = 8000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_server(port)
