"""Grounded local protocol question answering; optional local Ollama model.

No remote AI calls. Current-session answers are computed from live session state;
concept explanations are retrieved from a reviewed, implementation-specific index.
"""
from __future__ import annotations

import json
import os
import re
from urllib.request import Request, urlopen

ARTICLES = [
    ('overview system protocol purpose architecture project design multi agent',
     'This is a loopback-only research demonstration of authenticated agent-to-agent messaging and six isolated attack-defense experiments. The Python backend owns cryptographic checks; the browser visualizes reported outcomes.'),
    ('add create register identity agent nodes directory trust approval new',
     'The local administrator registers approved agents and pins their Ed25519 signing and X25519 encryption public keys with other approved agents. Eve is untrusted. New registration does not establish trust independently of this localhost demo.'),
    ('send delivery transport recipient sender tcp network socket envelope workflow',
     'Send an approved-agent message in Communication & Attack Simulator. The sender encrypts and signs a packet, sends it over loopback TCP, and verifies the recipient-signed delivery receipt before reporting delivery. Inbox access is available to any user of this local dashboard.'),
    ('ciphertext encryption aes gcm confidentiality authentication nonce iv key derivation ephemeral',
     'Each message uses a fresh ephemeral X25519 sender key with the recipient’s static X25519 key, HKDF-SHA256, and AES-256-GCM authenticated encryption. The public nonce and ciphertext can be inspected in the audit; the derived AES key and private keys must never be logged.'),
    ('sign signature identity spoof impersonation forged tamper integrity ed25519 pinned',
     'Ed25519 signatures authenticate a packet against the claimed sender’s pinned public signing key. Editing signed bytes or pretending to be a trusted agent with the wrong key causes signature verification to fail.'),
    ('replay nonce duplicate message id timestamp stale cache window',
     'The receiving agent checks message IDs and timestamps and rejects a previously accepted ID. Its replay cache is in memory; a process restart clears that history. The replay experiment resends the identical signed packet.'),
    ('decryption unauthorized eavesdrop intercepted private key adversary eve',
     'An interceptor can obtain the public envelope but cannot decrypt its AES-256-GCM ciphertext without the intended recipient’s private agreement key. The experiment tries Eve’s wrong key and observes an authentication failure.'),
    ('size oversized bytes frames limits flood denial of service rate speed queue',
     'Message bodies are limited to 4,096 UTF-8 bytes; TCP frames are capped at 16 KiB. Recipients use a per-sender sliding rate limit of six accepted messages in a two-second window. These controls do not constitute comprehensive distributed-DoS protection.'),
    ('attack simulation experiment test comparison vulnerable safe real security reenact original',
     'The six experiments are tampering, replay, impersonation, unauthorized decryption, oversized packets and flooding. Each runs with isolated temporary cryptographic identities and reenacts the selected message; it does not modify the original delivered packet. Vulnerable mode is a hypothetical comparison, not disabled live protection.'),
    ('audit logs trace history events evidence inspect export json csv ciphertext public keys fingerprints status error',
     'The Security Audit displays this server run’s agent registrations, message encryption evidence, signed receipt verification, attack steps and rejection codes. JSON/CSV export excludes plaintext. Only public cryptographic metadata is logged; private keys and shared secrets are excluded.'),
    ('topology graph diagram node drag placement position sender receiver visual',
     'The topology displays all registered agents. Drag nodes or click to place a newly registered agent; positions are saved in this browser’s local storage. Communication and attack experiments highlight selected source, recipient and Eve on the same full network.'),
    ('privacy anonymity metadata unlinkability traffic analysis forward secrecy production risk limitations',
     'This demo is not anonymous: agent names, endpoints and message timing can be observed. Static recipient agreement keys do not provide full forward secrecy. The dashboard has no user login and is safe only as a localhost research demonstration, not a production messaging service.'),
    ('algorithm cryptographic parameters cryptography key exchange digest hkdf hash aes ed',
     'The implementation uses Ed25519 for message and receipt signatures, X25519 for agreement, HKDF-SHA256 for key derivation and AES-256-GCM for authenticated encryption. No cryptocurrency balances, payments or transfers are part of this project.'),
]
STOP = set('what which who why how where when does do did is are the a an of and for to in my our this that with tell show give explain please me about on can from it your have has there'.split())

def _terms(text: str) -> set[str]:
    words = re.findall(r'[a-z0-9_]+', text.lower())
    return {w[:-1] if len(w) > 4 and w.endswith('s') else w for w in words if len(w) > 2 and w not in STOP}


def _live_answer(question: str, session) -> str | None:
    q = question.lower()
    tokens = _terms(q)
    metric = session.agents
    trusted = [name for name, rec in metric.items() if rec.approved]
    messages = list(session.message_records.values())
    exps = session.experiments
    if any(k in tokens for k in {'count','many','number','total','statistic','metric','status','overview','current'}) or re.search(r'\bhow many\b',q):
        if any(k in tokens for k in {'agent','node','trusted','registered','peer'}):
            return f'There are {len(trusted)} trusted agents ({", ".join(trusted) or "none"}) and {len(metric)-len(trusted)} untrusted agents in this server session.'
        if any(k in tokens for k in {'message','delivery','delivered','sent'}):
            return f'This server session has {len(messages)} retained delivered message records and {sum(len(r.agent.inbox) for r in metric.values())} recipient inbox deliveries.'
        if any(k in tokens for k in {'attack','experiment','blocked','defense'}):
            count = sum(x.get('actual_blocked',False) for x in exps)
            return f'{len(exps)} security experiments have run this session. {count} produced a rejection by actual Python checks. Hypothetical comparison runs are labeled separately.'
        return f'Current session: {len(trusted)} trusted agents, {len(messages)} retained messages, {len(exps)} experiments and {len(session.audit_entries)} audit events.'
    if re.search(r'\b(list|name|who|which)\b',q) and any(k in tokens for k in {'agent','node','peer','registered','trusted'}):
        return ('Approved agents: ' + (', '.join(trusted) or 'none') + '. Untrusted: ' + (', '.join(x for x in metric if x not in trusted) or 'none') + '. Agent names do not by themselves prove identity; public signing keys are pinned.')
    if any(k in tokens for k in {'failure','fail','failed','reject','error','verdict','blocked','reason'}) and any(k in tokens for k in {'attack','last','latest','experiment'}):
        if not exps: return 'There is no experiment result to inspect yet. Run an attack against a message first.'
        x = exps[-1]
        return f'Last attack {x["label"]}: the Python library observed {x["observed_status"]}. Defense: {x["defense"]}. Reported result: {x["verdict"]}. View its per-stage checks in the audit inspector.'
    if any(k in tokens for k in {'latest','last','recent','newest'}) and any(k in tokens for k in {'attack','experiment','defense'}):
        if not exps: return 'No attacks have been tested since this server started. Select a delivered message in Communication & Attack Simulator and run an experiment.'
        x = exps[-1]
        return f'Latest experiment: {x["label"]} targeting {x.get("sender")} → {x.get("recipient")}; observed {x["observed_status"]}; result {x["verdict"]}. The detailed stages are available in the Security Audit.'
    if any(k in tokens for k in {'latest','last','recent','newest'}) and any(k in tokens for k in {'message','delivery','sent','receive'}):
        if not messages: return 'No messages have been delivered in this server session yet.'
        x = messages[-1]['summary']
        return f'Latest delivered message: {x["id"]}, {x["sender"]} → {x["recipient"]}, status {x["status"]}, serialized size {x["bytes"]} bytes. Message plaintext is not included in the assistant answer.'
    if 'audit' in tokens and any(k in tokens for k in {'count','many','total'}):
        return f'There are {len(session.audit_entries)} audit events in this server run. They include identity registrations, message operations and experiments. Exports omit plaintext and secrets.'
    return None


def _retrieve(question: str) -> list[str]:
    q = _terms(question)
    matches = []
    for index, (keywords, paragraph) in enumerate(ARTICLES):
        key_terms = _terms(keywords)
        body_terms = _terms(paragraph)
        score = 4 * len(q & key_terms) + len(q & body_terms)
        if score:
            matches.append((score,index,paragraph))
    matches.sort(key=lambda x:(-x[0],x[1]))
    if not matches: return []
    top = matches[0][0]
    return [paragraph for score,_,paragraph in matches if score >= max(2, top*.45)][:3]


def _local_model(question: str, evidence: str) -> str | None:
    # Opt in explicitly: MULTIAGENT_OLLAMA_MODEL=llama3.2 (already pulled locally).
    # No request ever leaves loopback. Server remains usable without Ollama.
    model = os.environ.get('MULTIAGENT_OLLAMA_MODEL','').strip()
    if not model: return None
    if not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,100}',model): return None
    instruction = ('Answer the user about THIS localhost multi-agent project. Use only the evidence supplied below. '
                   'If the evidence does not support the question, explicitly say it cannot be confirmed. '
                   'Never fabricate log events, keys, attacks or results. Never reveal secret keys or plaintext. '
                   'Be concise and helpful.\nEvidence:\n'+evidence+'\nQuestion: '+question)
    payload = json.dumps({'model':model,'prompt':instruction,'stream':False,'options':{'temperature':0.1,'num_predict':260}}).encode('utf-8')
    request = Request('http://127.0.0.1:11434/api/generate',payload,{'Content-Type':'application/json'},method='POST')
    try:
        with urlopen(request,timeout=7) as response:
            data = json.loads(response.read(24_000))
        answer = data.get('response','').strip()
        return answer[:3000] if answer else None
    except (OSError, ValueError, KeyError):
        return None


def answer(question: str, session) -> dict:
    live = _live_answer(question,session)
    passages = _retrieve(question)
    evidence = ('Current trusted agents: '+', '.join(n for n,r in session.agents.items() if r.approved)
        +'; current audit events: '+str(len(session.audit_entries))+'; delivered message records: '
        +str(len(session.message_records))+'; experiments: '+str(len(session.experiments))+'\n'
        +(live+'\n' if live else '')+'\n'.join(passages))
    model_result = _local_model(question,evidence)
    if model_result:
        return {'answer':model_result,'mode':'optional-local-ollama','sources':['current session','reviewed protocol explanations']}
    if live:
        return {'answer':live,'mode':'live-session-data','sources':['current session']}
    if passages:
        return {'answer':'\n\n'.join(passages),'mode':'retrieved-local-knowledge','sources':['reviewed implementation-specific explanations']}
    return {'answer':('I could not find verified information about that question in this project. '
                       'You can ask about the implemented protocol, current agents, message delivery, the last attack, '
                       'cryptographic details, audit records or the project’s limitations. '
                       'For broader natural-language answers, optionally run a local Ollama model.'),
            'mode':'out-of-scope','sources':[]}
