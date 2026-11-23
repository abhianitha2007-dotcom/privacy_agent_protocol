"""Local-only multi-agent secure-messaging laboratory.

Security scenarios run in isolated temporary agents, rather than mutating the live
inboxes or disabling any live cryptographic checks. This is a demonstration of
actual library checks, not a deployable anonymous or distributed identity system.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag

from .agent.agent import PrivacyAgent
from .crypto.secure_message import MAX_MESSAGE_BYTES, decrypt_message
from .network.cluster import ClusterManager
from .network.node import AsyncPeerNode
from .network.serializer import NetworkSerializer

ATTACK_NAMES = {
    'tamper': 'Ciphertext tampering',
    'replay': 'Replay injection',
    'impersonation': 'Identity impersonation',
    'decryption': 'Unauthorized decryption',
    'oversized': 'Oversized packet',
    'flood': 'Message flood / rate limit',
}

DEFENSE_NAMES = {
    'tamper': 'Ed25519 signature + AES-GCM authentication',
    'replay': 'Message-ID replay cache + timestamp window',
    'impersonation': 'Pinned sender signing identity',
    'decryption': 'X25519 recipient key + AES-256-GCM',
    'oversized': 'Message and TCP frame-size limits',
    'flood': 'Per-sender sliding-window rate limit',
}


@dataclass
class AgentRecord:
    agent: PrivacyAgent
    node: AsyncPeerNode
    approved: bool


class ProtocolSession:
    def __init__(self, audit_path: Path | None = None) -> None:
        self.agents: dict[str, AgentRecord] = {}
        self.cluster = ClusterManager()
        self.events: list[dict] = []
        self.experiments: list[dict] = []
        # Local demo trace storage is intentionally in-memory and capped. The
        # packet and plaintext are used only to reenact a user-selected message
        # under isolated test keys; they never appear in the normal audit API.
        self.message_records: dict[str, dict] = {}
        self.audit_entries: list[dict] = []
        self.audit_path = audit_path
        if self.audit_path is not None:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Restore complete audit metadata, but never recreate lost key material
            # or the private plaintext contents of prior sessions.
            if self.audit_path.exists():
                with self.audit_path.open('r', encoding='utf-8') as stream:
                    for line in stream:
                        try:
                            entry = json.loads(line)
                            if isinstance(entry, dict) and entry.get('kind') in {'message', 'attack', 'agent'}:
                                self.audit_entries.append(entry)
                        except (ValueError, TypeError):
                            continue
        self.started = time.time()
        self._initialized = False

    async def initialize_defaults(self) -> None:
        if self._initialized:
            return
        await self.add_agent('Alice', approved=True)
        await self.add_agent('Bob', approved=True)
        await self.add_agent('Eve', approved=False)
        self._initialized = True
        self._event('SYSTEM', 'Three local agents initialized; Eve is not in the trusted roster')

    def _event(self, category: str, message: str, *, level: str = 'info') -> None:
        self.events.append({
            'time': time.strftime('%H:%M:%S', time.localtime()),
            'category': category, 'message': message, 'level': level,
        })
        self.events = self.events[-250:]

    async def add_agent(self, name: str, *, approved: bool = True) -> dict:
        if not isinstance(name, str) or re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{1,23}', name) is None:
            raise ValueError('Agent name must contain 2–24 letters, digits, _ or - and start with a letter')
        if name in self.agents:
            raise ValueError('Agent already exists; identity keys cannot be overwritten')
        if len(self.agents) >= 12:
            raise ValueError('Demo supports a maximum of 12 agents')
        agent = PrivacyAgent(name)

        async def on_receive(payload: bytes) -> dict:
            return agent.receive(payload)

        node = AsyncPeerNode('127.0.0.1', 0, on_receive)
        await node.start()
        agent.set_endpoint('127.0.0.1', node.port)
        record = AgentRecord(agent=agent, node=node, approved=approved)
        self.agents[name] = record
        if approved:
            for existing_name, existing_record in self.agents.items():
                if existing_name != name and existing_record.approved:
                    existing_record.agent.trust(name, agent.keys.public)
                    agent.trust(existing_name, existing_record.agent.keys.public)
            self.cluster.register_peer(name, agent.host, agent.port, agent.keys.public)
        self._event('AGENT', f'{name} registered as {"trusted" if approved else "untrusted"} node')
        self._record_audit({
            'id': 'AUD-' + uuid.uuid4().hex[:12], 'kind': 'agent',
            'message_id': None, 'sender': name, 'recipient': 'LOCAL DIRECTORY',
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'status': 'TRUSTED' if approved else 'UNTRUSTED',
            'title': 'Agent identity registered',
            'summary': f'{name} registered with {"trusted" if approved else "untrusted"} status',
            'details': {
                'agent_name': name,
                'identity_fingerprint': agent.keys.public.fingerprint(),
                'signing_algorithm': 'Ed25519',
                'signing_public_key_hex': agent.keys.public.signing.hex(),
                'key_agreement': 'X25519',
                'encryption_public_key_hex': agent.keys.public.encryption.hex(),
                'trusted_peers_at_registration': sorted(agent.trusted),
                'trust_provisioning': 'Local demo administrator registration; not independently authenticated',
                'key_retention': 'New identity private keys generated on each process restart',
            },
            'steps': [
                {'operation': 'Generate local identity', 'actor': name, 'status': 'completed',
                 'detail': 'New Ed25519 signing and X25519 encryption keypairs generated in memory.'},
                {'operation': 'Register public identity', 'actor': 'Local Directory', 'status': 'completed',
                 'detail': 'Public keys and fingerprint recorded; private keys excluded from audit.'},
                {'operation': 'Pin trusted peers', 'actor': 'Local Directory',
                 'status': 'completed' if approved else 'restricted',
                 'detail': 'Identity added to trusted peer directories.' if approved
                           else 'Agent remains untrusted and cannot exchange approved messages.'},
            ],
            'privacy_note': 'Only public keys and fingerprint recorded. Long-term private keys are never logged.',
        })
        return self._agent_info(name, record)

    def _agent_info(self, name: str, record: AgentRecord) -> dict:
        return {
            'name': name, 'role': 'trusted' if record.approved else 'untrusted',
            'port': record.agent.port, 'fingerprint': record.agent.keys.public.fingerprint(),
            'inbox_count': len(record.agent.inbox),
            'peer_count': len(record.agent.trusted),
        }

    def _record_audit(self, record: dict) -> None:
        self.audit_entries.append(record)
        if self.audit_path is not None:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            fd = os.open(self.audit_path, flags, 0o600)
            with os.fdopen(fd, 'a', encoding='utf-8') as stream:
                stream.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n')

    async def get_audit(self, *, include_plaintext: bool = False, all_entries: bool = False) -> dict:
        # Full crypto metadata is public *in this local demo*; long-term private
        # keys, per-message derived keys, and shared secrets are never returned.
        records = list(reversed(self.audit_entries if all_entries else self.audit_entries[-250:]))
        if include_plaintext:
            records = [dict(entry, plaintext=self.message_records[entry['message_id']]['text'])
                       if entry['kind'] == 'message'
                       and entry['message_id'] in self.message_records else entry
                       for entry in records]
        return {
            'entries': records,
            'count': len(records), 'total_count': len(self.audit_entries),
            'counts_by_kind': {kind: sum(e['kind'] == kind for e in self.audit_entries)
                               for kind in ('message', 'attack', 'agent')},
            'retention': 'Metadata stored in local JSONL log when running the web app; current view shows newest 250 by default',
            'plaintext_included': include_plaintext,
            'sensitive_material_excluded': ['private keys', 'shared secrets', 'derived AES keys'],
        }

    async def get_state(self) -> dict:
        return {
            'app': 'Privacy-Preserving Multi-Agent Communication', 'mode': 'local-research-demo',
            'uptime_seconds': int(time.time() - self.started),
            'agents': [self._agent_info(name, r) for name, r in self.agents.items()],
            'events': list(reversed(self.events[-30:])),
            'experiments': list(reversed(self.experiments[-30:])),
            'messages': [record['summary'] for record in reversed(list(self.message_records.values()))],
            'audit_count': len(self.audit_entries),
            'metrics': {
                'trusted_agents': sum(r.approved for r in self.agents.values()),
                'delivered_messages': sum(len(r.agent.inbox) for r in self.agents.values()),
                'attack_runs': len(self.experiments),
                'attacks_blocked': sum(x['actual_blocked'] for x in self.experiments),
                'hypothetical_compromises': sum(not x['defenses_enabled'] for x in self.experiments),
            },
        }

    async def get_inbox(self, agent_name: str) -> dict:
        record = self.agents.get(agent_name)
        if not record or not record.approved:
            raise ValueError('Inbox unavailable for this agent')
        return {'agent': agent_name, 'messages': list(reversed(record.agent.inbox[-50:]))}

    async def send_message(self, sender: str, recipient: str, text: str) -> dict:
        source = self.agents.get(sender)
        dest = self.agents.get(recipient)
        if not source or not source.approved or not dest or not dest.approved:
            raise ValueError('Only approved local agents may exchange messages')
        if sender == recipient:
            raise ValueError('Select two different agents')
        packet = source.agent.make_packet(recipient, text, dest.agent.keys.public.encryption)
        payload = NetworkSerializer.serialize_message(packet)
        sender_fp = source.agent.keys.public.fingerprint()
        recipient_fp = dest.agent.keys.public.fingerprint()
        created = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(packet['created']))
        audit_steps = [
            {'operation': 'Ephemeral key generation', 'actor': sender, 'status': 'completed',
             'detail': 'X25519 ephemeral public key generated for this envelope.'},
            {'operation': 'Shared-key derivation', 'actor': sender, 'status': 'completed',
             'detail': 'X25519 exchange with pinned recipient public key; HKDF-SHA256 derives AES-256-GCM key.'},
            {'operation': 'Encrypt and sign', 'actor': sender, 'status': 'completed',
             'detail': 'AES-256-GCM authenticated encryption; Ed25519 signature over signed envelope.'},
        ]
        public_crypto = {
            'key_agreement': 'X25519 (ephemeral sender, static recipient)',
            'derivation': 'HKDF-SHA256', 'encryption': 'AES-256-GCM', 'signature_algorithm': 'Ed25519',
            'sender_identity_fingerprint': sender_fp, 'recipient_identity_fingerprint': recipient_fp,
            'sender_signing_public_key_hex': source.agent.keys.public.signing.hex(),
            'recipient_encryption_public_key_hex': dest.agent.keys.public.encryption.hex(),
            'ephemeral_public_key_hex': packet['ephemeral'].hex(),
            'nonce_hex': packet['nonce'].hex(),
            'authentication_tag_hex': packet['ciphertext'][-16:].hex(),
            'ciphertext_base64': base64.b64encode(packet['ciphertext']).decode('ascii'),
            'signature_hex': packet['signature'].hex(),
            'plaintext_size_bytes': len(text.encode('utf-8')),
            'wire_size_bytes': len(payload),
            'receipt_signature_hex': None,
        }
        audit = {'id': 'AUD-' + uuid.uuid4().hex[:12], 'kind': 'message',
                 'message_id': packet['id'], 'sender': sender, 'recipient': recipient,
                 'timestamp': created, 'status': 'PENDING', 'title': 'Secure message transmission',
                 'summary': f'{sender} → {recipient}: delivery pending',
                 'details': public_crypto, 'steps': audit_steps,
                 'privacy_note': 'Plaintext excluded by default; private/derived keys and secrets never logged.'}
        try:
            receipt = await AsyncPeerNode.send_with_receipt(dest.agent.host, dest.agent.port, payload)
            if receipt is None or receipt.get('id') != packet['id'] or receipt.get('recipient') != recipient:
                raise RuntimeError('No matching response received from recipient')
            if not PrivacyAgent.verify_receipt(receipt, dest.agent.keys.public.signing):
                raise RuntimeError('Recipient delivery receipt signature is invalid')
            accepted = receipt['status'] == 'ACCEPTED'
            audit['status'] = receipt['status']
            audit['summary'] = f'{sender} → {recipient}: {receipt["status"]}'
            public_crypto['receipt_signature_hex'] = receipt.get('signature')
            public_crypto['receipt_verified'] = True
            if accepted:
                audit_steps.extend([
                    {'operation': 'Pinned sender identity verified', 'actor': recipient, 'status': 'completed',
                     'detail': 'Sender identity found in the recipient trusted-key roster.'},
                    {'operation': 'Ed25519 signature verified', 'actor': recipient, 'status': 'completed',
                     'detail': 'Signed envelope matches the pinned sender public key.'},
                    {'operation': 'Timestamp validation', 'actor': recipient, 'status': 'completed',
                     'detail': 'Message timestamp accepted inside the configured clock-skew window.'},
                    {'operation': 'Replay ID check', 'actor': recipient, 'status': 'completed',
                     'detail': 'Message ID not present in the receiver replay cache.'},
                    {'operation': 'Rate limit evaluation', 'actor': recipient, 'status': 'completed',
                     'detail': 'Sender remains within the configured delivery rate.'},
                    {'operation': 'AES-256-GCM authentication', 'actor': recipient, 'status': 'completed',
                     'detail': 'Recipient successfully authenticated and decrypted the AEAD ciphertext.'},
                ])
            audit_steps.extend([
                {'operation': 'Identity, integrity and replay checks', 'actor': recipient,
                 'status': 'completed' if accepted else 'rejected',
                 'detail': 'Receiver result: ' + receipt['status'] + ' — ' + receipt['detail']},
                {'operation': 'Decrypt and deliver', 'actor': recipient,
                 'status': 'completed' if accepted else 'rejected', 'detail': receipt['detail']},
                {'operation': 'Verify signed delivery receipt', 'actor': sender,
                 'status': 'completed', 'detail': 'Recipient Ed25519 receipt verified against pinned identity.'},
            ])
            self._event('MESSAGE', audit['summary'], level='success' if accepted else 'warning')
            if accepted:
                self.message_records[packet['id']] = {
                    'summary': {'id': packet['id'], 'sender': sender, 'recipient': recipient,
                                'created': packet['created'], 'status': receipt['status'],
                                'bytes': len(payload)},
                    'text': text,
                }
                while len(self.message_records) > 100:
                    self.message_records.pop(next(iter(self.message_records)))
            return {'id': packet['id'], 'sender': sender, 'recipient': recipient,
                    'status': receipt['status'], 'detail': receipt['detail'],
                    'wire_bytes': len(payload), 'ciphertext_bytes': len(packet['ciphertext']),
                    'verified_receipt': True, 'audit_id': audit['id']}
        except Exception as exc:
            audit['status'] = 'ERROR'
            audit['summary'] = f'{sender} → {recipient}: delivery error'
            audit_steps.append({'operation': 'Delivery/receipt verification', 'actor': recipient,
                                'status': 'failed', 'detail': str(exc)})
            self._event('MESSAGE', audit['summary'], level='danger')
            raise
        finally:
            self._record_audit(audit)

    async def simulate_attack(self, attack: str, *, defenses_enabled: bool = True, message_id: str | None = None) -> dict:
        if attack not in ATTACK_NAMES:
            raise ValueError(f'Unknown attack: {attack}')
        if not isinstance(defenses_enabled, bool):
            raise ValueError('defenses_enabled must be a boolean')
        if message_id is not None and (not isinstance(message_id, str) or message_id not in self.message_records):
            raise ValueError('Select a message that was delivered during this session')
        source = self.message_records.get(message_id) if message_id else None
        sender_name = source['summary']['sender'] if source else 'Alice'
        recipient_name = source['summary']['recipient'] if source else 'Bob'
        message_text = source['text'] if source else 'Isolated protocol test message'
        # The exercise uses isolated identities and a fresh receiver. Never turn off
        # protections on a genuine agent, even for a vulnerable-mode comparison.
        alice, bob, eve = PrivacyAgent(sender_name), PrivacyAgent(recipient_name), PrivacyAgent('Eve')
        bob.trust(sender_name, alice.keys.public)
        packet = alice.make_packet(recipient_name, message_text, bob.keys.public.encryption)
        encoded = NetworkSerializer.serialize_message(packet)
        stages = []
        observed = ''
        checks: dict = {}

        def stage(actor: str, title: str, detail: str, tone: str = 'neutral') -> None:
            actor = {'Alice': sender_name, 'Bob': recipient_name}.get(actor, actor)
            detail = re.sub(r'\b(Alice|Bob)\b', lambda match: {'Alice': sender_name, 'Bob': recipient_name}[match.group()], detail)
            stages.append({'actor': actor, 'title': title, 'detail': detail, 'tone': tone})

        if attack == 'tamper':
            stage('Alice', 'Authentic packet', 'Alice signs and encrypts a payload for Bob.', 'good')
            damaged = dict(packet)
            damaged['ciphertext'] = bytes([packet['ciphertext'][0] ^ 1]) + packet['ciphertext'][1:]
            stage('Eve', 'Ciphertext mutated', 'Eve changes a byte while the packet crosses the channel.', 'danger')
            receipt = bob.receive(NetworkSerializer.serialize_message(damaged))
            observed = receipt['status']
            stage('Bob', 'Signature verification', 'Signed ciphertext no longer matches Alice’s pinned key.', 'good')
            try:
                decrypt_message(damaged, bob.keys.encryption)
                aead_rejected = False
            except InvalidTag:
                aead_rejected = True
            checks['aead_tag_rejected'] = aead_rejected
            stage('Bob', 'Second integrity layer', 'AES-GCM also rejects altered ciphertext when independently checked.', 'good')
        elif attack == 'replay':
            stage('Alice', 'Original transmission', 'A legitimate authenticated message is delivered.', 'good')
            first = bob.receive(encoded)
            checks['original_status'] = first['status']
            stage('Eve', 'Packet captured', 'A verbatim copy is retained for replay.', 'danger')
            second = bob.receive(encoded)
            observed = second['status']
            stage('Eve', 'Duplicate injected', 'The same message ID and timestamp arrive again.', 'danger')
            stage('Bob', 'Replay cache check', 'The receiver rejects a previously accepted message ID.', 'good')
        elif attack == 'impersonation':
            stage('Eve', 'Identity mask', 'Eve creates a new packet that claims its sender is Alice.', 'danger')
            forged = eve.make_packet(recipient_name, 'Unauthorized instruction', bob.keys.public.encryption, claim=sender_name)
            stage('Eve', 'Wrong signing key', 'The forged envelope is signed using Eve’s private key.', 'danger')
            observed = bob.receive(NetworkSerializer.serialize_message(forged))['status']
            stage('Bob', 'Identity pin check', 'Bob verifies the claimed Alice identity against Alice’s pinned key.', 'good')
            stage('Bob', 'Forgery rejected', 'A matching display name does not confer identity authority.', 'good')
        elif attack == 'decryption':
            stage('Alice', 'Encrypted transmission', 'Alice encrypts to Bob’s X25519 public encryption key.', 'good')
            stage('Eve', 'Ciphertext intercepted', 'Eve obtains the public envelope but not Bob’s private key.', 'danger')
            try:
                decrypt_message(packet, eve.keys.encryption)
                observed = 'UNEXPECTED_DECRYPTED'
            except (InvalidTag, ValueError):
                observed = 'REJECT_DECRYPT'
            stage('Eve', 'Incorrect shared secret', 'Eve derives a different encryption key and AES-GCM authentication fails.', 'good')
            delivered = bob.receive(encoded)
            checks['recipient_status'] = delivered['status']
            stage('Bob', 'Intended recipient decrypts', 'Bob can decrypt and authenticate the original packet.', 'good')
        elif attack == 'oversized':
            stage('Eve', 'Oversized payload', f'Attacker attempts a {MAX_MESSAGE_BYTES + 1}-byte plaintext.', 'danger')
            try:
                alice.make_packet(recipient_name, 'X' * (MAX_MESSAGE_BYTES + 1), bob.keys.public.encryption)
                refused = False
            except ValueError:
                refused = True
            stage('Gateway', 'Message cap', 'Oversized plaintext is rejected before encryption and transmission.', 'good')
            # This is also checked at the TCP sender before opening a connection.
            outgoing = await AsyncPeerNode.send_payload('127.0.0.1', 0, b'X' * (AsyncPeerNode.MAX_FRAME_BYTES + 1))
            checks['message_rejected'] = refused
            checks['wire_frame_rejected'] = outgoing is False
            observed = 'REJECT_SIZE' if refused and outgoing is False else 'UNEXPECTED_ACCEPTED'
            stage('Gateway', 'Frame cap', 'The network layer refuses over-limit framed data.', 'good')
            stage('Bob', 'Service preserved', 'No oversized payload reaches the recipient.', 'good')
        else:  # flood
            stage('Alice', 'Burst begins', 'Nine distinct correctly signed packets target Bob.', 'danger')
            statuses = []
            for i in range(9):
                sample = alice.make_packet(recipient_name, f'Burst sample {i}', bob.keys.public.encryption)
                statuses.append(bob.receive(NetworkSerializer.serialize_message(sample))['status'])
            checks['accepted_in_window'] = statuses.count('ACCEPTED')
            checks['rate_rejections'] = statuses.count('REJECT_RATE_LIMIT')
            observed = 'REJECT_RATE_LIMIT' if checks['rate_rejections'] else 'UNEXPECTED_ACCEPTED'
            stage('Gateway', 'Window count rises', f'{checks["accepted_in_window"]} messages accepted inside a two-second window.', 'neutral')
            stage('Gateway', 'Threshold crossed', 'Further signed traffic exceeds the configured per-sender limit.', 'danger')
            stage('Bob', 'Rate limit engaged', f'{checks["rate_rejections"]} excess packets rejected by Bob.', 'good')

        actual_blocked = observed in {
            'REJECT_SIGNATURE', 'REJECT_REPLAY', 'REJECT_DECRYPT',
            'REJECT_SIZE', 'REJECT_RATE_LIMIT',
        }
        if not defenses_enabled:
            stage('Research model', 'What-if: safeguards disabled',
                  'Hypothetical vulnerable outcome only. Live cryptographic checks were NOT disabled.', 'danger')
        final = 'BLOCKED' if defenses_enabled and actual_blocked else ('HYPOTHETICAL_BREACH' if not defenses_enabled else 'CHECK_FAILED')
        result = {
            'id': uuid.uuid4().hex[:12], 'attack': attack,
            'target_message_id': message_id, 'sender': sender_name, 'recipient': recipient_name,
            'label': ATTACK_NAMES[attack], 'defense': DEFENSE_NAMES[attack],
            'defenses_enabled': defenses_enabled, 'verdict': final,
            'observed_status': observed, 'actual_blocked': actual_blocked,
            'stages': stages, 'checks': checks,
            'mode': 'actual-library-checks' if defenses_enabled else 'hypothetical-unprotected-comparison',
            'time': time.strftime('%H:%M:%S', time.localtime()),
            'isolation_note': 'Attack reenacted on isolated temporary agents using the selected message text and roles; original delivery is unchanged.' if message_id else 'Isolated test packet; no delivered message selected.',
            'public_evidence': {
                'test_packet_id': packet['id'], 'sender_fingerprint': alice.keys.public.fingerprint(),
                'sender_signing_public_key_hex': alice.keys.public.signing.hex(),
                'recipient_encryption_public_key_hex': bob.keys.public.encryption.hex(),
                'recipient_fingerprint': bob.keys.public.fingerprint(),
                'nonce_hex': packet['nonce'].hex(), 'ephemeral_public_key_hex': packet['ephemeral'].hex(),
                'ciphertext_base64': base64.b64encode(packet['ciphertext']).decode('ascii'),
                'signature_hex': packet['signature'].hex(),
            },
        }
        self._record_audit({
            'id': 'AUD-' + uuid.uuid4().hex[:12], 'kind': 'attack',
            'message_id': message_id, 'sender': sender_name, 'recipient': recipient_name,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'status': observed, 'title': ATTACK_NAMES[attack],
            'summary': ATTACK_NAMES[attack] + ': ' + final,
            'details': {'attack': attack, 'defense': DEFENSE_NAMES[attack],
                        'verdict': final, 'observed_status': observed, 'checks': checks,
                        'defenses_enabled': defenses_enabled, 'test_packet': result['public_evidence'],
                        'isolation_note': result['isolation_note']},
            'steps': [{'operation': x['title'], 'actor': x['actor'],
                       'status': x['tone'], 'detail': x['detail']} for x in stages],
            'privacy_note': 'Only public cryptographic evidence is included; test keys are isolated.',
        })
        self.experiments.append(result)
        self.experiments = self.experiments[-100:]
        self._event('DEFENSE', f'{ATTACK_NAMES[attack]}: {final} / library observed {observed}',
                    level='success' if actual_blocked else 'danger')
        return result

    async def assistant(self, question: str) -> dict:
        if not isinstance(question, str) or not (1 <= len(question.strip()) <= 500):
            raise ValueError('Question must contain 1–500 characters')
        from .assistant_engine import answer
        return answer(question.strip(), self)

    async def stop(self) -> None:
        await asyncio.gather(*(record.node.stop() for record in self.agents.values()))
