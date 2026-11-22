"""Private agent with pinned peer identity checks, replay and flood defenses."""
from __future__ import annotations

import time
import json
from collections import OrderedDict, defaultdict, deque

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519
from privacy_agent_protocol.crypto.secure_message import (
    IdentityKeys, IdentityPublicKeys, decrypt_message, encrypt_message,
    verify_signature, MAX_CLOCK_SKEW_SECONDS,
)
from privacy_agent_protocol.network.serializer import NetworkSerializer


class PrivacyAgent:
    REPLAY_CAPACITY = 10000
    RATE_WINDOW_SECONDS = 2.0
    RATE_MAX = 6

    def __init__(self, name: str):
        self.name = name
        self.keys = IdentityKeys()
        self.host = '127.0.0.1'
        self.port = 0
        self.trusted: dict[str, IdentityPublicKeys] = {}
        self.seen: OrderedDict[str, float] = OrderedDict()
        self.rate: dict[str, deque[float]] = defaultdict(deque)
        self.inbox: list[dict] = []
        self.receipts: list[dict] = []

    def set_endpoint(self, host: str, port: int) -> None:
        self.host, self.port = host, port

    def trust(self, name: str, pub: IdentityPublicKeys) -> None:
        if name in self.trusted and self.trusted[name] != pub:
            raise ValueError(f'Pinned identity mismatch for {name}')
        self.trusted[name] = pub

    def make_packet(self, recipient: str, text: str, recipient_key: bytes, *, claim: str | None = None) -> dict:
        return encrypt_message(claim or self.name, recipient, text, recipient_key, self.keys.signing)

    def _reject(self, packet_id: str, status: str, detail: str) -> dict:
        receipt = {'id': packet_id, 'status': status, 'detail': detail, 'recipient': self.name}
        data = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode('utf-8')
        receipt['signature'] = self.keys.signing.sign(data).hex()
        self.receipts.append(receipt)
        return receipt

    @staticmethod
    def verify_receipt(receipt: dict, pinned_recipient_signing_key: bytes) -> bool:
        try:
            fields = {k: receipt[k] for k in ('id', 'status', 'detail', 'recipient')}
            data = json.dumps(fields, sort_keys=True, separators=(',', ':')).encode('utf-8')
            signature = bytes.fromhex(receipt['signature'])
            ed25519.Ed25519PublicKey.from_public_bytes(pinned_recipient_signing_key).verify(signature, data)
            return True
        except (KeyError, ValueError, TypeError, InvalidSignature):
            return False

    def receive(self, payload: bytes) -> dict:
        try:
            packet = NetworkSerializer.deserialize_message(payload)
        except (ValueError, TypeError, KeyError) as exc:
            return self._reject('', 'REJECT_MALFORMED', str(exc))
        packet_id = packet['id']
        if packet['recipient'] != self.name:
            return self._reject(packet_id, 'REJECT_RECIPIENT', 'Incorrect destination')
        pinned = self.trusted.get(packet['sender'])
        if pinned is None:
            return self._reject(packet_id, 'REJECT_UNTRUSTED', 'Sender is not authorized in receiver roster')
        try:
            verify_signature(packet, pinned.signing)
        except (InvalidSignature, ValueError):
            return self._reject(packet_id, 'REJECT_SIGNATURE', 'Signature does not match pinned sender identity')
        now = time.time()
        if abs(now - packet['created']) > MAX_CLOCK_SKEW_SECONDS:
            return self._reject(packet_id, 'REJECT_EXPIRED', 'Timestamp outside replay window')
        # Retain all packet IDs inside validity window; if the cache is full, fail closed.
        cutoff = now - MAX_CLOCK_SKEW_SECONDS * 2
        while self.seen and next(iter(self.seen.values())) < cutoff:
            self.seen.popitem(last=False)
        if packet_id in self.seen:
            return self._reject(packet_id, 'REJECT_REPLAY', 'Message ID already accepted')
        if len(self.seen) >= self.REPLAY_CAPACITY:
            return self._reject(packet_id, 'REJECT_CAPACITY', 'Replay cache full; refusing message')
        times = self.rate[packet['sender']]
        while times and times[0] <= now - self.RATE_WINDOW_SECONDS:
            times.popleft()
        if len(times) >= self.RATE_MAX:
            return self._reject(packet_id, 'REJECT_RATE_LIMIT', 'Per-sender message rate exceeded')
        try:
            message = decrypt_message(packet, self.keys.encryption)
        except (InvalidTag, UnicodeDecodeError, ValueError):
            return self._reject(packet_id, 'REJECT_DECRYPT', 'AEAD tag or decoding failed')
        self.seen[packet_id] = now
        times.append(now)
        self.inbox.append({'id': packet_id, 'sender': packet['sender'], 'text': message, 'created': packet['created']})
        self.inbox = self.inbox[-200:]
        return self._reject(packet_id, 'ACCEPTED', 'Signed encrypted message delivered to intended recipient')
