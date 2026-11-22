"""Authenticated, encrypted application messages using standard crypto primitives.

Ephemeral X25519 -> static recipient X25519 + HKDF + AES-256-GCM;
Ed25519 signs the envelope. WARNING: static recipient keys do NOT give full
forward secrecy if the recipient's long-term private key is compromised.
"""
from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass

import msgpack
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_MESSAGE_BYTES = 4096
MAX_CLOCK_SKEW_SECONDS = 300
PROTOCOL_VERSION = 2


def public_bytes(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass(frozen=True)
class IdentityPublicKeys:
    signing: bytes
    encryption: bytes

    def fingerprint(self) -> str:
        return hashlib.sha256(self.signing + self.encryption).hexdigest()[:20]


class IdentityKeys:
    def __init__(self):
        self.signing = ed25519.Ed25519PrivateKey.generate()
        self.encryption = x25519.X25519PrivateKey.generate()

    @property
    def public(self) -> IdentityPublicKeys:
        return IdentityPublicKeys(public_bytes(self.signing.public_key()), public_bytes(self.encryption.public_key()))


def _aad(packet: dict) -> bytes:
    return msgpack.packb([
        packet['v'], packet['type'], packet['sender'], packet['recipient'],
        packet['id'], packet['created'], packet['ephemeral'],
    ], use_bin_type=True)


def signing_input(packet: dict) -> bytes:
    return msgpack.packb([_aad(packet), packet['nonce'], packet['ciphertext']], use_bin_type=True)


def _key(shared: bytes, packet: dict) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'privacy-agent-message-v2|' + _aad(packet)).derive(shared)


def encrypt_message(sender: str, recipient: str, message: str, recipient_public_key: bytes,
                    signing_key: ed25519.Ed25519PrivateKey, *, created: int | None = None) -> dict:
    if not isinstance(message, str) or not message.strip():
        raise ValueError('Message must contain text')
    raw = message.encode('utf-8')
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError(f'Message exceeds {MAX_MESSAGE_BYTES} UTF-8 bytes')
    ephemeral_private = x25519.X25519PrivateKey.generate()
    packet = {
        'v': PROTOCOL_VERSION, 'type': 'secure_message',
        'sender': sender, 'recipient': recipient,
        'id': uuid.uuid4().hex, 'created': int(time.time()) if created is None else created,
        'ephemeral': public_bytes(ephemeral_private.public_key()),
        'nonce': secrets.token_bytes(12),
    }
    shared = ephemeral_private.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_public_key))
    packet['ciphertext'] = AESGCM(_key(shared, packet)).encrypt(packet['nonce'], raw, _aad(packet))
    packet['signature'] = signing_key.sign(signing_input(packet))
    return packet


def decrypt_message(packet: dict, recipient_private_key: x25519.X25519PrivateKey) -> str:
    sender_ephemeral = x25519.X25519PublicKey.from_public_bytes(packet['ephemeral'])
    secret = recipient_private_key.exchange(sender_ephemeral)
    text_bytes = AESGCM(_key(secret, packet)).decrypt(packet['nonce'], packet['ciphertext'], _aad(packet))
    return text_bytes.decode('utf-8')


def verify_signature(packet: dict, pinned_sender_key: bytes) -> None:
    pub = ed25519.Ed25519PublicKey.from_public_bytes(pinned_sender_key)
    pub.verify(packet['signature'], signing_input(packet))
