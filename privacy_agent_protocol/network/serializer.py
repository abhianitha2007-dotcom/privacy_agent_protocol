"""Strict MessagePack serialization and validation for v2 encrypted messages."""
from __future__ import annotations

import msgpack
from privacy_agent_protocol.crypto.secure_message import PROTOCOL_VERSION

REQUIRED = frozenset(('v', 'type', 'sender', 'recipient', 'id', 'created', 'ephemeral', 'nonce', 'ciphertext', 'signature'))
MAX_WIRE_BYTES = 16 * 1024


class NetworkSerializer:
    @staticmethod
    def serialize_message(packet: dict) -> bytes:
        NetworkSerializer.validate(packet)
        result = msgpack.packb(packet, use_bin_type=True)
        if len(result) > MAX_WIRE_BYTES:
            raise ValueError('Wire message exceeds size cap')
        return result

    @staticmethod
    def deserialize_message(payload: bytes) -> dict:
        if len(payload) > MAX_WIRE_BYTES:
            raise ValueError('Wire message exceeds size cap')
        try:
            packet = msgpack.unpackb(payload, raw=False, strict_map_key=True,
                                     max_map_len=16, max_str_len=5120, max_bin_len=8192)
        except (msgpack.ExtraData, msgpack.FormatError, msgpack.StackError, ValueError, TypeError) as exc:
            raise ValueError('Malformed MessagePack payload') from exc
        NetworkSerializer.validate(packet)
        return packet

    @staticmethod
    def validate(packet: dict) -> None:
        if not isinstance(packet, dict) or set(packet) != REQUIRED:
            raise ValueError('Invalid message schema')
        if type(packet['v']) is not int or packet['v'] != PROTOCOL_VERSION or packet['type'] != 'secure_message':
            raise ValueError('Unsupported protocol message')
        for name in ('sender', 'recipient'):
            if not isinstance(packet[name], str) or not (1 <= len(packet[name]) <= 40):
                raise ValueError(f'Invalid {name}')
        if not isinstance(packet['id'], str) or len(packet['id']) != 32 or any(c not in '0123456789abcdef' for c in packet['id']):
            raise ValueError('Invalid packet ID')
        if type(packet['created']) is not int or packet['created'] < 0:
            raise ValueError('Invalid timestamp')
        for field, length in (('ephemeral', 32), ('nonce', 12), ('signature', 64)):
            if not isinstance(packet[field], bytes) or len(packet[field]) != length:
                raise ValueError(f'Invalid {field}')
        if not isinstance(packet['ciphertext'], bytes) or not (17 <= len(packet['ciphertext']) <= 4112):
            raise ValueError('Invalid ciphertext length')
