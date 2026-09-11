import secrets
import msgpack
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from privacy_agent_protocol.zk.proofs import OpeningProof

class NetworkSerializer:
    @staticmethod
    def _int_to_bytes(val: int) -> bytes:
        return val.to_bytes(32, byteorder="big")

    @staticmethod
    def _bytes_to_int(raw: bytes) -> int:
        return int.from_bytes(raw, byteorder="big")

    @staticmethod
    def peek_message_type(payload_bytes: bytes) -> str:
        unpacked = msgpack.unpackb(payload_bytes)
        return unpacked.get("type", "unknown")

    @staticmethod
    def serialize_point(point: Point) -> dict:
        return {
            "x": NetworkSerializer._int_to_bytes(point.x),
            "y": NetworkSerializer._int_to_bytes(point.y),
        }

    @staticmethod
    def deserialize_point(data: dict) -> Point:
        x = NetworkSerializer._bytes_to_int(data["x"])
        y = NetworkSerializer._bytes_to_int(data["y"])
        return Point(x, y, curve=secp256k1)

    @staticmethod
    def serialize_proof(commitment: Point, proof: OpeningProof) -> bytes:
        payload = {
            "type": "proof",
            "commitment": NetworkSerializer.serialize_point(commitment),
            "R": NetworkSerializer.serialize_point(proof.R),
            "s_v": NetworkSerializer._int_to_bytes(proof.s_v),
            "s_r": NetworkSerializer._int_to_bytes(proof.s_r),
        }
        return msgpack.packb(payload)

    @staticmethod
    def deserialize_proof(payload_bytes: bytes) -> tuple[Point, OpeningProof]:
        data = msgpack.unpackb(payload_bytes)
        commitment = NetworkSerializer.deserialize_point(data["commitment"])
        R = NetworkSerializer.deserialize_point(data["R"])
        s_v = NetworkSerializer._bytes_to_int(data["s_v"])
        s_r = NetworkSerializer._bytes_to_int(data["s_r"])
        return commitment, OpeningProof(R, s_v, s_r)

    @staticmethod
    def serialize_transfer(
        transfer_commitment: Point,
        encrypted_r: bytes,
        ephemeral_pk: Point,
        stealth_pk: Point | None = None,
        ephemeral_stealth_pk: Point | None = None,
        nonce: int = None,
    ) -> bytes:
        if nonce is None:
            nonce = secrets.randbits(64)
            
        payload = {
            "type": "transfer",
            "nonce": nonce,
            "transfer_commitment": NetworkSerializer.serialize_point(transfer_commitment),
            "encrypted_r": encrypted_r,
            "ephemeral_pk": NetworkSerializer.serialize_point(ephemeral_pk),
            "stealth_pk": NetworkSerializer.serialize_point(stealth_pk) if stealth_pk is not None else None,
            "ephemeral_stealth_pk": NetworkSerializer.serialize_point(ephemeral_stealth_pk) if ephemeral_stealth_pk is not None else None,
        }
        return msgpack.packb(payload)

    @staticmethod
    def deserialize_transfer(payload_bytes: bytes) -> tuple[Point, bytes, Point, Point | None, Point | None, int]:
        data = msgpack.unpackb(payload_bytes)
        transfer_commitment = NetworkSerializer.deserialize_point(data["transfer_commitment"])
        encrypted_r = data["encrypted_r"]
        ephemeral_pk = NetworkSerializer.deserialize_point(data["ephemeral_pk"])
        stealth_pk = NetworkSerializer.deserialize_point(data["stealth_pk"]) if data.get("stealth_pk") else None
        ephemeral_stealth_pk = NetworkSerializer.deserialize_point(data["ephemeral_stealth_pk"]) if data.get("ephemeral_stealth_pk") else None
        nonce = data["nonce"]
        return transfer_commitment, encrypted_r, ephemeral_pk, stealth_pk, ephemeral_stealth_pk, nonce

    @staticmethod
    def serialize_ring_auth(challenge: bytes, c0: int, s: list[int]) -> bytes:
        payload = {
            "type": "ring_auth",
            "challenge": challenge,
            "c0": NetworkSerializer._int_to_bytes(c0),
            "s": [NetworkSerializer._int_to_bytes(val) for val in s],
        }
        return msgpack.packb(payload)

    @staticmethod
    def deserialize_ring_auth(payload_bytes: bytes) -> tuple[bytes, int, list[int]]:
        data = msgpack.unpackb(payload_bytes)
        c0 = NetworkSerializer._bytes_to_int(data["c0"])
        s = [NetworkSerializer._bytes_to_int(val) for val in data["s"]]
        return data["challenge"], c0, s

    @staticmethod
    def serialize_handshake(sender_name: str, host: str, port: int, sender_pk: Point, is_ack: bool = False) -> bytes:
        payload = {
            "type": "handshake_ack" if is_ack else "handshake",
            "sender": sender_name,
            "host": host,
            "port": port,
            "sender_pk": NetworkSerializer.serialize_point(sender_pk),
        }
        return msgpack.packb(payload)

    @staticmethod
    def deserialize_handshake(payload_bytes: bytes) -> tuple[str, str, int, Point]:
        data = msgpack.unpackb(payload_bytes)
        sender_pk = NetworkSerializer.deserialize_point(data["sender_pk"])
        return data["sender"], data["host"], data["port"], sender_pk
