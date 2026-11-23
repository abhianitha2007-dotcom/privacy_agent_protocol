"""Bounded, timeout-protected local TCP framing with an explicit demo receipt."""
from __future__ import annotations

import asyncio
import json


class AsyncPeerNode:
    MAX_FRAME_BYTES = 16 * 1024
    IO_TIMEOUT_SECONDS = 5

    def __init__(self, host: str, port: int, message_handler):
        self.host = host
        self.port = port
        self.message_handler = message_handler
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            header = await asyncio.wait_for(reader.readexactly(4), self.IO_TIMEOUT_SECONDS)
            length = int.from_bytes(header, 'big')
            if length <= 0 or length > self.MAX_FRAME_BYTES:
                return
            payload = await asyncio.wait_for(reader.readexactly(length), self.IO_TIMEOUT_SECONDS)
            reply = await self.message_handler(payload)
            if isinstance(reply, dict):
                encoded = json.dumps(reply, separators=(',', ':')).encode('utf-8')
                if len(encoded) <= 4096:
                    writer.write(len(encoded).to_bytes(4, 'big') + encoded)
                    await asyncio.wait_for(writer.drain(), self.IO_TIMEOUT_SECONDS)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    @staticmethod
    async def _send(target_host: str, target_port: int, payload: bytes, receipt: bool):
        if not isinstance(payload, bytes) or not 0 < len(payload) <= AsyncPeerNode.MAX_FRAME_BYTES:
            return None if receipt else False
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target_host, target_port), AsyncPeerNode.IO_TIMEOUT_SECONDS)
            writer.write(len(payload).to_bytes(4, 'big') + payload)
            await asyncio.wait_for(writer.drain(), AsyncPeerNode.IO_TIMEOUT_SECONDS)
            if receipt:
                header = await asyncio.wait_for(reader.readexactly(4), AsyncPeerNode.IO_TIMEOUT_SECONDS)
                length = int.from_bytes(header, 'big')
                if not 0 < length <= 4096:
                    return None
                body = await asyncio.wait_for(reader.readexactly(length), AsyncPeerNode.IO_TIMEOUT_SECONDS)
                reply = json.loads(body)
                return reply if isinstance(reply, dict) else None
            return True
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError, json.JSONDecodeError):
            return None if receipt else False
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

    @staticmethod
    async def send_payload(host: str, port: int, payload: bytes) -> bool:
        return await AsyncPeerNode._send(host, port, payload, False)

    @staticmethod
    async def send_with_receipt(host: str, port: int, payload: bytes) -> dict | None:
        return await AsyncPeerNode._send(host, port, payload, True)
