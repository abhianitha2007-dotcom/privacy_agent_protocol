import asyncio
import msgpack

class AsyncPeerNode:
    def __init__(self, host: str, port: int, message_handler):
        self.host = host
        self.port = port
        self.message_handler = message_handler
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            length_bytes = await reader.readexactly(4)
            length = int.from_bytes(length_bytes, byteorder="big")
            payload = await reader.readexactly(length)
            await self.message_handler(payload)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    async def send_payload(target_host: str, target_port: int, payload: bytes) -> bool:
        """Transmits length-prefixed payload frame over socket safely handling connection drops."""
        try:
            reader, writer = await asyncio.open_connection(target_host, target_port)
            length_prefix = len(payload).to_bytes(4, byteorder="big")
            writer.write(length_prefix + payload)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, OSError):
            # Target node is offline or uninitialized
            return False
