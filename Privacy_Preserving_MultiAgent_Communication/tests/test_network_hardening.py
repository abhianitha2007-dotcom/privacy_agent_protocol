"""Network regression tests, runnable even if optional EC backend is not installed."""
import asyncio
import importlib.util
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location("network_node_standalone", Path(__file__).resolve().parents[1] / "privacy_agent_protocol/network/node.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
AsyncPeerNode = module.AsyncPeerNode

@pytest.mark.asyncio
async def test_reject_oversized_header_without_reading_body():
    received = []
    async def handler(payload): received.append(payload)
    node = AsyncPeerNode("127.0.0.1", 0, handler)
    await node.start()
    port = node.server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write((AsyncPeerNode.MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), timeout=2) == b""
    assert received == []
    writer.close(); await writer.wait_closed(); await node.stop()

@pytest.mark.asyncio
async def test_normal_frame_and_outgoing_cap():
    received = []
    async def handler(payload): received.append(payload)
    node = AsyncPeerNode("127.0.0.1", 0, handler)
    await node.start()
    port = node.server.sockets[0].getsockname()[1]
    assert await AsyncPeerNode.send_payload("127.0.0.1", port, b"hello") is True
    for _ in range(20):
        if received: break
        await asyncio.sleep(0.01)
    assert received == [b"hello"]
    assert await AsyncPeerNode.send_payload("127.0.0.1", port, b"x" * (AsyncPeerNode.MAX_FRAME_BYTES + 1)) is False
    await node.stop()

@pytest.mark.asyncio
async def test_offline_peer_returns_false():
    assert await AsyncPeerNode.send_payload("127.0.0.1", 0, b"hello") is False
