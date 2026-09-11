import asyncio
from dataclasses import dataclass
from fastecdsa.point import Point
from privacy_agent_protocol.network.node import AsyncPeerNode

@dataclass
class PeerInfo:
    name: str
    host: str
    port: int
    public_key: Point

class ClusterManager:
    def __init__(self):
        self.peers: dict[str, PeerInfo] = {}

    def register_peer(self, name: str, host: str, port: int, public_key: Point):
        """Adds a peer node to the local routing directory."""
        self.peers[name] = PeerInfo(name, host, port, public_key)

    async def broadcast(self, payload: bytes) -> dict[str, bool]:
        """Concurrently broadcasts a binary payload to all registered cluster peers."""
        async def _send_to_peer(peer: PeerInfo) -> tuple[str, bool]:
            try:
                await AsyncPeerNode.send_payload(peer.host, peer.port, payload)
                return peer.name, True
            except Exception as e:
                print(f"[Cluster Error] Failed to reach {peer.name} at {peer.host}:{peer.port} -> {e}")
                return peer.name, False

        tasks = [_send_to_peer(peer) for peer in self.peers.values()]
        results = await asyncio.gather(*tasks)
        return dict(results)
