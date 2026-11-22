"""Session-owned directory; peer keys are pinned, never learned from packets."""
from dataclasses import dataclass
from privacy_agent_protocol.crypto.secure_message import IdentityPublicKeys
from privacy_agent_protocol.network.node import AsyncPeerNode


@dataclass(frozen=True)
class PeerInfo:
    name: str
    host: str
    port: int
    public_keys: IdentityPublicKeys


class ClusterManager:
    def __init__(self):
        self.peers: dict[str, PeerInfo] = {}

    def register_peer(self, name: str, host: str, port: int, keys: IdentityPublicKeys):
        previous = self.peers.get(name)
        if previous and previous.public_keys != keys:
            raise ValueError(f'Refusing replacement of pinned keys for {name}')
        self.peers[name] = PeerInfo(name, host, port, keys)

    async def broadcast(self, payload: bytes) -> dict[str, bool]:
        import asyncio
        names = list(self.peers)
        results = await asyncio.gather(*(AsyncPeerNode.send_payload(self.peers[n].host, self.peers[n].port, payload) for n in names), return_exceptions=True)
        return {n: (result is True) for n, result in zip(names, results)}
