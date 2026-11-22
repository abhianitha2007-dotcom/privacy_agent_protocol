import time
from copy import deepcopy

import pytest
from cryptography.exceptions import InvalidTag

from privacy_agent_protocol.agent.agent import PrivacyAgent
from privacy_agent_protocol.crypto.secure_message import decrypt_message, MAX_MESSAGE_BYTES
from privacy_agent_protocol.network.serializer import NetworkSerializer


def agents():
    alice = PrivacyAgent('Alice')
    bob = PrivacyAgent('Bob')
    eve = PrivacyAgent('Eve')
    bob.trust('Alice', alice.keys.public)
    return alice, bob, eve


def packet_and_bytes(alice, bob, text='secret'):
    packet = alice.make_packet('Bob', text, bob.keys.public.encryption)
    return packet, NetworkSerializer.serialize_message(packet)


def test_authenticated_encrypted_message_delivered():
    alice, bob, _ = agents()
    packet, wire = packet_and_bytes(alice, bob)
    assert b'secret' not in wire
    receipt = bob.receive(wire)
    assert receipt['status'] == 'ACCEPTED'
    assert bob.inbox[-1]['text'] == 'secret'
    assert PrivacyAgent.verify_receipt(receipt, bob.keys.public.signing)


def test_signed_delivery_receipt_rejects_modification():
    alice, bob, _ = agents()
    receipt = bob.receive(packet_and_bytes(alice, bob)[1])
    receipt['status'] = 'REJECT_SIGNATURE'
    assert not PrivacyAgent.verify_receipt(receipt, bob.keys.public.signing)


def test_untrusted_sender_rejected():
    _, bob, eve = agents()
    packet = eve.make_packet('Bob', 'hijack', bob.keys.public.encryption)
    assert bob.receive(NetworkSerializer.serialize_message(packet))['status'] == 'REJECT_UNTRUSTED'


def test_unauthorized_decryption_rejected_by_aes_gcm():
    alice, bob, eve = agents()
    packet, _ = packet_and_bytes(alice, bob)
    with pytest.raises(InvalidTag):
        decrypt_message(packet, eve.keys.encryption)


def test_tampered_ciphertext_rejected():
    alice, bob, _ = agents()
    packet, _ = packet_and_bytes(alice, bob)
    modified = deepcopy(packet)
    modified['ciphertext'] = packet['ciphertext'][:-1] + bytes([packet['ciphertext'][-1] ^ 1])
    assert bob.receive(NetworkSerializer.serialize_message(modified))['status'] == 'REJECT_SIGNATURE'
    assert not bob.inbox


def test_replay_rejected():
    alice, bob, _ = agents()
    _, wire = packet_and_bytes(alice, bob)
    assert bob.receive(wire)['status'] == 'ACCEPTED'
    assert bob.receive(wire)['status'] == 'REJECT_REPLAY'
    assert len(bob.inbox) == 1


def test_impostor_cannot_use_alices_claimed_name():
    alice, bob, eve = agents()
    forged = eve.make_packet('Bob', 'bad', bob.keys.public.encryption, claim='Alice')
    assert bob.receive(NetworkSerializer.serialize_message(forged))['status'] == 'REJECT_SIGNATURE'


def test_signed_expired_message_rejected():
    alice, bob, _ = agents()
    packet, _ = packet_and_bytes(alice, bob)
    packet['created'] = int(time.time()) - 1000
    packet['signature'] = alice.keys.signing.sign(__import__('privacy_agent_protocol.crypto.secure_message', fromlist=['signing_input']).signing_input(packet))
    assert bob.receive(NetworkSerializer.serialize_message(packet))['status'] == 'REJECT_EXPIRED'


def test_wrong_recipient_rejected():
    alice, bob, _ = agents()
    packet, _ = packet_and_bytes(alice, bob)
    packet['recipient'] = 'Charlie'
    assert bob.receive(NetworkSerializer.serialize_message(packet))['status'] == 'REJECT_RECIPIENT'


def test_packet_plaintext_size_limit():
    alice, bob, _ = agents()
    with pytest.raises(ValueError):
        alice.make_packet('Bob', 'ü' * (MAX_MESSAGE_BYTES // 2 + 1), bob.keys.public.encryption)


def test_schema_rejects_unexpected_fields():
    alice, bob, _ = agents()
    packet, _ = packet_and_bytes(alice, bob)
    packet['unexpected'] = True
    with pytest.raises(ValueError):
        NetworkSerializer.serialize_message(packet)


def test_corrupt_serialization_rejected_safely():
    _, bob, _ = agents()
    assert bob.receive(b'not-a-message')['status'] == 'REJECT_MALFORMED'


def test_rate_limiter_rejects_burst():
    alice, bob, _ = agents()
    statuses = []
    for n in range(9):
        statuses.append(bob.receive(packet_and_bytes(alice, bob, str(n))[1])['status'])
    assert statuses.count('ACCEPTED') == bob.RATE_MAX
    assert statuses.count('REJECT_RATE_LIMIT') == 3


def test_peer_key_pinning_never_silently_overwritten():
    alice, bob, eve = agents()
    with pytest.raises(ValueError):
        bob.trust('Alice', eve.keys.public)


def test_malformed_message_does_not_populate_inbox():
    _, bob, _ = agents()
    bob.receive(b'\x82')
    assert bob.inbox == []
