import pytest
import pytest_asyncio

from privacy_agent_protocol.session import ProtocolSession, ATTACK_NAMES


@pytest_asyncio.fixture
async def session():
    session = ProtocolSession()
    await session.initialize_defaults()
    yield session
    await session.stop()


@pytest.mark.asyncio
async def test_initial_roster_and_no_financial_state(session):
    state = await session.get_state()
    assert [a['name'] for a in state['agents']] == ['Alice', 'Bob', 'Eve']
    assert [a['role'] for a in state['agents']] == ['trusted', 'trusted', 'untrusted']
    assert not any('balance' in a or 'account' in a for a in state['agents'])


@pytest.mark.asyncio
async def test_secure_message_through_actual_local_tcp(session):
    receipt = await session.send_message('Alice', 'Bob', 'Hello from Alice')
    assert receipt['status'] == 'ACCEPTED' and receipt['verified_receipt']
    inbox = await session.get_inbox('Bob')
    assert inbox['messages'][0]['text'] == 'Hello from Alice'
    assert (await session.get_state())['metrics']['delivered_messages'] == 1


@pytest.mark.asyncio
async def test_adversary_cannot_send_or_view_trusted_inbox(session):
    with pytest.raises(ValueError):
        await session.send_message('Eve', 'Bob', 'fake')
    with pytest.raises(ValueError):
        await session.send_message('Bob', 'Eve', 'forbidden')
    with pytest.raises(ValueError):
        await session.get_inbox('Eve')


@pytest.mark.asyncio
async def test_add_trusted_agent_with_pinned_peer_keys(session):
    charlie = await session.add_agent('Charlie')
    assert charlie['role'] == 'trusted'
    assert (await session.send_message('Charlie', 'Alice', 'hello'))['status'] == 'ACCEPTED'
    assert (await session.send_message('Bob', 'Charlie', 'hello2'))['status'] == 'ACCEPTED'
    with pytest.raises(ValueError):
        await session.add_agent('Charlie')


@pytest.mark.asyncio
async def test_name_rejects_bad_values(session):
    for bad in ['a', '__x', 'a/b', 'A B', 'Eve', '', 22]:
        with pytest.raises(ValueError):
            await session.add_agent(bad)


@pytest.mark.asyncio
@pytest.mark.parametrize('attack', list(ATTACK_NAMES))
async def test_all_six_real_attack_defenses_block(session, attack):
    result = await session.simulate_attack(attack, defenses_enabled=True)
    assert result['actual_blocked']
    assert result['verdict'] == 'BLOCKED'
    assert result['observed_status'].startswith('REJECT_')
    assert len(result['stages']) >= 4


@pytest.mark.asyncio
async def test_vulnerable_comparison_does_not_disable_real_protection(session):
    result = await session.simulate_attack('tamper', defenses_enabled=False)
    assert result['verdict'] == 'HYPOTHETICAL_BREACH'
    assert result['observed_status'] == 'REJECT_SIGNATURE'
    assert result['actual_blocked'] is True
    assert (await session.send_message('Alice', 'Bob', 'still secure'))['status'] == 'ACCEPTED'


@pytest.mark.asyncio
async def test_attack_scenario_does_not_modify_real_inbox(session):
    await session.simulate_attack('flood')
    assert (await session.get_inbox('Bob'))['messages'] == []
    assert (await session.send_message('Alice', 'Bob', 'real message'))['status'] == 'ACCEPTED'


@pytest.mark.asyncio
async def test_unknown_attack_and_invalid_mode(session):
    with pytest.raises(ValueError):
        await session.simulate_attack('unknown')
    with pytest.raises(ValueError):
        await session.simulate_attack('tamper', defenses_enabled='yes')


@pytest.mark.asyncio
async def test_protocol_bot_explains_implemented_cryptography(session):
    reply = await session.assistant('How does encryption work?')
    assert 'AES-256-GCM' in reply['answer']
    with pytest.raises(ValueError):
        await session.assistant('')


@pytest.mark.asyncio
async def test_audit_persistence_excludes_plaintext_and_private_secrets(tmp_path):
    path = tmp_path / 'local' / 'security_audit.jsonl'
    session = ProtocolSession(audit_path=path)
    await session.initialize_defaults()
    result = await session.send_message('Alice', 'Bob', 'Do not persist me')
    await session.simulate_attack('replay', message_id=result['id'])
    records = (await session.get_audit(all_entries=True))['entries']
    assert len(records) == 5
    assert sum(entry['kind'] == 'agent' for entry in records) == 3
    assert records[0]['kind'] == 'attack' and records[0]['message_id'] == result['id']
    assert 'Do not persist me' not in path.read_text()
    assert 'private_key' not in path.read_text()
    disclosed = (await session.get_audit(include_plaintext=True))['entries']
    assert any(record.get('plaintext') == 'Do not persist me' for record in disclosed)
    await session.stop()
    restored = ProtocolSession(audit_path=path)
    assert (await restored.get_audit(all_entries=True))['total_count'] == 5
    assert 'Do not persist me' not in str(await restored.get_audit(all_entries=True))
    assert (path.stat().st_mode & 0o777) == 0o600

@pytest.mark.asyncio
async def test_all_six_attacks_reference_custom_agent_message(session):
    await session.add_agent('Charlie')
    received = await session.send_message('Charlie', 'Bob', 'Custom user-authored security test payload')
    initial = list((await session.get_inbox('Bob'))['messages'])
    for kind in ATTACK_NAMES:
        result = await session.simulate_attack(kind, message_id=received['id'])
        assert result['target_message_id'] == received['id']
        assert result['sender'] == 'Charlie' and result['recipient'] == 'Bob'
        assert result['verdict'] == 'BLOCKED'
        assert result['actual_blocked']
        assert result['observed_status'].startswith('REJECT_')
        assert 'isolated' in result['isolation_note']
        assert result['public_evidence']['sender_signing_public_key_hex']
    assert (await session.get_inbox('Bob'))['messages'] == initial
    audit = await session.get_audit(all_entries=True)
    linked = [e for e in audit['entries'] if e['message_id'] == received['id']]
    assert sum(e['kind'] == 'attack' for e in linked) == 6
    assert sum(e['kind'] == 'message' for e in linked) == 1
