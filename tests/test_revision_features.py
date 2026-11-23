"""Regression tests for topology, fresh-run audits and broader protocol answers."""
from pathlib import Path
import pytest

from privacy_agent_protocol.session import ProtocolSession
from web_app import start_new_audit_run


def test_localhost_audit_is_scoped_to_a_fresh_server_run(tmp_path):
    active = tmp_path / 'data' / 'security_audit.jsonl'
    active.parent.mkdir()
    past = '{"kind":"message","id":"old"}\n'
    active.write_text(past, encoding='utf-8')
    start_new_audit_run(active)
    assert not active.exists()
    archives = list((active.parent / 'previous_sessions').glob('*.jsonl'))
    assert len(archives) == 1
    assert archives[0].read_text() == past
    start_new_audit_run(active)
    assert len(list((active.parent / 'previous_sessions').glob('*.jsonl'))) == 1


@pytest.mark.asyncio
async def test_local_assistant_answer_live_data_and_freeform_protocol_questions(monkeypatch):
    monkeypatch.delenv('MULTIAGENT_OLLAMA_MODEL', raising=False)
    session = ProtocolSession()
    await session.initialize_defaults()
    try:
        agent_answer = await session.assistant('How many trusted nodes exist right now?')
        assert agent_answer['mode'] == 'live-session-data'
        assert '2 trusted agents' in agent_answer['answer']
        result = await session.send_message('Alice', 'Bob', 'Local audit assistant question')
        latest = await session.assistant('What was the latest message sent?')
        assert result['id'] in latest['answer']
        await session.simulate_attack('replay',message_id=result['id'])
        failure = await session.assistant('Why did the last attack fail?')
        assert 'REJECT_REPLAY' in failure['answer']
        assert 'replay' in failure['answer'].lower()
        concepts = await session.assistant('Discuss metadata exposure, anonymous identities and forward secrecy')
        assert 'not anonymous' in concepts['answer'].lower()
        unrecognized = await session.assistant('Explain how to grow tomatoes in a garden')
        assert unrecognized['mode'] == 'out-of-scope'
    finally:
        await session.stop()


def test_both_graphs_use_complete_roster_and_node_placement_controls():
    root=Path(__file__).resolve().parents[1] / 'frontend'
    html=(root/'index.html').read_text(encoding='utf-8')
    js=(root/'app.js').read_text(encoding='utf-8')
    assert 'id="liveNetworkSvg"' in html
    assert 'id="attackNetworkSvg"' in html
    assert 'id="placementHint"' in html
    assert 'id="autoArrangeNodes"' in html
    assert 'function drawTopology(svg,agents,forAttack=false)' in js
    assert "drawTopology($('attackNetworkSvg'),agents,true)" in js
    assert 'localStorage.setItem' in js
    assert 'state.placingAgent=name' in js
