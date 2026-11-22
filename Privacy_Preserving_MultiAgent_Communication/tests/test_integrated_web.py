"""Integration coverage for the final integrated browser/API project."""
from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from web_app import AppHandler


@pytest.fixture(scope='module')
def server_url():
    server = ThreadingHTTPServer(('127.0.0.1', 0), AppHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def get(base, path):
    with urlopen(base + path, timeout=5) as response:
        return response.status, response.read(), dict(response.headers)


def post(base, path, obj):
    payload = json.dumps(obj).encode('utf-8')
    request = Request(base + path, data=payload,
                      headers={'Content-Type': 'application/json'}, method='POST')
    with urlopen(request, timeout=5) as response:
        return response.status, json.loads(response.read())


def test_web_frontend_and_health(server_url):
    status, html, headers = get(server_url, '/')
    assert status == 200 and b'MULTI' in html and b'AGENT' in html
    assert b'Communication &amp;' in html and b'Attack Simulator' in html
    assert html.count(b'<section class="page') == 5
    assert b'page-communication' not in html
    assert b'Cryptographic Operations &amp; Security Audit' in html
    assert b'Trust is a' not in html and b'Make security' not in html
    assert b'Transfer Studio' not in html and b'Cluster Nodes' not in html
    assert headers['X-Content-Type-Options'] == 'nosniff'
    for asset in ('/styles.css', '/app.js'):
        status, content, _ = get(server_url, asset)
        assert status == 200 and len(content) > 2000
    assert json.loads(get(server_url, '/api/health')[1])['status'] == 'ok'


def test_api_secure_communication_and_agent_management(server_url):
    status, state_bytes, _ = get(server_url, '/api/state')
    state = json.loads(state_bytes)
    assert status == 200
    assert [a['name'] for a in state['agents'][:3]] == ['Alice', 'Bob', 'Eve']
    assert [a['role'] for a in state['agents'][:3]] == ['trusted', 'trusted', 'untrusted']
    code, message = post(server_url, '/api/messages', {
        'sender': 'Alice', 'recipient': 'Bob', 'text': 'Encrypted HTTP integration test'
    })
    assert code == 200 and message['status'] == 'ACCEPTED'
    assert message['verified_receipt'] is True
    inbox = json.loads(get(server_url, '/api/inbox/Bob')[1])
    assert inbox['messages'][0]['text'] == 'Encrypted HTTP integration test'
    status, new_agent = post(server_url, '/api/agents', {'name': 'WebTester'})
    assert status == 200 and new_agent['role'] == 'trusted'
    assert post(server_url, '/api/messages', {
        'sender': 'WebTester', 'recipient': 'Alice', 'text': 'New peer verified'
    })[1]['status'] == 'ACCEPTED'


@pytest.mark.parametrize('attack', ['tamper', 'replay', 'impersonation', 'decryption', 'oversized', 'flood'])
def test_api_attack_types_have_different_real_checks(server_url, attack):
    status, result = post(server_url, '/api/simulations', {'attack': attack, 'defenses_enabled': True})
    assert status == 200
    assert result['verdict'] == 'BLOCKED' and result['actual_blocked']
    assert result['observed_status'].startswith('REJECT_')
    assert len(result['stages']) >= 4
    assert result['attack'] == attack


def test_comparison_mode_is_explicitly_hypothetical(server_url):
    _, result = post(server_url, '/api/simulations', {'attack': 'replay', 'defenses_enabled': False})
    assert result['actual_blocked'] is True
    assert result['verdict'] == 'HYPOTHETICAL_BREACH'
    assert result['mode'] == 'hypothetical-unprotected-comparison'


def test_invalid_calls_and_removed_financial_routes(server_url):
    for path in ('/api/transfers', '/api/credits', '/api/balances', '/api/settlements'):
        with pytest.raises(HTTPError) as err:
            get(server_url, path)
        assert err.value.code == 404
    with pytest.raises(HTTPError) as err:
        post(server_url, '/api/messages', {'sender': 'Eve', 'recipient': 'Bob', 'text': 'forged'})
    assert err.value.code == 400
    with pytest.raises(HTTPError) as err:
        get(server_url, '/api/inbox/Eve')
    assert err.value.code == 400
    with pytest.raises(HTTPError) as err:
        request = Request(server_url + '/api/state', headers={'Origin': 'http://malicious.example'})
        urlopen(request, timeout=5)
    assert err.value.code == 403


class _Ids(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
    def handle_starttag(self, tag, attrs):
        self.ids.update(v for k, v in attrs if k == 'id')


def test_frontend_uses_all_six_scenarios_and_is_wired_to_api():
    root = Path(__file__).resolve().parents[1] / 'frontend'
    html = (root / 'index.html').read_text()
    js = (root / 'app.js').read_text()
    css = (root / 'styles.css').read_text()
    ids = _Ids()
    ids.feed(html)
    for name in ('simTheater','runAttack','pauseAttack','stepAttack','resetAttack',
                 'messageForm','senderSelect','recipientSelect','inboxList',
                 'agentGrid','attackTimeline','experimentHistory','assistantForm'):
        assert name in ids.ids
        assert f"$('{name}')" in js or f"$('{name}')" in js
    for attack in ('tamper','replay','impersonation','decryption','oversized','flood'):
        assert f'data-attack="{attack}"' in html or f"'{attack}'" in js
        assert f"data-attack='{attack}'" in css
    assert '/api/messages' in js and '/api/simulations' in js and '/api/agents' in js
    assert '#d4fa61' in css and '#f36c4a' in css and '#eeeee2' in css
    assert 'Transfer Studio' not in html and '/api/transfers' not in js
    for name in ('targetMessageSelect','liveNetworkSvg','auditEntries','auditDetails','auditSearch','auditFilter','auditPlaintext','auditExportJson','auditExportCsv'):
        assert name in ids.ids
    assert '/api/audit' in js


def test_message_target_linked_attack_and_full_audit(server_url):
    _, agent = post(server_url, '/api/agents', {'name': 'TraceAgent'})
    assert agent['role'] == 'trusted'
    _, sent = post(server_url, '/api/messages', {
        'sender': 'TraceAgent', 'recipient': 'Bob', 'text': 'Real user-authored payload for audit testing',
    })
    assert sent['status'] == 'ACCEPTED'
    snapshot = json.loads(get(server_url, '/api/state')[1])
    assert any(x['id'] == sent['id'] for x in snapshot['messages'])
    _, result = post(server_url, '/api/simulations', {
        'attack': 'impersonation', 'defenses_enabled': True, 'message_id': sent['id'],
    })
    assert result['target_message_id'] == sent['id']
    assert result['sender'] == 'TraceAgent' and result['recipient'] == 'Bob'
    assert result['observed_status'] == 'REJECT_SIGNATURE'
    assert 'isolated' in result['isolation_note']
    assert all('Alice' not in s['detail'] for s in result['stages'])
    data = json.loads(get(server_url, '/api/audit?all=1')[1])
    matches = [entry for entry in data['entries'] if entry.get('message_id') == sent['id']]
    assert {'message', 'attack'} <= {entry['kind'] for entry in matches}
    message = next(entry for entry in matches if entry['kind'] == 'message')
    assert message['status'] == 'ACCEPTED'
    assert message['details']['signature_algorithm'] == 'Ed25519'
    assert message['details']['encryption'] == 'AES-256-GCM'
    assert message['details']['receipt_verified'] is True
    assert len(message['details']['authentication_tag_hex']) == 32
    assert 'plaintext' not in message
    assert len(message['details']['sender_signing_public_key_hex']) == 64
    assert len(message['details']['recipient_encryption_public_key_hex']) == 64
    assert any(x['kind'] == 'agent' and x['sender'] == 'TraceAgent' for x in data['entries'])
    raw = json.dumps(data).lower()
    assert 'real user-authored payload for audit testing' not in raw
    assert 'private_key' not in raw
    disclosed = json.loads(get(server_url, '/api/audit?include_plaintext=1')[1])
    inspect = next(entry for entry in disclosed['entries'] if entry['kind'] == 'message' and entry['message_id'] == sent['id'])
    assert inspect['plaintext'] == 'Real user-authored payload for audit testing'
    inbox = json.loads(get(server_url, '/api/inbox/Bob')[1])
    assert sum(x['id'] == sent['id'] for x in inbox['messages']) == 1
    with pytest.raises(HTTPError) as exc:
        post(server_url, '/api/simulations', {'attack': 'tamper', 'message_id': 'unknown'})
    assert exc.value.code == 400
