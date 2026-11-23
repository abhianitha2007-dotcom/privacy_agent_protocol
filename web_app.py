"""Loopback-only web UI/API for the multi-agent communication laboratory."""
from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit, unquote, parse_qs

from privacy_agent_protocol.session import ProtocolSession

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / 'frontend'
_session: ProtocolSession | None = None
_loop: asyncio.AbstractEventLoop | None = None
_guard = threading.Lock()


def start_new_audit_run(audit_file: Path) -> None:
    """Rotate previous process metadata so a new run starts with fresh logs."""
    if audit_file.exists() and audit_file.stat().st_size:
        archives = audit_file.parent / 'previous_sessions'
        archives.mkdir(parents=True, exist_ok=True)
        archive_name = time.strftime('%Y%m%d_%H%M%S', time.gmtime()) + '_' + uuid.uuid4().hex[:8] + '.jsonl'
        audit_file.replace(archives / archive_name)


def get_session() -> tuple[ProtocolSession, asyncio.AbstractEventLoop]:
    global _session, _loop
    with _guard:
        if _session is None:
            loop = asyncio.new_event_loop()
            threading.Thread(target=lambda: _loop_worker(loop), daemon=True, name='multiagent-security-loop').start()

            async def setup():
                # Keep Section 3 scoped to this server run; archive old metadata.
                audit_file = ROOT / 'data' / 'security_audit.jsonl'
                start_new_audit_run(audit_file)
                session = ProtocolSession(audit_path=audit_file)
                await session.initialize_defaults()
                return session

            session = asyncio.run_coroutine_threadsafe(setup(), loop).result(timeout=10)
            _loop, _session = loop, session
    return _session, _loop


def _loop_worker(loop: asyncio.AbstractEventLoop) -> None:
    asyncio.set_event_loop(loop)
    loop.run_forever()


def execute(coroutine):
    _, loop = get_session()
    return asyncio.run_coroutine_threadsafe(coroutine, loop).result(timeout=15)


class AppHandler(BaseHTTPRequestHandler):
    server_version = 'MultiAgentSecurityLab/3.0'
    protocol_version = 'HTTP/1.1'

    def setup(self) -> None:
        super().setup()
        # A stalled localhost client must not occupy a handler thread forever.
        self.connection.settimeout(8)

    def _headers(self, code: int, content_type: str, size: int) -> None:
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()

    def _send(self, code: int, data: bytes, mime: str) -> None:
        self._headers(code, mime, len(data))
        self.wfile.write(data)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), 'application/json; charset=utf-8')

    def _error(self, code: int, description: str) -> None:
        self._json(code, {'error': description})

    def _allowed_origin(self) -> bool:
        # The server is intentionally never made reachable from other machines.
        host = self.headers.get('Host', '')
        if host not in {'localhost', '127.0.0.1'} and not (
            host.startswith('localhost:') or host.startswith('127.0.0.1:')):
            return False
        origin = self.headers.get('Origin')
        if not origin:
            return True
        parts = urlsplit(origin)
        return (parts.scheme == 'http' and parts.netloc == host and parts.path == ''
                and not parts.username and not parts.password)

    def _read_json(self) -> dict:
        length_text = self.headers.get('Content-Length', '')
        if not length_text.isdigit():
            raise ValueError('Missing or invalid Content-Length')
        length = int(length_text)
        if length < 2 or length > 16_384:
            raise ValueError('JSON body must be between 2 and 16384 bytes')
        if self.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
            raise ValueError('Content-Type must be application/json')
        obj = json.loads(self.rfile.read(length))
        if not isinstance(obj, dict):
            raise ValueError('JSON body must be an object')
        return obj

    def do_GET(self) -> None:
        if not self._allowed_origin():
            return self._error(403, 'Invalid Host or cross-origin request')
        path = urlsplit(self.path).path
        try:
            if path == '/api/health':
                return self._json(200, {'status': 'ok', 'protocol': 'v2', 'mode': 'loopback-only'})
            if path == '/api/audit':
                session, _ = get_session()
                opts = parse_qs(urlsplit(self.path).query)
                include = opts.get('include_plaintext') == ['1']
                all_entries = opts.get('all') == ['1']
                return self._json(200, execute(session.get_audit(include_plaintext=include, all_entries=all_entries)))
            if path == '/api/state':
                session, _ = get_session()
                return self._json(200, execute(session.get_state()))
            if path.startswith('/api/inbox/'):
                name = unquote(path[len('/api/inbox/'):])
                if '/' in name or not name:
                    return self._error(404, 'Unknown agent')
                session, _ = get_session()
                return self._json(200, execute(session.get_inbox(name)))
            files = {'/': ('index.html', 'text/html; charset=utf-8'),
                     '/index.html': ('index.html', 'text/html; charset=utf-8'),
                     '/styles.css': ('styles.css', 'text/css; charset=utf-8'),
                     '/app.js': ('app.js', 'text/javascript; charset=utf-8')}
            if path in files:
                filename, mime = files[path]
                return self._send(200, (STATIC / filename).read_bytes(), mime)
            return self._error(404, 'Not found')
        except ValueError as exc:
            return self._error(400, str(exc))
        except Exception as exc:
            print('GET handler failure:', type(exc).__name__, str(exc))
            return self._error(500, 'Server operation failed')

    def do_POST(self) -> None:
        if not self._allowed_origin():
            return self._error(403, 'Invalid Host or cross-origin request')
        path = urlsplit(self.path).path
        if path not in {'/api/messages', '/api/agents', '/api/simulations', '/api/assistant'}:
            return self._error(404, 'Not found')
        try:
            data = self._read_json()
            session, _ = get_session()
            if path == '/api/messages':
                payload = execute(session.send_message(data.get('sender'), data.get('recipient'), data.get('text')))
            elif path == '/api/agents':
                payload = execute(session.add_agent(data.get('name'), approved=True))
            elif path == '/api/simulations':
                payload = execute(session.simulate_attack(data.get('attack'), defenses_enabled=data.get('defenses_enabled', True), message_id=data.get('message_id')))
            else:
                payload = execute(session.assistant(data.get('question')))
            return self._json(200, payload)
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return self._error(400, str(exc))
        except Exception as exc:
            print('POST handler failure:', type(exc).__name__, str(exc))
            return self._error(500, 'Server operation failed')

    def log_message(self, format_string: str, *args) -> None:
        # Do not log message bodies or secrets.
        print(f'[http] {self.address_string()} {format_string % args}')


def run_server(port: int = 8000) -> None:
    if not (0 <= port <= 65535):
        raise ValueError('Port must be in range 0 to 65535')
    get_session()
    httpd = ThreadingHTTPServer(('127.0.0.1', port), AppHandler)
    actual_port = httpd.server_address[1]
    print(f'Multi-Agent Secure Communication Lab at http://127.0.0.1:{actual_port}', flush=True)
    print('LOCAL RESEARCH DEMO ONLY. No browser login. Do not expose this server publicly.', flush=True)
    try:
        httpd.serve_forever(poll_interval=0.2)
    finally:
        httpd.server_close()
        if _session and _loop:
            try:
                asyncio.run_coroutine_threadsafe(_session.stop(), _loop).result(timeout=5)
            finally:
                _loop.call_soon_threadsafe(_loop.stop)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Privacy-Preserving Multi-Agent Communication dashboard')
    parser.add_argument('--port', type=int, default=8000)
    run_server(parser.parse_args().port)
