"""Entrypoint for local multi-agent encrypted messaging and attack experiments."""
import argparse
import asyncio

from privacy_agent_protocol.session import ATTACK_NAMES, ProtocolSession


async def demo() -> None:
    session = ProtocolSession()
    await session.initialize_defaults()
    try:
        print('PRIVACY-PRESERVING MULTI-AGENT COMMUNICATION')
        print('LOCAL RESEARCH DEMO — no transfers, balances, or settlement features')
        print('Agents:', ', '.join(a['name'] for a in (await session.get_state())['agents']))
        sent = await session.send_message('Alice', 'Bob', 'Hello Bob — authenticated encrypted message')
        print(f'Secure message Alice -> Bob: {sent["status"]} (verified signed receipt: {sent["verified_receipt"]})')
        print('\nPROTECTED ATTACK EXPERIMENTS')
        for attack in ATTACK_NAMES:
            outcome = await session.simulate_attack(attack)
            print(f'  {outcome["label"]:28} {outcome["observed_status"]:20} {outcome["verdict"]}')
        print('\nThis does not demonstrate anonymous identities or full forward secrecy.')
    finally:
        await session.stop()


async def cli() -> None:
    session = ProtocolSession()
    await session.initialize_defaults()
    try:
        print('Multi-Agent Communication CLI. Commands: agents, send, inbox, attack, quit')
        while True:
            cmd = input('\nCommand> ').strip().lower()
            if cmd in {'quit', 'exit', 'q'}:
                break
            if cmd == 'agents':
                for a in (await session.get_state())['agents']:
                    print(a)
            elif cmd == 'send':
                sender = input('Sender: ').strip()
                recipient = input('Recipient: ').strip()
                message = input('Message: ')
                try:
                    print(await session.send_message(sender, recipient, message))
                except (ValueError, RuntimeError) as exc:
                    print('Error:', exc)
            elif cmd == 'inbox':
                name = input('Agent name: ').strip()
                try:
                    for m in (await session.get_inbox(name))['messages']:
                        print(f'{m["sender"]} [{m["id"][:8]}]: {m["text"]}')
                except ValueError as exc:
                    print('Error:', exc)
            elif cmd == 'attack':
                print('Types:', ', '.join(ATTACK_NAMES))
                kind = input('Type: ').strip().lower()
                if kind in ATTACK_NAMES:
                    r = await session.simulate_attack(kind)
                    print(r['label'], r['observed_status'], r['verdict'])
                else:
                    print('Unknown attack')
            else:
                print('Commands: agents, send, inbox, attack, quit')
    finally:
        await session.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Privacy-Preserving Multi-Agent Communication: local security lab')
    parser.add_argument('--web', action='store_true', help='Run integrated dashboard and API')
    parser.add_argument('--cli', action='store_true', help='Interactive terminal')
    parser.add_argument('--simulate', action='store_true', help='Run console protocol and attack demo')
    parser.add_argument('--port', type=int, default=8000, help='Dashboard port, loopback only')
    args = parser.parse_args()
    if args.web:
        from web_app import run_server
        run_server(args.port)
    elif args.cli:
        asyncio.run(cli())
    else:
        asyncio.run(demo())
