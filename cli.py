"""Compatibility CLI entrypoint for the redesigned non-financial demo."""
import asyncio
from main import cli

if __name__ == '__main__':
    asyncio.run(cli())
