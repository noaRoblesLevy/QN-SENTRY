"""Decoy for issue #2: answers every connection with an SSH banner and closes it.

There is no SSH server behind it: no login and no shell. A port scanner only
sees the banner and reports an (outdated) OpenSSH version.

No connection stays open (the banner is sent and the connection is closed at once), so
a flood of connections from bots costs almost nothing and needs no connection limit.

The addresses of the clients are never logged: on the internet that is every scanner
and bot, and IP addresses are personal data under the GDPR (legal framework 5.3).
"""

import asyncio
import logging

BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
PORT = 2222


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        writer.write(BANNER)
        await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


async def main() -> None:
    server = await asyncio.start_server(handle, host="0.0.0.0", port=PORT)
    logging.info("Decoy SSH banner listening on port %s", PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    asyncio.run(main())
