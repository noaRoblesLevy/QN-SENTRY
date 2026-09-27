"""Decoy for issue #2: answers every connection with an SSH banner and closes it.

There is no SSH server behind it: no login and no shell. A port scanner only
sees the banner and reports an (outdated) OpenSSH version.
"""

import asyncio
import logging

BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
PORT = 2222


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    logging.info("Connection from %s", writer.get_extra_info("peername"))
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
