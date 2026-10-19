"""Temporary fixed-destination relay for local installation, never offline runtime."""

import asyncio


ROUTES = {
    30944: ("node", 9944),
    38088: ("indexer", 8088),
    36300: ("proof-server", 6300),
}


async def forward(source, destination):
    try:
        while data := await source.read(65536):
            destination.write(data)
            await destination.drain()
    finally:
        if destination.can_write_eof():
            destination.write_eof()


async def handle(client_reader, client_writer, destination):
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(*destination)
        try:
            await asyncio.gather(
                forward(client_reader, upstream_writer),
                forward(upstream_reader, client_writer),
            )
        finally:
            upstream_writer.close()
            await upstream_writer.wait_closed()
    except (OSError, ConnectionError):
        pass
    finally:
        client_writer.close()
        await client_writer.wait_closed()


async def main():
    servers = []
    for local_port, destination in ROUTES.items():
        server = await asyncio.start_server(
            lambda reader, writer, target=destination: handle(reader, writer, target),
            "0.0.0.0",
            local_port,
        )
        servers.append(server)
    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
