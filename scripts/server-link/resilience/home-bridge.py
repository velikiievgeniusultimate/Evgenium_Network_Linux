#!/usr/bin/env python3
"""Loopback-only entry to the restricted home SSH relay, at most eight streams."""
import asyncio

active = 0
SSH = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes',
       '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes',
       '-o', 'HostKeyAlias=starfive', '-o', 'ConnectTimeout=5',
       '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax=2',
       '-o', 'UserKnownHostsFile=/etc/evgenium-home-relay/known_hosts',
       '-i', '/etc/evgenium-home-relay/id_ed25519', '-p', '5555',
       'Evgenius@109.194.67.159']

async def pump(reader, writer):
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()

async def handle(reader, writer):
    global active
    if active >= 8:
        writer.close()
        return
    active += 1
    process = None
    tasks = []
    try:
        process = await asyncio.create_subprocess_exec(*SSH, stdin=asyncio.subprocess.PIPE,
                                                       stdout=asyncio.subprocess.PIPE)
        tasks = [asyncio.create_task(pump(reader, process.stdin)),
                 asyncio.create_task(pump(process.stdout, writer))]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (OSError, ConnectionError) as exc:
        print(type(exc).__name__, flush=True)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), 3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        active -= 1

async def main():
    server = await asyncio.start_server(handle, '127.0.0.1', 24551)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
