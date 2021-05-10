#!/usr/bin/env python3.9

import re
import secrets
from pathlib import Path
from typing import Optional

from cmyui.logging import Ansi
from cmyui.logging import log
from cmyui.web import Connection
from cmyui.web import Domain
from cmyui.web import ratelimit
from cmyui.web import Server

REQUIRED_HEADERS = ('User-Agent', 'Token', 'Content-Type')
SHAREX_VER_RGX = re.compile(r'^ShareX/(?:\d+\.\d+\.\d+)$')
SHIT_PATH = Path.cwd() / 'shit'
DISAPPOINTED = (Path.cwd() / 'disappointed.jpeg').read_bytes()

TOKENS = { # TODO: db or smth
    'w8y9W50f5RxPJyw1fXxWrUsgBwq7KT4Mwiaq5buscwM',
}

app = Server(name='static file server', debug=True)
domain = Domain('i.cmyui.xyz')

@domain.route(re.compile(r'^/[^\.]+\.(?:jpeg|png)$'))
@ratelimit(period=60, max_count=20, default_return=DISAPPOINTED)
async def get(conn: Connection) -> Optional[bytes]:
    file = SHIT_PATH / conn.path[1:]
    if not file.exists():
        return (404, b'file not found')

    if file.suffix == '.png':
        conn.resp_headers['Content-Type'] = 'image/png'
    elif file.suffix == '.jpeg':
        conn.resp_headers['Content-Type'] = 'image/jpeg'
    else:
        return (400, b'') # impossible atm

    return file.read_bytes()

@domain.route('/', methods=['POST'])
async def upload(conn: Connection) -> Optional[bytes]:
    if not (
        all(h in conn.headers for h in ('User-Agent', 'Token', 'Content-Type')) and
        SHAREX_VER_RGX.match(conn.headers['User-Agent'])
    ):
        return (400, b'') # invalid request

    token = conn.headers['Token']
    if token not in TOKENS:
        return (401, b'') # unauthorized

    # check file headers
    if (
        conn.headers['Content-Type'] == 'image/jpeg' and
        conn.body[6:10] in (b'JFIF', b'Exif')
    ):
        ext = 'jpeg'
    elif (
        conn.headers['Content-Type'] == 'image/png' and
        conn.body.startswith(b'\211PNG\r\n\032\n')
    ):
        ext = 'png'
    else: # ^ TODO more
        return (400, b'') # invalid file type

    num_chars = secrets.randbelow(9) + 8 # 8-16
    while True:
        new_file = SHIT_PATH / f'{secrets.token_urlsafe(num_chars)}.{ext}'
        if not new_file.exists():
            break

    new_file.write_bytes(conn.body)
    return (200, f'https://i.cmyui.xyz/{new_file.name}'.encode())

if __name__ == '__main__':
    app.add_domain(domain)
    app.run('/tmp/staticserv.sock')
