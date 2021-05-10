#!/usr/bin/env python3.9

import pymysql
import re
import secrets
from enum import IntFlag
from pathlib import Path
from typing import Callable
from typing import Optional

from cmyui.logging import Ansi
from cmyui.logging import log
from cmyui.mysql import AsyncSQLPool
from cmyui.web import Connection
from cmyui.web import Domain
from cmyui.web import ratelimit
from cmyui.web import Server

DATABASE: Optional[AsyncSQLPool] = None
import config as CONFIG

STATIC_PATH = Path.cwd() / 'static'

REQUIRED_HEADERS = ('User-Agent', 'Token', 'Content-Type')
SHAREX_VER_RGX = re.compile(r'^ShareX/(?P<ver>\d+\.\d+\.\d+)$')

DISAPPOINTED = (Path.cwd() / 'disappointed.jpeg').read_bytes()
FAVICON = (Path.cwd() / 'favicon.ico').read_bytes()

app = Server(name='static file server', debug=True)
domain = Domain('i.cmyui.xyz')

def fmt_bytes(n: int) -> str:
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    for suffix in suffixes:
        if n < 1024:
            break
        n /= 1024 # more to go
    return f'{n:,.2f}{suffix}'

def pymysql_encode(conv: Callable):
    """Decorator to allow for adding to pymysql's encoders."""
    def wrapper(cls):
        pymysql.converters.encoders[cls] = conv
        return cls
    return wrapper

escape_enum = lambda val, _: str(int(val)) # used with pymysql_encode

@pymysql_encode(escape_enum)
class Privileges(IntFlag):
    ACTIVE = 1 << 0      # unbanned, can use the service
    MANAGEMENT = 1 << 1  # has moderative/administrative access
    DEVELOPMENT = 1 << 2 # has full access to all features

@domain.route('/favicon.ico')
async def favicon(conn: Connection) -> bytes:
    conn.resp_headers['Cache-Control'] = 'public, max-age=604800'
    conn.resp_headers['Content-Type'] = 'image/x-icon'
    return FAVICON

@domain.route(re.compile(r'^/[^\.]+\.(?:jpeg|png)$'))
@ratelimit(period=60, max_count=20, default_return=DISAPPOINTED)
async def get(conn: Connection) -> Optional[bytes]:
    file = STATIC_PATH / conn.path[1:]
    if not file.exists():
        return (404, b'file not found')

    if file.suffix == '.png':
        conn.resp_headers['Content-Type'] = 'image/png'
    elif file.suffix == '.jpeg':
        conn.resp_headers['Content-Type'] = 'image/jpeg'
    else:
        return (400, b'') # impossible atm

    conn.resp_headers['Cache-Control'] = 'public, max-age=86400'
    return file.read_bytes()

@domain.route('/', methods=['POST'])
async def upload(conn: Connection) -> Optional[bytes]:
    if not (
        all(h in conn.headers for h in ('User-Agent', 'Token', 'Content-Type')) and
        SHAREX_VER_RGX.match(conn.headers['User-Agent'])
    ):
        return (400, b'') # invalid request

    filesize = int(conn.headers['Content-Length'])
    if not 0x40 <= filesize < 0x400 ** 3: # 64B - 1GB
        return (400, b'') # filesize invalid

    global DATABASE

    user = await DATABASE.fetch(
        'SELECT id, name, priv FROM users '
        'WHERE token = %s AND priv & 1',
        [conn.headers['Token']]
    )

    if user is None:
        return (401, b'') # unauthorized

    # ensure at least some basic
    # file signatures are correct
    # TODO: more file formats & signature checks
    if (
        conn.headers['Content-Type'] == 'image/png' and
        conn.body[:8] == b'\x89PNG\r\n\x1a\n' and
        conn.body[-8:] == b'IEND\xaeB`\x82'
    ):
        ext = 'png'
    elif (
        conn.headers['Content-Type'] == 'image/jpeg' and
        (
            (     # jfif, jpe, jpeg, jpg graphics file
                conn.body[:4] == b'\xff\xd8\xff\xe0' and
                conn.body[6:11] == b'JFIF\x00'
            ) or ( # exif digital jpg
                conn.body[:4] == b'\xff\xd8\xff\xe1' and
                conn.body[6:11] == b'Exif\x00'
            ) or ( # spiff still picture jpg
                conn.body[:4] == b'\xff\xd8\xff\xe8' and
                conn.body[6:12] == b'SPIFF\x00'
            )
        ) and
        conn.body[-2:] == b'\xff\xd9'
    ):
        ext = 'jpeg'
    elif (
        conn.headers['Content-Type'] == 'image/gif' and
        conn.body[:6] in (b'GIF87a', b'GIF89a') and
        conn.body[-2:] == b'\x00\x3b'
    ):
        ext = 'gif'
    elif ( # TODO: deeper?
        conn.headers['Content-Type'] == 'video/mp4' and
        conn.body[4:8] == b'ftyp' and
        conn.body[8:12] in (b'avc1', b'iso2', b'isom', b'mmp4', b'mp41',
                            b'mp42', b'mp71', b'msnv', b'ndas', b'ndsc',
                            b'ndsh', b'ndsm', b'ndsp', b'ndss', b'ndxc',
                            b'ndxh', b'ndxm', b'ndxp', b'ndxs')
    ):
        ext = 'mp4'
    else:
        return (400, b'') # invalid file type

    # generate a random non-existent filename
    num_chars = secrets.randbelow(9) + 8 # 8-16
    while True:
        new_file = STATIC_PATH / f'{secrets.token_urlsafe(num_chars)}.{ext}'
        if not new_file.exists():
            break

    new_file.write_bytes(conn.body)

    await DATABASE.execute(
        'INSERT INTO uploads '
        '(name, user_id, size) '
        'VALUES (%s, %s, %s)',
        [new_file.name, user['id'], filesize]
    )

    user_str = '<{name} ({id})>'.format(**user)
    log(f"{user_str} uploaded a {fmt_bytes(filesize)} {ext}", Ansi.LCYAN)
    return f'https://i.cmyui.xyz/{new_file.name}'.encode()

async def before_serving() -> None:
    global DATABASE
    DATABASE = AsyncSQLPool()
    await DATABASE.connect(CONFIG.mysql)

async def after_serving() -> None:
    global DATABASE
    if DATABASE is not None:
        await DATABASE.close()

if __name__ == '__main__':
    app.add_domain(domain)
    app.before_serving = before_serving
    app.after_serving = after_serving
    app.run('/tmp/staticserv.sock')
