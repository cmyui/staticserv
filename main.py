#!/usr/bin/env python3.9

import pymysql
import re
import secrets
from enum import IntFlag
from pathlib import Path
from typing import Callable
from typing import Optional
from typing import Type
from typing import Union

from cmyui.logging import Ansi
from cmyui.logging import log
from cmyui.mysql import AsyncSQLPool
from cmyui.web import Connection
from cmyui.web import Domain
from cmyui.web import ratelimit
from cmyui.web import Server

WebResponse = Union[bytes, tuple[int, bytes]]

# constants

import config as CONFIG

SQL_DB: AsyncSQLPool

STATIC_PATH = Path.cwd() / 'static'

SHAREX_VER_RGX = re.compile(r'^ShareX/(?P<ver>\d+\.\d+\.\d+)$')

DISAPPOINTED = (Path.cwd() / 'disappointed.jpeg').read_bytes()
FAVICON = (Path.cwd() / 'favicon.ico').read_bytes()

# supported filetype checks

SUPPORTED_FILES = {}

def register_filetype(mime_type: str, extension: str) -> Callable:
    def wrapper(condition: Callable) -> Callable:
        SUPPORTED_FILES[mime_type] = {
            'extension': extension,
            'condition': condition
        }
        return condition
    return wrapper

@register_filetype('image/png', 'png')
def png_condition(body: bytes) -> bool:
    return (
        body[:8] == b'\x89PNG\r\n\x1a\n' and
        body[-8:] == b'\x49END\xae\x42\x60\x82'
    )

@register_filetype('image/jpeg', 'jpeg')
def jpeg_condition(body: bytes) -> bool:
    return (
        # jfif, jpe, jpeg, jpg graphics file
        body[:4] == b'\xff\xd8\xff\xe0' and
        body[6:11] == b'JFIF\x00'
    ) or (
        # exif digital jpg
        body[:4] == b'\xff\xd8\xff\xe1' and
        body[6:11] == b'Exif\x00'
    ) or (
        # spiff still picture jpg
        body[:4] == b'\xff\xd8\xff\xe8' and
        body[6:12] == b'SPIFF\x00'
    )

@register_filetype('image/gif', 'gif')
def gif_condition(body: bytes) -> bool:
    return (
        body[:6] in (b'GIF87a', b'GIF89a') and
        body[-2:] == b'\x00\x3b'
    )

@register_filetype('image/bmp', 'bmp')
def bmp_condition(body: bytes) -> bool:
    return body[:2] == b'\x42\x4d'

MP4_TYPES = (
    b'avc1', b'iso2', b'isom', b'mmp4',
    b'mp41', b'mp42', b'mp71', b'msnv',
    b'ndas', b'ndsc', b'ndsh', b'ndsm',
    b'ndsp', b'ndss', b'ndxc', b'ndxh',
    b'ndxm', b'ndxp', b'ndxs'
)
@register_filetype('video/mp4', 'mp4')
def mp4_condition(body: bytes) -> bool:
    return (
        body[4:8] == b'ftyp' and
        body[8:12] in MP4_TYPES
    )

@register_filetype('video/webm', 'webm')
def webm_condition(body: bytes) -> bool:
    return body[:4] == b'\x1a\x45\xdf\xa3'

@register_filetype('image/vnd.adobe.photoshop', 'psd')
def psd_condition(body: bytes) -> bool:
    return body[:4] == b'8BPS'

@register_filetype('image/vnd.radiance', 'hdr')
def hdr_condition(body: bytes) -> bool:
    return body[:11] == b'#?RADIANCE\n'

# helper functions and such

BYTE_ORDER_SUFFIXES = ['B', 'KB', 'MB', 'GB', 'TB',
                       'PB', 'EB', 'ZB', 'YT']
def fmt_bytes(n: Union[int, float]) -> str:
    for suffix in BYTE_ORDER_SUFFIXES:
        if n < 1024:
            break
        n /= 1024 # more to go
    return f'{n:,.2f}{suffix}'

def pymysql_encode(conv: Callable) -> Callable:
    """Decorator to allow for adding to pymysql's encoders."""
    def wrapper(cls: Type[object]) -> Type[object]:
        pymysql.converters.encoders[cls] = conv
        return cls
    return wrapper

escape_enum = lambda val, _: str(int(val)) # used with pymysql_encode

# user privileges

@pymysql_encode(escape_enum)
class Privileges(IntFlag):
    ACTIVE = 1 << 0      # unbanned, can use the service
    MANAGEMENT = 1 << 1  # has moderative/administrative access
    DEVELOPMENT = 1 << 2 # has full access to all features

# create server/domain & add our routes to it
app = Server(name='static file server', debug=True)
domain = Domain('i.cmyui.xyz')

@domain.route('/favicon.ico')
async def favicon(conn: Connection) -> bytes:
    conn.resp_headers['Cache-Control'] = 'public, max-age=604800'
    conn.resp_headers['Content-Type'] = 'image/x-icon'
    return FAVICON

@domain.route(re.compile(r'^/[\w-]{11,22}\.(?:jpeg|png|gif|bmp|mp4|webm|psd|hdr)$'))
@ratelimit(period=60, max_count=15, default_return=DISAPPOINTED)
async def get(conn: Connection) -> Optional[WebResponse]:
    file = STATIC_PATH / conn.path[1:]
    if not file.exists():
        return (404, b'file not found')

    for mime_type, file_info in SUPPORTED_FILES.items():
        if file.suffix == f".{file_info['extension']}":
            conn.resp_headers['Content-Type'] = mime_type
            break
    else:
        return (400, b'') # impossible filetype

    conn.resp_headers['Cache-Control'] = 'public, max-age=86400'
    return file.read_bytes()

REQUIRED_UPLOAD_HEADERS = (
    'User-Agent', 'Token', 'Content-Type'
)
@domain.route('/', methods=['POST'])
async def upload(conn: Connection) -> Optional[WebResponse]:
    if not (
        all(h in conn.headers for h in REQUIRED_UPLOAD_HEADERS) and
        SHAREX_VER_RGX.match(conn.headers['User-Agent'])
    ):
        return (400, b'') # invalid request

    filesize = int(conn.headers['Content-Length'])
    if not 0x40 <= filesize < 0x400 ** 3: # 64B - 1GB
        return (400, b'') # filesize invalid

    global SQL_DB

    user = await SQL_DB.fetch(
        'SELECT id, name, priv FROM users '
        'WHERE token = %s AND priv & 1',
        [conn.headers['Token']]
    )

    if user is None:
        return (401, b'') # unauthorized

    mime_type = conn.headers['Content-Type']
    if mime_type not in SUPPORTED_FILES:
        return (400, b'') # unsupported filetype

    filetype = SUPPORTED_FILES[mime_type]

    if filetype['condition'](conn.body): # type: ignore
        # file contents match the mime type
        ext = filetype['extension']
    else:
        return (400, b'') # invalid file type

    # generate a random non-existent filename
    num_chars = secrets.randbelow(9) + 8 # 8-16
    while True:
        new_file = STATIC_PATH / f'{secrets.token_urlsafe(num_chars)}.{ext}'
        if not new_file.exists():
            break

    new_file.write_bytes(conn.body)

    await SQL_DB.execute(
        'INSERT INTO uploads '
        '(name, user_id, size) '
        'VALUES (%s, %s, %s)',
        [new_file.name, user['id'], filesize]
    )

    user_str = '<{name} ({id})>'.format(**user)
    log(f"{user_str} uploaded a {fmt_bytes(filesize)} {ext} file.", Ansi.LCYAN)
    return f'https://i.cmyui.xyz/{new_file.name}'.encode()

async def before_serving() -> None:
    global SQL_DB
    SQL_DB = AsyncSQLPool()
    await SQL_DB.connect(CONFIG.mysql)

async def after_serving() -> None:
    global SQL_DB
    if SQL_DB is not None:
        await SQL_DB.close()

if __name__ == '__main__':
    app.add_domain(domain)
    app.before_serving = before_serving
    app.after_serving = after_serving
    app.run('/tmp/staticserv.sock')
