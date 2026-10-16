"""Bounded cookie-authenticated loopback RPC, with a read-only method allowlist."""
import base64
import contextlib
import http.client
import ipaddress
import json
import math
import os
import signal
import stat
import urllib.parse

from .chain import integer, require
from .proof import hash_bytes
from .transaction import Invalid

MAX_RESPONSE = 65_536


def endpoint(value):
    require(type(value) is str and len(value) <= 256
            and all(32 < ord(c) < 127 for c in value) and '\\' not in value,
            'Invalid Bitcoin RPC endpoint')
    try:
        url = urllib.parse.urlsplit(value)
        require(url.scheme == 'http' and url.username is None and url.password is None
                and url.path in ('', '/') and not url.query and not url.fragment,
                'Bitcoin RPC requires a loopback HTTP root endpoint')
        address = ipaddress.ip_address(url.hostname)
        require(address.is_loopback and '%' not in url.netloc and url.port is not None,
                'Bitcoin RPC requires a literal loopback address and explicit port')
        integer(url.port, 1, 65535)
        return str(address), url.port
    except ValueError:
        raise Invalid('Invalid Bitcoin RPC endpoint') from None


def cookie_authorization(path):
    # The operator must trust ancestor directories. Never follow the final symlink.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and not info.st_mode & 0o077
                and 0 < info.st_size <= 4096, 'RPC cookie must be a private operator-owned file')
        raw = os.read(descriptor, 4097)
        require(len(raw) <= 4096, 'RPC cookie exceeds limit')
        raw = raw.removesuffix(b'\n')
        require(raw.startswith(b'__cookie__:') and len(raw) > len(b'__cookie__:')
                and all(32 < c < 127 for c in raw) and raw.count(b':') == 1,
                'Invalid Bitcoin Core cookie')
        return 'Basic ' + base64.b64encode(raw).decode('ascii')
    finally:
        os.close(descriptor)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate RPC JSON key')
        result[key] = value
    return result


def reject_constant(_):
    raise Invalid('Nonfinite RPC number')


def bounded_int(value):
    require(len(value) <= 20, 'Oversized RPC integer')
    return int(value)


def finite_float(value):
    require(len(value) <= 64, 'Oversized RPC number')
    result = float(value)
    require(math.isfinite(result), 'Nonfinite RPC number')
    return result


@contextlib.contextmanager
def collection_deadline():
    """POSIX main-thread CLI deadline; refuse to replace another active timer."""
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'An alarm is already active')
    def expired(*_):
        raise Invalid('Bitcoin collection deadline exceeded')
    old = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, 40)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


class CoreRpc:
    def __init__(self, url, cookie_path):
        self.host, self.port = endpoint(url)
        self._authorization = cookie_authorization(cookie_path)

    def __call__(self, method, params):
        require(type(params) is list, 'Invalid RPC parameters')
        if method == 'getblockchaininfo':
            require(not params, 'Invalid chain information request')
        elif method == 'getblockhash':
            require(len(params) == 1, 'Invalid block height request')
            integer(params[0], 0, 2_147_483_647)
        elif method == 'getblockheader':
            require(len(params) == 2 and type(params[1]) is bool, 'Invalid header request')
            hash_bytes(params[0])
        else:
            raise Invalid('RPC method is not allowed')
        payload = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': params}).encode()
        connection = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            connection.request('POST', '/', payload, headers={
                'Authorization': self._authorization, 'Content-Type': 'application/json',
                'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Connection': 'close',
            })
            response = connection.getresponse()
            require(response.status == 200, 'Bitcoin RPC HTTP failure')
            require(response.headers.get_content_type() == 'application/json'
                    and response.headers.get('Content-Encoding', 'identity') == 'identity'
                    and 'Transfer-Encoding' not in response.headers, 'Unsupported RPC response encoding')
            lengths = response.headers.get_all('Content-Length', [])
            require(len(lengths) == 1 and lengths[0].isascii() and lengths[0].isdigit()
                    and len(lengths[0]) <= 6, 'Invalid RPC response length')
            length = integer(int(lengths[0]), 1, MAX_RESPONSE)
            raw = response.read(length + 1)
            require(len(raw) == length, 'Truncated RPC response')
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                               parse_constant=reject_constant, parse_int=bounded_int,
                               parse_float=finite_float)
            require(type(value) is dict and set(value) == {'result', 'error', 'id'}
                    and type(value['id']) is int and value['id'] == 1 and value['error'] is None,
                    'Invalid or unsuccessful Bitcoin RPC envelope')
            return value['result']
        except (OSError, ValueError, RecursionError, http.client.HTTPException):
            # Never echo response bodies, endpoints or cookie authentication.
            raise Invalid('Bitcoin RPC request failed') from None
        finally:
            connection.close()
