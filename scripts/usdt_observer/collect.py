"""Explicit, bounded read-only collection from one operator-selected source RPC."""
import contextlib
import http.client
import ipaddress
import json
import signal
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .networks import EVM_CHAIN_IDS
from .common import MAX_JSON, Invalid, integer, parse_json, quantity, require, word


def endpoint_url(value):
    require(type(value) is str and len(value) <= 2048
            and all(32 < ord(c) < 127 for c in value) and '\\' not in value,
            'invalid source endpoint')
    try:
        url = urllib.parse.urlsplit(value)
        require(url.hostname and url.username is None and url.password is None and not url.query and not url.fragment,
                'endpoint credentials, queries and fragments are unsupported')
        if url.port is not None:
            require(0 < url.port < 65536, 'invalid endpoint port')
        local = False
        try:
            local = ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            pass
        require(url.scheme == 'https' or (url.scheme == 'http' and local), 'HTTPS source required')
        return value, local
    except ValueError:
        raise Invalid('invalid source endpoint') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise Invalid('source redirects are refused')


@contextlib.contextmanager
def collection_deadline():
    """CLI/main-thread wall limit, including DNS, TLS and slow response bodies."""
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
            'a collection alarm is already active')
    def expired(*_):
        raise Invalid('source collection exceeded deadline')
    old = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 40)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


class HttpSource:
    def __init__(self, endpoint):
        self.endpoint, self.loopback = endpoint_url(endpoint)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def post(self, path, payload):
        # `path` is selected exclusively from constants below, never RPC data.
        url = self.endpoint if not path else self.endpoint.rstrip('/') + path
        request = urllib.request.Request(url, data=json.dumps(payload, allow_nan=False).encode(), headers={
            'Content-Type': 'application/json', 'Accept': 'application/json',
            'User-Agent': 'PosternUSDTObserver/1.0', 'Accept-Encoding': 'identity'})
        try:
            with self.opener.open(request, timeout=5) as response:
                require(response.status == 200, 'source HTTP request failed')
                require(response.headers.get_content_type() == 'application/json', 'source response is not JSON')
                require(response.headers.get('Content-Encoding', 'identity') == 'identity',
                        'compressed HTTP responses are unsupported')
                lengths = response.headers.get_all('Content-Length', [])
                declared = None
                if lengths:
                    require(len(lengths) == 1 and lengths[0].isascii() and lengths[0].isdigit()
                            and 'Transfer-Encoding' not in response.headers,
                            'ambiguous HTTP response length')
                    declared = int(lengths[0])
                    require(0 < declared <= MAX_JSON, 'declared source response exceeds limit')
                raw = response.read(MAX_JSON + 1)
                require(declared is None or len(raw) == declared, 'truncated source response')
                return parse_json(raw)
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
            raise Invalid('source HTTP request failed') from None

    def eth(self, method, params):
        payload = self.post('', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
        require(type(payload) is dict and set(payload) == {'jsonrpc', 'id', 'result'}
                and payload['jsonrpc'] == '2.0' and type(payload['id']) is int and payload['id'] == 1,
                'invalid source JSON-RPC envelope')
        return payload['result']


def collect(route, tx_hash, source):
    """Return the exact adapters' evidence shape, never a mint authorization.

    The caller must apply the chain-specific validator to the returned values.
    The canonical block is fetched again after the reported finality boundary;
    a changed view is rejected. This is not a light-client finality proof.
    """
    txid = word(tx_hash, 32)
    require(any(txid), 'zero transaction ID')
    tx_hash = '0x' + txid.hex()
    if route['network'] in EVM_CHAIN_IDS:
        chain_id = source.eth('eth_chainId', [])
        require(quantity(chain_id) == EVM_CHAIN_IDS[route['network']], 'wrong EVM source chain')
        genesis = source.eth('eth_getBlockByNumber', ['0x0', False])
        require(type(genesis) is dict and quantity(genesis.get('number')) == 0
                and word(genesis.get('hash'), 32) == word(route['genesis_hash'], 32), 'source genesis mismatch')
        receipt = source.eth('eth_getTransactionReceipt', [tx_hash])
        require(type(receipt) is dict and word(receipt.get('transactionHash'), 32) == txid,
                'requested receipt is unavailable or mismatched')
        height = quantity(receipt.get('blockNumber'))
        canonical = source.eth('eth_getBlockByNumber', [hex(height), False])
        finalized = source.eth('eth_getBlockByNumber', ['finalized', False])
        require(type(finalized) is dict, 'finalized checkpoint is unavailable')
        final_height = quantity(finalized.get('number'))
        final_hash = word(finalized.get('hash'), 32)
        require(any(final_hash), 'zero finalized checkpoint hash')
        pinned_finalized = source.eth('eth_getBlockByNumber', [hex(final_height), False])
        require(type(pinned_finalized) is dict
                and quantity(pinned_finalized.get('number')) == final_height
                and word(pinned_finalized.get('hash'), 32) == final_hash,
                'finalized checkpoint changed during collection')
        rechecked = source.eth('eth_getBlockByNumber', [hex(height), False])
        require(type(canonical) is dict and type(rechecked) is dict
                and canonical == rechecked, 'canonical block changed during collection')
        return {'chain_id': chain_id, 'genesis': genesis, 'receipt': receipt,
                'canonical_block': canonical, 'finalized_block': finalized}
    require(route['network'] == 'tron-mainnet', 'unknown source network')
    genesis = source.post('/walletsolidity/getblockbynum', {'num': 0, 'visible': False})
    require(type(genesis) is dict and word(genesis.get('blockID'), 32, prefix=False)
            == word(route['genesis_hash'], 32), 'source genesis mismatch')
    info = source.post('/walletsolidity/gettransactioninfobyid', {'value': txid.hex(), 'visible': False})
    require(type(info) is dict and word(info.get('id'), 32, prefix=False) == txid,
            'requested TRON receipt is unavailable or mismatched')
    transaction = source.post('/walletsolidity/gettransactionbyid', {'value': txid.hex(), 'visible': False})
    require(type(transaction) is dict and word(transaction.get('txID'), 32, prefix=False) == txid,
            'requested TRON transaction is unavailable or mismatched')
    height = integer(info.get('blockNumber'))
    canonical = source.post('/walletsolidity/getblockbynum', {'num': height, 'visible': False})
    solidified = source.post('/walletsolidity/getnowblock', {'visible': False})
    require(type(solidified) is dict and type(solidified.get('block_header')) is dict
            and type(solidified['block_header'].get('raw_data')) is dict,
            'solidified checkpoint is unavailable')
    solid_height = integer(solidified['block_header']['raw_data'].get('number'))
    solid_id = word(solidified.get('blockID'), 32, prefix=False)
    require(any(solid_id), 'zero solidified checkpoint ID')
    pinned_solidified = source.post('/walletsolidity/getblockbynum',
                                    {'num': solid_height, 'visible': False})
    require(type(pinned_solidified) is dict
            and type(pinned_solidified.get('block_header')) is dict
            and type(pinned_solidified['block_header'].get('raw_data')) is dict
            and integer(pinned_solidified['block_header']['raw_data'].get('number')) == solid_height
            and word(pinned_solidified.get('blockID'), 32, prefix=False) == solid_id,
            'solidified checkpoint changed during collection')
    rechecked = source.post('/walletsolidity/getblockbynum', {'num': height, 'visible': False})
    require(type(canonical) is dict and type(rechecked) is dict and canonical == rechecked,
            'solidified block changed during collection')
    return {'genesis': genesis, 'transaction': transaction, 'transaction_info': info,
            'canonical_block': canonical, 'solidified_block': solidified}
