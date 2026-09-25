"""Validate the entire bUSDT/bUSDC registry before selecting any source route.

This is configuration consistency only, not an on-chain asset registration.
The existing six-decimal wire protocol retains its legacy USDT domain tags.
"""
from .common import normalized_route, require, word
from .networks import EVM_CHAIN_IDS


def select_route(catalog, symbol, network, allow_synthetic=False):
    require(type(catalog) is dict and set(catalog) == {'version', 'assets'},
            'invalid stablecoin catalog')
    require(type(catalog['version']) is int and catalog['version'] == 1,
            'unsupported stablecoin catalog version')
    assets = catalog['assets']
    require(type(assets) is list and len(assets) == 2, 'both stablecoin registrations required')
    seen, native_ids, vaults, route_ids = set(), set(), set(), set()
    source_domains = {}
    native_domain, synthetic, selected = None, None, None
    for entry in assets:
        require(type(entry) is dict and set(entry) == {'source_symbol', 'symbol', 'manifest'},
                'invalid stablecoin registration')
        source = entry['source_symbol']
        require(type(source) is str and source in ('USDT', 'USDC') and source not in seen,
                'unknown or duplicate stablecoin')
        require(entry['symbol'] == 'b' + source, 'incorrect bridged symbol')
        seen.add(source)
        manifest = entry['manifest']
        # Validates every route, including unselected assets, before any RPC I/O.
        require(type(manifest) is dict and type(manifest.get('routes')) is list
                and len(manifest['routes']) > 0 and type(manifest['routes'][0]) is dict,
                'explicit stablecoin routes required')
        first = normalized_route(manifest, manifest['routes'][0].get('network'), allow_synthetic,
                                 source_asset=source)
        domain, asset = word(first['native_domain'], 32), word(first['native_asset'], 32)
        require(asset not in native_ids, 'stablecoins must have distinct native asset IDs')
        native_ids.add(asset)
        if native_domain is None:
            native_domain, synthetic = domain, manifest['synthetic']
        require(domain == native_domain and manifest['synthetic'] is synthetic,
                'catalog destination or synthetic mode mismatch')
        for configured in manifest['routes']:
            route = normalized_route(manifest, configured['network'], allow_synthetic,
                                     source_asset=source)
            prior = source_domains.setdefault(route['network'], route['source_domain'])
            require(prior == route['source_domain'], 'source network genesis mismatch across assets')
            # Each reviewed source vault has one immutable token/route binding.
            vault = (route['network'], route['vault_vm_hex'])
            require(vault not in vaults and route['route_id'] not in route_ids,
                    'shared vault or route identity')
            vaults.add(vault)
            route_ids.add(route['route_id'])
            if entry['symbol'] == symbol and route['network'] == network:
                selected = dict(route, source_symbol=source, symbol=entry['symbol'],
                                synthetic=synthetic,
                                transfer_mode=configured['transfer_mode'],
                                committee_threshold=configured['committee']['threshold'],
                                committee_signers=tuple(s.lower() if network in EVM_CHAIN_IDS else s
                                                        for s in configured['committee']['signers']),
                                vault_runtime_sha256=configured['deployment']['runtime_sha256'].lower(),
                                vault_deployment_height=configured['deployment']['block_number'])
    require(selected is not None, 'stablecoin source route is not configured')
    return selected
