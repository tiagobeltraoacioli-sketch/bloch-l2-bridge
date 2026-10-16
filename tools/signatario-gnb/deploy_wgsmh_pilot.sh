#!/usr/bin/env bash
# wGSMH mainnet pilot on devnet4: WrappedGnBV2 (symbol wGSMH, GnB MAINNET 0x474E0001) for the pilot signer set,
# plus signer configs pointing at it. Run as root on the devnet4 host from the Foundry project root:
#   sudo DEPLOY_KEY=/path/l2.key GNB_TOOLS=/home/ubuntu/gnb-vault-single-build bash tools/signatario-gnb/deploy_wgsmh_pilot.sh
# Reuses the 2-of-3 signer keystores of the first pilot ($SRC: signers.json, keys/, password); writes only under $DIR.
# Limits (8 dp): supply cap 30 GSMH, token bucket 10 GSMH refilled in 24 h (DEX cap = bucket/10 = 1 wGSMH),
# mints above 5 GSMH wait 1 h, min burn 0.001 GSMH, no guardians. The deploy is one L2 transaction from DEPLOY_KEY.
set -euo pipefail
SRC=${SRC:-/var/lib/bloch-l2-devnet4-pontes-main}
DIR=${DIR:-/var/lib/bloch-l2-devnet4-pontes-gsmh}
BIN=${BIN:-/home/ubuntu/.foundry/bin}
RPC=${RPC:-http://127.0.0.1:18945}
GNB_TOOLS=${GNB_TOOLS:?gnb-smh build dir with tools/ponte and target/release/gnb-cli}
GNB_HOME=${GNB_HOME:-/home/ubuntu/gnb-ponte-main}       # vault.json, w/s{1,2,3}-mainnet.json, pw
GNB_RPC_PORT=${GNB_RPC_PORT:-17510}
MIN_CONF=${MIN_CONF:-30}
GNB_CHAIN_ID=0x474E0001
SUPPLY_CAP=3000000000 BUCKET=1000000000 REFILL=$((1000000000 / 86400))
LARGE=500000000 DELAY=3600 MIN_BURN=100000
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -s "${DEPLOY_KEY:?}" ] || { echo "DEPLOY_KEY missing"; exit 1; }

install -d -m 700 "$DIR" "$DIR/work"
SIGNERS=$(python3 -c "import json; print('[' + ','.join(s['address'] for s in sorted(json.load(open('$SRC/signers.json')), key=lambda s: int(s['address'], 16))) + ']')")

if [ ! -e "$DIR/deploy.json" ]; then
  "$BIN/forge" build --root . >/dev/null
  KEY=$(tr -d '\n' < "$DEPLOY_KEY")
  FROM=$("$BIN/cast" wallet address --private-key "$KEY")
  NONCE=$("$BIN/cast" nonce "$FROM" --block latest --rpc-url "$RPC")
  PRICE=$(( $("$BIN/cast" gas-price --rpc-url "$RPC") * 2 ))
  CODE=$("$BIN/forge" inspect --root . contracts/wgnb/WrappedGnBV2.sol:WrappedGnBV2 bytecode)
  ARGS=$("$BIN/cast" abi-encode \
         "c(uint32,address[],uint256,(uint256,uint256,uint256,uint256,uint256,uint256),(address[],uint256,uint256))" \
         "$GNB_CHAIN_ID" "$SIGNERS" 2 "($SUPPLY_CAP,$BUCKET,$REFILL,$LARGE,$DELAY,$MIN_BURN)" "([],0,0)")
  # The settled RPC has no "pending" level: sign offline, publish, poll the receipt.
  RAW=$("$BIN/cast" mktx --private-key "$KEY" --chain 700771 --nonce "$NONCE" --gas-limit "${GAS:-6000000}" \
        --gas-price "$PRICE" --legacy --create "${CODE}${ARGS#0x}")
  HASH=$("$BIN/cast" publish --async "$RAW" --rpc-url "$RPC" | tr -d '"')
  ADDR=$("$BIN/cast" compute-address "$FROM" --nonce "$NONCE" | awk '{print $NF}')
  echo "{\"pending\": \"$HASH\", \"contract\": \"$ADDR\"}" > "$DIR/deploy-pending.json"
  echo "sent $HASH (deployer $FROM nonce $NONCE, contract $ADDR); waiting for the L2 block" >&2
  "$BIN/cast" receipt "$HASH" --rpc-url "$RPC" --confirmations 1 --rpc-timeout 7200 --json > "$DIR/deploy-receipt.json"
  python3 - "$DIR" "$HASH" "$FROM" "$NONCE" "$ADDR" "$SIGNERS" <<'EOF2'
import json, sys
d, h, frm, nonce, addr, signers = sys.argv[1:]
r = json.load(open(f'{d}/deploy-receipt.json'))
assert r['status'] in ('0x1', 1), r
assert r['contractAddress'].lower() == addr.lower(), (r['contractAddress'], addr)
json.dump({'deployedTo': addr, 'transactionHash': h, 'deployer': frm, 'nonce': int(nonce),
           'blockNumber': int(r['blockNumber'], 16), 'gasUsed': int(r['gasUsed'], 16), 'signers': signers},
          open(f'{d}/deploy.json', 'w'), indent=1)
EOF2
fi
TOKEN=$(python3 -c "import json; print(json.load(open('$DIR/deploy.json'))['deployedTo'].lower())")
CODE_KECCAK=$("$BIN/cast" keccak "$("$BIN/cast" code "$TOKEN" --rpc-url "$RPC")")

python3 - "$SRC" "$DIR" "$TOKEN" "$CODE_KECCAK" "$GNB_CHAIN_ID" "$GNB_TOOLS" "$GNB_HOME" "$GNB_RPC_PORT" "$MIN_CONF" <<'EOF'
import json, sys
src, d, token, code, gnb, tools, home, port, min_conf = sys.argv[1:]
cli = f'{tools}/target/release/gnb-cli'
half = f'{tools}/tools/ponte/signatario_gnb.py'
vault = f'{home}/vault.json'
for s in json.load(open(f'{src}/signers.json')):
    i = s['signer']
    journal = f'{d}/journal-gnb-s{i}'
    cfg = {'signer': i, 'l2_rpc': 'http://127.0.0.1:18945', 'l2_chain_id': 700771, 'wgnb': token,
           'wgnb_code_keccak': code, 'gnb_chain_id': gnb, 'threshold': 2, 'keystore': s['keystore'],
           'password_file': f'{src}/password', 'cast': '/home/ubuntu/.foundry/bin/cast', 'db': f'{d}/db{i}.json',
           'l2_source': 'rebuild', 'work_dir': f'{d}/work', 'follower': '/var/lib/bloch-l2-devnet4-follower',
           'genesis': '/etc/bloch-l2-devnet4/public/genesis.blg',
           'produce': '/opt/bloch/l2-devnet4-settler/bloch-l2-produce-dev',
           'settled_rpc': '/opt/bloch/l2-devnet4-finality/bloch-l2-settled-rpc',
           'gnb_half_lock': ['python3', half, 'lock', '--txid', '{txid}', '--min-conf', min_conf, '--vault', vault,
                             '--rpc-port', port, '--cli', cli, '--journal', journal],
           'gnb_half_release': ['python3', half, 'release', '--spend', '{spend}', '--burn', '{burn}',
                                '--key', f'{home}/w/s{i}-mainnet.json', '--password-file', f'{home}/pw',
                                '--vault', vault, '--rpc-port', port, '--cli', cli, '--journal', journal]}
    with open(f'{d}/signer{i}.json', 'w') as f:
        json.dump(cfg, f, indent=1)
print(json.dumps({'token': token, 'code_keccak': code, 'configs': [f'{d}/signer{i}.json' for i in (1, 2, 3)]}))
EOF
