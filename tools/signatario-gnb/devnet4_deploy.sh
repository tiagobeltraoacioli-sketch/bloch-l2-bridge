#!/usr/bin/env bash
# devnet4 rehearsal: 3 signer keystores (2-of-3) + WrappedGnB deploy + signer configs. Run as root on the
# devnet4 host from the Foundry project root:  sudo bash tools/signatario-gnb/devnet4_deploy.sh
# Development only: all three signers live on this host (a real signer runs on its own machine with its own
# GnB node and native follower). Writes only under $DIR; the deploy is one L2 transaction from the dev account.
set -euo pipefail
DIR=${DIR:-/var/lib/bloch-l2-devnet4-pontes}
BIN=/home/ubuntu/.foundry/bin
RPC=${RPC:-http://127.0.0.1:18946}          # forge-compatible proxy over the settled RPC (18945)
DEV_KEY=/var/lib/bloch-l2-devnet4-settler/ensaio/l2.key
GNB_CHAIN_ID=${GNB_CHAIN_ID:-0x474E0002}     # GnB testnet; 0x474E0001 = mainnet pilot
PERIOD=${PERIOD:-86400} PERIOD_CAP=${PERIOD_CAP:-100000000000} SUPPLY_CAP=${SUPPLY_CAP:-1000000000000}  # 1,000 / 10,000 GNB
MIN_BURN=${MIN_BURN:-100000}                 # 0.001 GNB
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

install -d -m 700 "$DIR" "$DIR/keys" "$DIR/work"
[ -s "$DIR/password" ] || (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$DIR/password")
if [ ! -e "$DIR/signers.json" ]; then
  for i in 1 2 3; do
    out=$(CAST_PASSWORD="$(cat "$DIR/password")" "$BIN/cast" wallet new "$DIR/keys" "s$i" --json)
    echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["address"])' > "$DIR/keys/s$i.addr"
  done
  python3 - "$DIR" <<'EOF'
import json, sys
d = sys.argv[1]
addrs = sorted((open(f'{d}/keys/s{i}.addr').read().strip().lower(), i) for i in (1, 2, 3))
json.dump([{'signer': i, 'address': a, 'keystore': f'{d}/keys/s{i}'} for a, i in addrs], open(f'{d}/signers.json', 'w'), indent=1)
EOF
fi
SIGNERS=$(python3 -c "import json; print('[' + ','.join(s['address'] for s in json.load(open('$DIR/signers.json'))) + ']')")

if [ ! -e "$DIR/deploy.json" ]; then
  # The settled RPC has no "pending" level (forge create asks for it): sign offline, publish, poll the receipt.
  "$BIN/forge" build --root . >/dev/null 2>&1
  KEY=$(tr -d '\n' < "$DEV_KEY")
  FROM=$("$BIN/cast" wallet address --private-key "$KEY")
  NONCE=$("$BIN/cast" nonce "$FROM" --block latest --rpc-url "$RPC")
  PRICE=$(( $("$BIN/cast" gas-price --rpc-url "$RPC") * 2 ))
  CODE=$("$BIN/forge" inspect --root . contracts/wgnb/WrappedGnB.sol:WrappedGnB bytecode)
  ARGS=$("$BIN/cast" abi-encode "c(uint32,address[],uint256,uint256,uint256,uint256,uint256)" \
         "$GNB_CHAIN_ID" "$SIGNERS" 2 "$PERIOD" "$PERIOD_CAP" "$SUPPLY_CAP" "$MIN_BURN")
  RAW=$("$BIN/cast" mktx --private-key "$KEY" --chain 700771 --nonce "$NONCE" --gas-limit 3000000 \
        --gas-price "$PRICE" --legacy --create "${CODE}${ARGS#0x}")
  HASH=$("$BIN/cast" publish --async "$RAW" --rpc-url "$RPC" | tr -d '"')
  ADDR=$("$BIN/cast" compute-address "$FROM" --nonce "$NONCE" | awk '{print $NF}')
  echo "sent $HASH (deployer $FROM nonce $NONCE, contract $ADDR); waiting for the L2 block" >&2
  "$BIN/cast" receipt "$HASH" --rpc-url "$RPC" --confirmations 1 --rpc-timeout 3600 --json > "$DIR/deploy-receipt.json"
  python3 - "$DIR" "$HASH" "$FROM" "$NONCE" "$ADDR" <<'EOF2'
import json, sys
d, h, frm, nonce, addr = sys.argv[1:]
r = json.load(open(f'{d}/deploy-receipt.json'))
assert r['status'] in ('0x1', 1), r
assert r['contractAddress'].lower() == addr.lower(), (r['contractAddress'], addr)
json.dump({'deployedTo': addr, 'transactionHash': h, 'deployer': frm, 'nonce': int(nonce),
           'blockNumber': int(r['blockNumber'], 16), 'gasUsed': int(r['gasUsed'], 16)}, open(f'{d}/deploy.json', 'w'))
EOF2
fi
WGNB=$(python3 -c "import json; print(json.load(open('$DIR/deploy.json'))['deployedTo'].lower())")
CODE_KECCAK=$("$BIN/cast" keccak "$("$BIN/cast" code "$WGNB" --rpc-url "$RPC")")

python3 - "$DIR" "$WGNB" "$CODE_KECCAK" "$GNB_CHAIN_ID" <<'EOF'
import json, sys
d, wgnb, code, gnb = sys.argv[1:]
for s in json.load(open(f'{d}/signers.json')):
    i = s['signer']
    cfg = {'signer': i, 'l2_rpc': 'http://127.0.0.1:18945', 'l2_chain_id': 700771, 'wgnb': wgnb,
           'wgnb_code_keccak': code, 'gnb_chain_id': gnb, 'threshold': 2, 'keystore': s['keystore'],
           'password_file': f'{d}/password', 'cast': '/home/ubuntu/.foundry/bin/cast', 'db': f'{d}/db{i}.json',
           'l2_source': 'rebuild', 'work_dir': f'{d}/work', 'follower': '/var/lib/bloch-l2-devnet4-follower',
           'genesis': '/etc/bloch-l2-devnet4/public/genesis.blg',
           'produce': '/opt/bloch/l2-devnet4-settler/bloch-l2-produce-dev',
           'settled_rpc': '/opt/bloch/l2-devnet4-finality/bloch-l2-settled-rpc',
           # argv templates for gnb-smh tools/ponte/signatario_gnb.py; set per network before the rehearsal
           'gnb_half_lock': ['false'], 'gnb_half_release': ['false']}
    p = f'{d}/signer{i}.json'
    try:
        old = json.load(open(p))
        cfg.update({k: old[k] for k in ('gnb_half_lock', 'gnb_half_release') if k in old})
    except (OSError, ValueError):
        pass
    json.dump(cfg, open(p, 'w'), indent=1)
print(json.dumps({'wgnb': wgnb, 'code_keccak': code, 'signers': json.load(open(f'{d}/signers.json'))}, indent=1))
EOF
