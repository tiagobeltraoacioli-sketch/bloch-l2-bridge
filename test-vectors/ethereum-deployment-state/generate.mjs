// Synthetic public evidence, never a mainnet deployment or a signing input.
// Node 24; argument: the locked postern-dex/frontend/package.json.
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
const require = createRequire(resolve(process.argv[2]));
const { toRlp, fromRlp, keccak256 } = require('viem');
const base = JSON.parse(readFileSync(new URL('../ethereum-deployment-inclusion/synthetic.json', import.meta.url)));
const slot = '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3';
const proxy = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const emptyRoot = keccak256(toRlp('0x'));
const sha = raw => '0x' + createHash('sha256').update(Buffer.from(raw.slice(2), 'hex')).digest('hex');
const integer = value => {
  const hex = BigInt(value).toString(16);
  return BigInt(value) ? '0x' + (hex.length % 2 ? '0' : '') + hex : '0x';
};
const compact = (key, leaf) => {
  const odd = key.length % 2;
  return '0x' + [2 * Number(leaf) + odd, ...(odd ? [] : [0]), ...key].map(n => n.toString(16)).join('');
};

// Independent test-only trie construction. These fixed-length secure-trie
// keys and account/slot values make every child >= 32 bytes; assert that fact.
function trie(entries) {
  const proofs = new Map();
  const reference = node => {
    if ((node.length - 2) / 2 < 32) throw new Error('fixture needs inline child support');
    return keccak256(node);
  };
  function build(rows, depth) {
    let shared = 0;
    while (rows.every(r => depth + shared < r.key.length && r.key[depth + shared] === rows[0].key[depth + shared])) shared++;
    let raw;
    if (rows.length === 1) raw = toRlp([compact(rows[0].key.slice(depth), true), rows[0].value]);
    else if (shared) raw = toRlp([compact(rows[0].key.slice(depth, depth + shared), false), reference(build(rows, depth + shared))]);
    else {
      const node = Array(17).fill('0x');
      for (let nibble = 0; nibble < 16; nibble++) {
        const subset = rows.filter(r => r.key[depth] === nibble);
        if (subset.length) node[nibble] = reference(build(subset, depth + 1));
      }
      raw = toRlp(node);
    }
    for (const row of rows) proofs.set(row.id, [raw, ...(proofs.get(row.id) ?? [])]);
    return raw;
  }
  const raw = build(entries.map(([id, key, value]) => ({ id, key: [...key.slice(2)].map(c => parseInt(c, 16)), value })), 0);
  return { root: keccak256(raw), proofs };
}

const cases = [];
for (let variant = 0; variant < 4; variant++) {
  const original = base.cases[(variant % 3) * 4];
  const inclusion = structuredClone(original.request);
  const implementation = variant === 3 ? '0x000102030405060708090a0b0c0d0e0f10111213' : '0x1234567890abcdef1234567890abcdef12345678';
  const storage = trie([
    ['implementation', keccak256(slot), toRlp(integer(implementation))],
    ['unrelated', keccak256('0x' + '01'.repeat(32)), toRlp('0x02')],
  ]);
  const contracts = ['vault', 'usdcProxy', 'usdcImplementation'].map((role, index) => {
    const code = ['0x60006000fd', '0x60016000fd', '0x60026000fd'][index];
    const address = [inclusion.contractAddress, proxy, implementation][index];
    const nonce = variant === 3 ? '0xffffffffffffffff' : '0x1';
    const balance = variant === 3 ? '0x' + 'ff'.repeat(32) : '0x0';
    return { role, address, code, runtimeSha256: sha(code), proof: {
      address, nonce, balance, codeHash: keccak256(code), storageHash: index === 1 ? storage.root : emptyRoot,
      accountProof: [], storageProof: index === 1 ? [{ key: slot, value: '0x' + BigInt(implementation).toString(16),
        proof: storage.proofs.get('implementation') }] : [],
    } };
  });
  const accounts = trie(contracts.map(c => [c.role, keccak256(c.address),
    toRlp([integer(c.proof.nonce), integer(c.proof.balance), c.proof.storageHash, c.proof.codeHash])]));
  for (const c of contracts) c.proof.accountProof = accounts.proofs.get(c.role);
  const header = fromRlp(inclusion.ancestry.headers[0]);
  header[3] = accounts.root;
  inclusion.ancestry.headers[0] = toRlp(header);
  inclusion.ancestry.anchors[0].stateRoot = accounts.root;
  inclusion.ancestry.anchors[0].blockHash = keccak256(inclusion.ancestry.headers[0]);
  cases.push({ kind: original.kind, variant, input: original.input,
    request: { schema: 'postern.custody-deployment-state-request.v1', inclusion, contracts } });
}
writeFileSync(new URL('./synthetic.json', import.meta.url), JSON.stringify({
  synthetic: true, generator: 'Node 24; locked viem; independent test-only account and storage trie builder',
  note: 'Artificial sparse state and headers, no execution or finality, not production evidence. Inherited signatures use a public example key.',
  cases,
}, null, 2) + '\n', { flag: 'wx' });
