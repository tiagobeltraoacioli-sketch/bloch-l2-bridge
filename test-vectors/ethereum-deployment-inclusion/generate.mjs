// Synthetic, unfunded vectors; never use this publicly known test key for funds.
// Run with Node 24 and a path to the locked postern-dex/frontend/package.json.
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
const require = createRequire(resolve(process.argv[2]));
const { toRlp, keccak256, getContractAddress } = require('viem');
const { privateKeyToAccount } = require('viem/accounts');
const account = privateKeyToAccount('0x' + '46'.repeat(32));
const zero = bytes => '0x' + '00'.repeat(bytes);
const repeat = (value, bytes) => '0x' + value.repeat(bytes);
const integer = value => {
  if (!value) return '0x';
  const hex = BigInt(value).toString(16);
  return '0x' + (hex.length % 2 ? '0' : '') + hex;
};
const nibbles = hex => [...hex.slice(2)].map(char => Number.parseInt(char, 16));
const compact = (key, leaf) => {
  const odd = key.length % 2;
  return '0x' + [2 * Number(leaf) + odd, ...(odd ? [] : [0]), ...key].map(n => n.toString(16)).join('');
};

// Independent test-only trie builder; production verifies with alloy-trie.
function trie(entries) {
  const paths = new Map();
  function build(rows, depth) {
    let shared = 0;
    while (rows.every(row => row.key.length > depth + shared && row.key[depth + shared] === rows[0].key[depth + shared])) shared++;
    let raw, children = [];
    if (rows.length === 1) raw = toRlp([compact(rows[0].key.slice(depth), true), rows[0].value]);
    else if (shared) {
      const child = build(rows, depth + shared); children = [child];
      raw = toRlp([compact(rows[0].key.slice(depth, depth + shared), false), keccak256(child.raw)]);
    } else {
      const node = Array(17).fill('0x');
      for (let nibble = 0; nibble < 16; nibble++) {
        const subset = rows.filter(row => row.key[depth] === nibble);
        if (subset.length) { const child = build(subset, depth + 1); children.push(child); node[nibble] = keccak256(child.raw); }
      }
      raw = toRlp(node);
    }
    const result = { raw, children, rows };
    for (const row of rows) paths.set(row.index, [raw, ...(paths.get(row.index) ?? [])]);
    return result;
  }
  const root = build(entries.map(([index, value]) => ({ index, key: nibbles(toRlp(integer(index))), value })), 0);
  return { root: keccak256(root.raw), proofs: paths };
}

const input = '0x60016000556002600055';
const inputSha = '0x' + createHash('sha256').update(Buffer.from(input.slice(2), 'hex')).digest('hex');
const cases = [];
for (const type of ['legacy', 'eip2930', 'eip1559']) {
  const kind = ['legacy', 'eip2930', 'eip1559'].indexOf(type);
  const rows = [];
  for (const [offset, index] of [0, 1, 127, 128].entries()) {
    const nonce = 9 + offset;
    const transaction = await account.signTransaction({ chainId: 1, type, nonce, gas: 200000n,
      data: input, value: 0n, ...(kind === 2 ? { maxFeePerGas: 30n, maxPriorityFeePerGas: 2n } : { gasPrice: 20n }),
      ...(kind ? { accessList: [] } : {}) });
    const payload = toRlp(['0x01', integer(80000 + offset * 80000), zero(256), []]);
    const receipt = kind ? '0x0' + kind + payload.slice(2) : payload;
    rows.push({ index, nonce, transaction, receipt, cumulative: String(80000 + offset * 80000) });
  }
  const txTrie = trie(rows.map(row => [row.index, row.transaction]));
  const receiptTrie = trie(rows.map(row => [row.index, row.receipt]));
  const header = toRlp([repeat('01',32), repeat('02',32), repeat('03',20), repeat('04',32),
    txTrie.root, receiptTrie.root, zero(256), integer(1), integer(100), integer(30000000),
    integer(320000), integer(1700000000), '0x', repeat('06',32), zero(8)]);
  const blockHash = keccak256(header);
  for (const row of rows) cases.push({
    kind, index: row.index, input,
    request: {
      schema: 'postern.custody-deployment-inclusion-request.v1',
      ancestry: { schema: 'postern.custody-deployment-ancestry.v2',
        manifestCanonicalSha256: repeat('07',32), comparisonCanonicalSha256: repeat('08',32),
        anchors: [{ blockNumber: '100', blockHash, parentHash: repeat('01',32), timestamp: '1700000000',
          stateRoot: repeat('04',32), transactionsRoot: txTrie.root, receiptsRoot: receiptTrie.root }], headers: [header] },
      transactionIndex: String(row.index), transactionHash: keccak256(row.transaction),
      sender: account.address.toLowerCase(),
      contractAddress: getContractAddress({ from: account.address, nonce: BigInt(row.nonce) }).toLowerCase(),
      creationInputSha256: inputSha, receiptType: String(kind), cumulativeGasUsed: row.cumulative,
      transaction: row.transaction, transactionProof: txTrie.proofs.get(row.index),
      receipt: row.receipt, receiptProof: receiptTrie.proofs.get(row.index),
    },
  });
}
writeFileSync(new URL('./synthetic.json', import.meta.url), JSON.stringify({
  synthetic: true, generator: 'Node 24; viem from the locked DEX frontend; independent test-only RLP trie builder',
  note: 'Sparse synthetic trees and headers are not valid production blocks or real deployment evidence. Signatures use the public EIP-155 example key.', cases,
}, null, 2) + '\n', { flag: 'wx' });
