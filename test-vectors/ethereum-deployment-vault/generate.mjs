// LOCAL TEST CHAIN ONLY. Start an empty Anvil at 127.0.0.1:18547, chain 1,
// Shanghai, zero development accounts, genesis timestamp 1700000000.
// Uses the public EIP-155 example key, fake funds and a mock USDC contract.
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const require = createRequire(resolve(process.argv[2]));
const { toRlp, keccak256, encodeAbiParameters } = require('viem');
const { privateKeyToAccount } = require('viem/accounts');
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const compiler = resolve(process.argv[3]);
const sha = bytes => '0x' + createHash('sha256').update(bytes).digest('hex');
if (!['0xcc2d44c706905ccc382f484625dff61d741e0c24232d226f139a6835fc644f3f',
       '0xfb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f'].includes(sha(readFileSync(compiler)))) throw new Error('compiler pin');
const buildBytes = readFileSync(resolve(root, 'test-vectors/vault-storage-build/solc-0.8.24.json'));
const build = JSON.parse(buildBytes);
const selected = spawnSync('python3', ['-c', 'import sys,json;sys.path.insert(0,"scripts/tests");from test_custody_deployment_manifest import candidate;print(json.dumps(candidate()))'], { cwd: root, encoding: 'utf8' });
if (selected.status) throw new Error('public test configuration unavailable');
const manifest = JSON.parse(selected.stdout);
const configuration = { sourceDomain: manifest.source.source_domain, nativeDomain: manifest.native.domain,
  nativeAsset: manifest.native.asset_id, cap: String(manifest.cap.base_units), threshold: 3, transferMode: 0,
  signers: manifest.custody.custodians.map(c => c.ethereum_signer) };
const word = n => '0x' + BigInt(n).toString(16).padStart(64, '0');
const integer = n => { const h = BigInt(n).toString(16); return BigInt(n) ? '0x' + (h.length % 2 ? '0' : '') + h : '0x'; };
const bytes = raw => Buffer.from(raw.slice(2), 'hex');
const rpc = async (method, params = []) => {
  const response = await fetch('http://127.0.0.1:18547', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(10000) });
  const result = await response.json();
  if (!response.ok || result.error || !('result' in result)) throw new Error('local test RPC refused ' + method);
  return result.result;
};
const client = await rpc('web3_clientVersion');
let genesis = await rpc('eth_getBlockByNumber', ['0x0', false]);
if (process.argv[4] === '--reset-local-fixture') {
  if (!client.toLowerCase().includes('anvil') || await rpc('eth_chainId') !== '0x1'
      || await rpc('eth_blockNumber') !== '0x1' || Number(genesis.timestamp) !== 1700000000
      || (await rpc('eth_accounts')).length !== 0) throw new Error('not the dedicated local fixture chain');
  await rpc('anvil_reset', []);
  genesis = await rpc('eth_getBlockByNumber', ['0x0', false]);
}
if (!client.toLowerCase().includes('anvil') || await rpc('eth_chainId') !== '0x1'
    || await rpc('eth_blockNumber') !== '0x0' || Number(genesis.timestamp) !== 1700000000
    || (await rpc('eth_accounts')).length !== 0) throw new Error('not the empty dedicated local fixture chain');
const account = privateKeyToAccount('0x' + '46'.repeat(32));
const proxy = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const implementation = '0x' + '12'.repeat(19) + '13';
const implementationSlot = '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3';
const mock = 'pragma solidity 0.8.24; contract Mock { function decimals() external pure returns(uint8){return 6;} function balanceOf(address) external pure returns(uint256){return 0;} function implementation() external pure returns(address){return ' + implementation + ';} }';
const compile = spawnSync(compiler, ['--standard-json'], { input: JSON.stringify({ language: 'Solidity', sources: { 'Mock.sol': { content: mock } },
  settings: { ...build.settings, outputSelection: { '*': { '*': ['evm.deployedBytecode'] } } } }), encoding: 'utf8' });
const mockOutput = JSON.parse(compile.stdout);
if (compile.status || mockOutput.errors?.some(e => e.severity === 'error')) throw new Error('mock compile refused');
const proxyCode = '0x' + mockOutput.contracts['Mock.sol'].Mock.evm.deployedBytecode.object;
await rpc('anvil_setBalance', [account.address, word(100n * 10n ** 18n)]);
await rpc('anvil_setCode', [proxy, proxyCode]);
await rpc('anvil_setCode', [implementation, '0x60006000fd']);
await rpc('anvil_setStorageAt', [proxy, implementationSlot, word(implementation)]);
const args = encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'bytes32' }, { type: 'address' },
  { type: 'uint64' }, { type: 'uint8' }, { type: 'address[]' }, { type: 'uint8' }],
  [configuration.sourceDomain, configuration.nativeDomain, configuration.nativeAsset, proxy, BigInt(configuration.cap), 0, configuration.signers, 3]);
const input = build.creationBytecode + args.slice(2);
const transaction = await account.signTransaction({ chainId: 1, type: 'legacy', nonce: 0, gas: 4000000n, gasPrice: 20000000000n, value: 0n, data: input });
await rpc('evm_setNextBlockTimestamp', [1700000001]);
const transactionHash = await rpc('eth_sendRawTransaction', [transaction]);
const receipt = await rpc('eth_getTransactionReceipt', [transactionHash]);
if (receipt.status !== '0x1' || receipt.logs.length || receipt.transactionIndex !== '0x0') throw new Error('local constructor did not succeed');
const block = await rpc('eth_getBlockByHash', [receipt.blockHash, false]);
const header = toRlp([block.parentHash, block.sha3Uncles, block.miner, block.stateRoot, block.transactionsRoot,
  block.receiptsRoot, block.logsBloom, integer(block.difficulty), integer(block.number), integer(block.gasLimit),
  integer(block.gasUsed), integer(block.timestamp), block.extraData, block.mixHash, block.nonce,
  integer(block.baseFeePerGas), block.withdrawalsRoot]);
if (keccak256(header) !== block.hash) throw new Error('local header encoding mismatch');
const receiptBytes = toRlp(['0x01', integer(receipt.cumulativeGasUsed), receipt.logsBloom, []]);
const transactionProof = [toRlp(['0x2080', transaction])];
const receiptProof = [toRlp(['0x2080', receiptBytes])];
if (keccak256(transactionProof[0]) !== block.transactionsRoot || keccak256(receiptProof[0]) !== block.receiptsRoot) throw new Error('single-transaction roots mismatch');
const elementBase = BigInt(keccak256(word(0)));
const slots = [word(0), word(2), word(5), ...configuration.signers.map((_, i) => word(elementBase + BigInt(i))),
  ...configuration.signers.map(s => keccak256(word(s) + word(1).slice(2)))];
const selector = { blockHash: block.hash, requireCanonical: true };
const proof = await rpc('eth_getProof', [receipt.contractAddress, slots, selector]);
const contracts = [];
for (const [index, address] of [receipt.contractAddress, proxy, implementation].entries()) {
  const accountProof = index === 0 ? { ...proof, storageProof: [] }
    : await rpc('eth_getProof', [address, index === 1 ? [implementationSlot] : [], selector]);
  const code = await rpc('eth_getCode', [address, selector]);
  contracts.push({ role: ['vault', 'usdcProxy', 'usdcImplementation'][index], address, code, runtimeSha256: sha(bytes(code)), proof: accountProof });
}
const inclusion = { schema: 'postern.custody-deployment-inclusion-request.v1',
  ancestry: { schema: 'postern.custody-deployment-ancestry.v2', manifestCanonicalSha256: word(7), comparisonCanonicalSha256: word(8),
    anchors: [{ blockNumber: String(BigInt(block.number)), blockHash: block.hash, parentHash: block.parentHash,
      timestamp: String(BigInt(block.timestamp)), stateRoot: block.stateRoot, transactionsRoot: block.transactionsRoot, receiptsRoot: block.receiptsRoot }], headers: [header] },
  transactionIndex: '0', transactionHash, sender: account.address.toLowerCase(), contractAddress: receipt.contractAddress,
  creationInputSha256: sha(bytes(input)), receiptType: '0', cumulativeGasUsed: String(BigInt(receipt.cumulativeGasUsed)),
  transaction, transactionProof, receipt: receiptBytes, receiptProof };
const request = { schema: 'postern.custody-deployment-vault-request.v1',
  state: { schema: 'postern.custody-deployment-state-request.v1', inclusion, contracts },
  buildArtifactSha256: sha(buildBytes), configuration, storageProof: proof.storageProof };
writeFileSync(new URL('./anvil-shanghai.json', import.meta.url), JSON.stringify({
  localTestOnly: true, client, compilerSha256: sha(readFileSync(compiler)), genesis, block, receipt, input, request,
  note: 'Locally executed constructor with fake funds and a mock USDC at the mainnet address. Artificial chain ID 1; not Ethereum mainnet evidence or authenticated consensus/finality. Public example signing key only.',
}, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ localTestOnly: true, block: block.number, storageProofs: proof.storageProof.length, runtimeBytes: (contracts[0].code.length - 2) / 2 }));
