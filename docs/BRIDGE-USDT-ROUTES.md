# Several assets per network: the USDT routes on Ethereum, Arbitrum One and OP Mainnet

Status: UNAUDITED. Nothing is deployed. All three routes are **held** (coordinator, 2026-11-19): independent review,
external audit and the owner's key ceremony are pending, and every tool refuses them. Written in round 20 (agent 411)
on `codex/bridge-usdt-r20-20261119`, from `main` `135bdba`.

Owner request (2026-11-19): the bridge must accept several assets. Until round 20 a network carried exactly one
route (USDC on the EVM networks, BTC, USDT only on TRON). This document describes how a network carries several
routes, and the three USDT routes that are the first use of it.

## 1. A route is (network, asset)

| | First route of a network (unchanged) | Further route (round 20) |
|---|---|---|
| Route id | the network id: `ethereum`, `arbitrum-one`, `op-mainnet`, ... | `<network>-<asset>`, lower case: `ethereum-usdt`, `arbitrum-one-usdt`, `op-mainnet-usdt` |
| File | `deployments/<network>/bridge.network.json` (Ethereum: the frozen configs under `deployments/mainnet/`) | `deployments/<route-id>/bridge.network.json`, with a `route` block `{id, asset}`; `network.id` and `network.chainId` are the NETWORK's |
| Decided in | `tools/evm-nets/networks.json` + `launch.py` (Ethereum: the frozen line) | `tools/evm-nets/asset-routes.json` + `asset_routes.py` (two records that must agree, as `launch.py`) |
| Vault, L2 token, books | its own | its own: another vault, another `BridgedStablecoinV3`, another deposit chain |
| Committee | the seven signer keys and three guardian keys | the same keys, the same shape (5 of 7, switch 6, pause-only guardians, 259,200 s) |

Nothing of a first route moved: no route id, no file, no token identity, no launch identity (section 9).

| Route | Asset on the source network | Vault | L2 token | Fees (deposit / release), minimums | Cap, window per 24 h | Launch |
|---|---|---|---|---|---|---|
| `ethereum-usdt` | USDT `0xdAC17F958D2ee523a2206206994597C13D831ec7` (Tether's own contract) | `TronSourceVault` (the Tether-aware vault), transferMode 1 | `bUSDT` "Bloch Bridged USDT" | 5 / 10 bps, 101 / 100 | 500,000, 50,000 | held |
| `arbitrum-one-usdt` | USD₮0 `0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9` (proxy; another issuer arrangement) | frozen `ProvenanceSourceVault`, transferMode 0 | `bUSDT.arb` "Bloch Bridged USDT (Arbitrum)" | 5 / 5 bps, 21 / 20 | 250,000, 25,000 | held |
| `op-mainnet-usdt` | USDT `0x94b008aA00579c1307B0EF2c499aD98a8ce58e58` (bridged by the OP standard bridge) | frozen `ProvenanceSourceVault`, transferMode 0 | `bUSDT.op` "Bloch Bridged USDT (OP Mainnet)" | 5 / 5 bps, 21 / 20 | 250,000, 25,000 | held |

Fees and minimums are those of the USDC route of the same network and are compared with it on every load of the
registry; cap and window follow the rule decided for USDC on 2026-11-19; the fee recipient is the owner's address
`0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544`. `bUSDT.trx` (TRON) is untouched.

### No USDT route on Linea, Base and BNB Smart Chain

- **Linea.** The canonical-bridge USDT (`0xA219439258ca9da29E9Cc4cE5596924745e12B93`) is in Linea's own token list, so
  the address is provable, but agent 409 found no usable second price reference for it on Linea (deepest pool 1.23
  WETH, observation cardinality 1), so the DEX lists no USDT there; a bridge route for an asset the DEX does not list
  on its network serves nobody yet. To revisit when the DEX lists it.
- **Base.** The candidate address (`0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2`) is named only by Optimism's Superchain
  token list, not by a page of Base and not by Tether (409): the asset identity is not proven by the rule the bridge
  applies to every asset (one issuer or chain document plus one on-chain reading). Independently, the Base network
  itself is held for the bridge (R325-EVM-1: no release has landed inside its 256-block window with the production
  signer path), so no route of any asset can launch there.
- **BNB Smart Chain.** Out of bridge v1 as a network (a custodial 18-decimal peg token behind a wrapper and a second
  transaction per recipient; R325-EVM-1 / -2). Its "USDT" is Binance-Peg BSC-USD: 18 decimals, issued by Binance, whose
  owner can mint. The frozen vault refuses a token that does not answer 6 decimals.

## 2. Which contract is the asset, what its admin can do, what the signers check

Read on loopback forks of the three networks on 2026-11-19 (public endpoints as read-only fork sources) and from
agent 409's probes of 2026-11-18. Every fact below is in `tools/evm-nets/asset-routes.json` (`asset`, `guard`) and in
the route's `bridge.network.json` (`asset.contractIs`, `asset.admin`, `asset.behaviour`).

| | Ethereum USDT | Arbitrum One USD₮0 | OP Mainnet USDT |
|---|---|---|---|
| The contract | Tether's own `TetherToken` (Solidity 0.4.17); not a proxy; code keccak `0xb44fb4e9…ea55` | EIP-1967 transparent proxy (code keccak `0xfc1ea81d…3986`); implementation `0x3263CD78…A3F4` (code keccak `0x1d4c20a1…2279`); `symbol()` is `USD₮0` | plain bridged token (`L2StandardERC20`); not a proxy; code keccak `0xb49036bd…4151`; `l1Token()` = Tether's Ethereum contract, `l2Bridge()` = predeploy `0x4200…0010` |
| Issuer | Tether | the USDT0 arrangement (LayerZero OFT): supply is minted and burned by `oftContract()` = `0x14E4A1B1…8D92` as USDT moves between chains. NOT named on Tether's supported-protocols page. That one USD₮0 is redeemable for one USDT locked on Ethereum is the publisher's statement, not verified here | none on this network: every unit stands for USDT locked in the Ethereum side of the OP standard bridge |
| Admin | `owner()` = `0xC6CDE7C3…a828` (a contract; its signers not examined) | proxy admin contract `0x553ec478…1B4A`, owned by the Safe `0x4DFF9b5b…0bF8` (3 of 5, read on the fork); the same Safe is the token's `owner()` | the token has none. The bridge is a proxy (implementation `0xAE9ed42F…d1a1`) whose admin is the predeploy `0x4200…0018` (the OP Stack's upgrade authority; stated from the design, not read on chain) |
| What the admin can do | blacklist an address and destroy its balance; pause; set a transfer fee below 20 bps and below 50 USDT; issue and redeem; `deprecate` (forward every call to another contract) | replace the implementation with any code; block an address and destroy its balance | the bridge may mint to any address and `burn(address,uint256)` from ANY holder without an allowance (shown on the fork); an upgrade of the bridge changes what it does with that power |
| What every signer reads at its finalized block before attesting a deposit (`guard`) | the token's code; `basisPointsRate()` = 0; `maximumFee()` = 0; `paused()` = false; `deprecated()` = false; `isBlackListed(vault)` = false; `owner()` unchanged | the proxy's code; the implementation slot and the implementation's code; the proxy admin slot; `isBlocked(vault)` = false; `owner()`, `oftContract()` and the proxy admin's `owner()` unchanged | the token's code; `l1Token()` and `l2Bridge()`; the bridge's implementation slot and proxy admin slot |

The guard (`tools/signatario-stable/token_guard.py`, applied by `eth_half.py deposit`) fails closed: a difference, a
getter that reverts, an answer that is not one ABI word and an RPC error all mean "attest nothing". **Minting stops
for that route** until the token is back in the pinned state or the route's pins are changed by a reviewed commit.
Releases are not guarded: an exit the token refuses reverts in the token with no state change, and an exit must not be
stopped by a monitor. The guard reads state, not history: a fee that was on and off again between two finalized
blocks the signer reads is not seen (the vault's own balance checks cover that interval, section 3).

## 3. USDT is not USDC: behaviour, and the test that pins each row

No product contract is new or changed (section 9). `ethereum-usdt` takes the Tether-aware vault that the TRON line
wrote for the same `TetherToken` design (`contracts/tron/TronSourceVault.sol`: the frozen vault plus the seven marked
changes of `docs/TRON-VAULT-DIFF.md`), in this tree's stock solc 0.8.24 build (creation keccak `0x52144d19…2b0c`; the
TRON deployment pins TRON's compiler build, another identity). The other two take the frozen vault (creation keccak
`0x901d52d0…3a74`).

Tests: **F** = `solidity-tests/R411UsdtRoutes.t.sol` (stand-in tokens in `solidity-tests/harness/UsdtRouteTokens.sol`);
**R** = `tools/evm-nets/rehearse_route.py <route>` (the REAL token on a loopback fork, step 11; the same run compares
each stand-in with the real contract call by call); **G** = `tools/signatario-stable/test_token_guard_r20.py`.

| # | Token behaviour | What the route does | Pinned by |
|---|---|---|---|
| 1 | Ethereum USDT returns no data from `transfer`, `transferFrom`, `approve` | The vault never decodes a boolean it requires: transferMode 1 ignores the answer and requires exact balance changes on both sides. A caller that decodes one reverts (control) | F `R411EthereumUsdtTokenTest.test_transfer_transferFrom_and_approve_return_no_data`, `test_a_caller_that_decodes_a_boolean_reverts`; F `R411EthereumUsdtVaultTest` (all ten); R steps 1, 4, 5 on the real token |
| 2 | Ethereum USDT: `approve` reverts from non-zero to non-zero | The vault never calls `approve`. The rule is the depositor's: `bridge.network.json` `deposit.steps` tells the page to read the allowance and send `approve(vault, 0)` first; `asset.behaviour.approveZeroFirst` is true | F `R411EthereumUsdtChoiceTest.test_the_vault_never_calls_approve`, `test_a_standing_allowance_serves_a_deposit_and_a_new_one_goes_through_zero`; F `…TokenTest.test_approve_must_go_through_zero`; R stand-in comparison rows "approve 5 -> 7", "approve 5 -> 5" |
| 3 | Ethereum USDT: the fee switch (`basisPointsRate`, `maximumFee`; zero today) | A deposit that would deliver less than its amount is refused: the vault books what it received or nothing. A release and a fee sweep still pay: the vault's balance falls by exactly what it sent, the recipient bears the issuer's fee (at most 20 bps and 50 USDT, the limits in the token's code), `IssuerFeeKept` is logged. The signers attest no deposit while either parameter is non-zero | F `…ChoiceTest.test_fuzz_no_fee_setting_makes_the_vault_credit_more_than_it_received`; F `…VaultTest.test_d_issuerFeeOn_depositsRefusedReleaseAndSweepPayRecipientBearsTheFee`, `test_d_issuerFeeOn_transfersWithoutAnEffectiveFeeLeaveNoTrace`; R "with the transfer fee ON a deposit is refused", "a release still pays", "guard: the issuer's transfer fee on"; G `test_the_fee_switch_the_pause_the_replacement_and_the_blacklist_each_stop_minting_on_ethereum` |
| 4 | Ethereum USDT: the VAULT blacklisted. The token alone accepts a `transferFrom` INTO a blacklisted address | The vault refuses the deposit itself (`TokenUnsafe`): it reads `isBlackListed(vault)` and `deprecated()` before every deposit. Releases and sweeps revert in the token with no state change; the same certificate pays after the blacklist is lifted. The signers attest nothing meanwhile | F `…VaultTest.test_a_vaultBlacklisted_allPathsStopNothingChangesThenResume`, `test_a_tokenAloneWouldAcceptADepositIntoABlacklistedVault`, `test_b_destroyedFunds_everyPathRevertsUntilTheBalanceIsRestored`; F `…ChoiceTest.test_control_the_frozen_vault_over_this_token_takes_a_deposit_it_can_never_pay_back` (why the frozen vault is not used here); R "with the VAULT blacklisted …" (three checks), "guard: the vault blacklisted" |
| 5 | A blacklisted DEPOSITOR | The token refuses the `transferFrom`; nothing is booked | F `…VaultTest.test_g_blacklistedDepositorIsRefusedNothingChanges`; F `R411Usdt0VaultTest.test_a_blocked_recipient_is_paid_and_a_blocked_depositor_is_refused`; R (Arbitrum) "a blocked depositor cannot deposit" |
| 6 | A blacklisted / blocked RELEASE RECIPIENT. Both tokens check the sender side only: the recipient is PAID, and the issuer can then destroy that balance | The release is paid like any other; nothing waits. (USDC differs: there the transfer reverts and the burn waits for the issuer.) | F `…VaultTest.test_f_blacklistedReleaseRecipientAndFeeRecipientArePaid`; F `R411Usdt0VaultTest.test_a_blocked_recipient_is_paid_…`; R "a burn to a recipient the issuer BLACKLISTED is paid" (Ethereum), "… the owner BLOCKED is paid" (Arbitrum) |
| 7 | A release the token refuses (the vault blocked, the token paused, on Arbitrum the recipient being the token contract itself, which no transfer can reach) | Section 4: the release transaction reverts as a whole; no nonce and no burn is consumed, `totalLocked` is unchanged, later burns are paid | F `R411Usdt0VaultTest.test_a_release_the_token_refuses_consumes_nothing_and_blocks_no_other`; R (Arbitrum) "a burn whose recipient the token refuses for good … is never paid", "does not stop the next burn", "books after the refused burn" |
| 8 | Pause by the issuer (Ethereum) | Deposits, releases and sweeps revert in the token; nothing changes; everything resumes after the unpause. The signers attest nothing while `paused()` | F `…VaultTest.test_c_tokenPaused_allPathsRevertThenResume`; F `…TokenTest.test_approve_is_not_stopped_by_the_pause_and_transfers_are`; R "with the token PAUSED …", "after the unpause …", "guard: the token paused" |
| 9 | `deprecate` (Ethereum): every call is forwarded to another contract | The vault refuses every deposit from then on (`tokenState()` reports the replacement). Exits stay open through the forwarder: a release pays once the upgraded token holds the vault's balance, with the same exact-debit rule. The signers attest nothing: `deprecated()` is pinned false | F `…VaultTest.test_e_deprecated_depositsRefusedReleasesPayThroughTheForwarder`; R "after `deprecate` the vault reports the replacement", "guard: the token replaced", "while the upgraded token holds nothing …", "once the upgraded token holds the vault's balance …" (on the REAL token, with a test upgraded token) |
| 10 | USD₮0 (Arbitrum): the VAULT blocked. This token refuses a `transferFrom` whose CALLER is blocked | A blocked vault cannot take a deposit (the token refuses), so the trap of row 4 does not exist here; releases revert with no state change and resume after the unblock | F `R411Usdt0VaultTest.test_a_blocked_vault_cannot_take_a_deposit_or_pay_and_resumes_when_unblocked`, `test_funds_destroyed_in_a_blocked_vault_stop_every_path_until_restored`; R "with the VAULT blocked …", "guard: the vault blocked" |
| 11 | USD₮0 (Arbitrum): an upgrade by the proxy admin | The signers stop attesting as soon as the implementation slot, the implementation's code, the admin or an owner differs. Whatever the new code does, the frozen vault books a deposit only if exactly the amount arrived and pays a release only if exactly the amount left and arrived: an implementation that charges or reads other balances stops the vault's paths instead of mis-booking | F `R411Usdt0VaultTest.test_fuzz_an_upgraded_implementation_that_charges_is_refused_on_every_path`; R "with ANOTHER implementation behind the proxy …", "guard: the implementation replaced"; G `test_a_lifted_route_attests_only_while_every_pin_of_its_guard_holds` |
| 12 | OP Mainnet: the bridge may burn any balance, and can be upgraded | If the vault's balance ever fell below its books, every path stops on the backing check (`InsufficientBacking`): no user is paid with another's funds. The reserves monitor reports the deficit. The signers stop attesting when the bridge's implementation or admin slot changes | F `R411OpUsdtVaultTest.test_fuzz_a_balance_burned_by_the_bridge_stops_every_path_until_restored`; R "after the bridge burned part of the vault's balance …", "the reserves monitor reports …", "guard: the standard bridge upgraded" |
| 13 | Why each route has the vault it has | The Tether-aware vault cannot be deployed over USD₮0 or the OP token (they lack `isBlackListed` and `deprecated`); the frozen vault over Ethereum USDT would take a deposit into a blacklisted vault and stop every exit while the issuer's fee is on | F `R411Usdt0VaultTest.test_the_tether_aware_vault_refuses_this_token_at_deployment`, `R411OpUsdtVaultTest.test_the_tether_aware_vault_refuses_this_token_at_deployment`, `…ChoiceTest.test_control_…` |
| 14 | The stand-in tokens are faithful | Each stand-in is deployed beside the real contract on the fork and both are driven through the same calls by the same accounts | R "the … stand-in of the forge suites answers N of N probe calls as the real contract": Ethereum 30, Arbitrum One 23, OP Mainnet 12 |

### Rehearsals on loopback forks with the real tokens

`python3 tools/evm-nets/rehearse_route.py <route>`: two loopback anvils (a fork of the source network, a plain one
standing in for the L2), throwaway keys, the real daemons (`signatario.py` with `eth_half.py`, `vigia.py` sign and
relay, `guardiao.py`, `reservas.py`), the unchanged contract artifacts. Steps 1 to 10 are the EVM network rehearsal's
(deposit, no attestation before finality, credit after the 12 h delay, burn, release with the fee to the owner's
address, replay, forged and under-quorum certificates, limits, guardian pause and 6-of-7 unpause, a deposit that
disappears after attestation); step 11 is the token's issuer, with the vault in each role. Each route runs under a
rehearsal chain id (it is held). Run of 2026-11-19 on the build host at commit `5dc29d0`:

| Route | Fork block | Chain id of the run | Result | Step 11 checks | Stand-in = real | Gas: deposit / release |
|---|---|---|---|---|---|---|
| `ethereum-usdt` | 26,446,698 | 900,000,001 | **59 / 59** | 23 | 30 of 30 calls | 152,113 / 208,076 |
| `arbitrum-one-usdt` | 525,516,424 | 900,042,161 | **55 / 55** | 17 | 23 of 23 calls | 154,138 / 206,714 (execution only) |
| `op-mainnet-usdt` | 159,731,887 | 900,000,010 | **46 / 46** | 9 | 12 of 12 calls | 134,016 / 193,755 (execution only) |

The release on Ethereum costs 208,076 gas with the Tether-aware vault and the real token, against the 207,000 the
launch registry records for the USDC route (`relayCost.ethereum`), from which the deploy tools derive the least
minimum burn: 0.5% more, on a floor of about 0.76 USDT against a minimum burn of 100.

## 4. A release the token refuses: the path of the claim

The vault keeps no queue. A release is identified by its burn nonce and its burn id; `releasedNonce` and `releasedBurn`
are sets, written only by a release that paid. So:

1. The relayer submits the certificate. The token's `transfer` reverts, the vault's `release` reverts with it, and
   nothing is written: the nonce and the burn stay unspent, `totalLocked`, the release bucket and the fee books are
   unchanged. The relayer simulates first, so normally nothing is even sent.
2. Every other burn is unaffected: the relayer goes on to the next one and it is paid (rehearsed on Arbitrum One with
   a burn to the token contract itself, which can never be paid, followed by a normal burn).
3. The refused burn keeps its claim. Its certificate expires (`validUntil`, and the anchor's 256-block window); when
   the token accepts the transfer again (blacklist of the vault lifted, pause ended) the signers sign a new round for
   the same burn and it is paid, exactly once (rehearsed on Ethereum for the blacklisted vault and the pause).
4. A claim whose recipient the token refuses FOR GOOD is never paid: the burn names its recipient on the L2 and no
   key can redirect it. The burned amount stays locked in the vault (backing nothing: the L2 supply fell by it). On
   these routes the only such recipient known is, on Arbitrum One, the USD₮0 contract itself;
   `asset.behaviour.recipientRefusals` names it so that a page refuses it before the burn. A blocked recipient is NOT
   such a case on either token: it is paid (row 6).

## 5. What refuses a held route, and what lifting one means

| Tool | What it does for a held route |
|---|---|
| `tools/evm-nets/asset_routes.py refusal(chain id, token)` | the reason; "cannot be trusted" for every decided pair when the file and the code disagree, or the file or the launch registry is missing |
| `tools/evm-nets/asset_routes.py write` / `check` | writes `bridge.network.json` and nothing else; `check` fails while any other file exists under `deployments/<route>/` |
| `tools/deploy-pontes/vault_pontes.py validate / args / verify` | refused with the route's reason for any config whose `vault.token` is the route's asset on its chain, whatever the rest says |
| `tools/deploy-pontes/deploy_pontes.py validate / plan / run / record / verify`, `route <id> …` | refused for a token config naming the route's L2 name or symbol on its chain; `route` prints the reason |
| `tools/signatario-stable/eth_half.py deposit / release` (the source half of every signer) | reads the vault's `token()`; refused before anything is attested or signed. No config key lifts it |
| `tools/deploy-pontes/ceremony_kit.py` | validates through the two deploy tools above, so it refuses; it also accepts only the frozen vault contract (not extended to the Tether-aware vault, section 10) |
| `ops/bundle.py` | knows no such route (as it knows no Base): no operator package can be built |
| `deployments/bridges.json` (`registry.py`) | `launch.v1` false, state `held`, source `asset-route-registry`; a finding can lower a state, nothing raises it |

Lifting a route is one reviewed commit that changes `asset-routes.json` and `DECIDED` in `asset_routes.py` together.
Then `asset_routes.py write` generates `busdt-vault.config.json`, `busdt-token.config.json` and the three operator
templates (the signer's source half with `"token_guard": "registry"`), the deploy tools accept exactly the route's
vault contract, transfer mode, labels, cap, window, fees, minimums, L2 name and symbol, and `deploy_pontes.py` reads
the source vault's `token()` and refuses a token deployed over another route's vault (with two vaults on one chain a
mis-paired token would mint the other route's deposits a second time). All of this is tested on a copy of the
registry in which the route is lifted (`tools/deploy-pontes/test_asset_routes.py`, class `Lifted`).

## 6. Cross-route isolation with two routes on one chain

Two routes of one network share the chain id word of every digest. They are separated by the vault address (in the
release digest, the control digests and the mint digest's `sourceVault`) and by the route id (`routeId()` hashes the
vault's own address and its token). `tools/allnets/registry.py`:

| Check | Statement |
|---|---|
| C1 | route ids unique; a file's directory is its route id; a further route is `<network.id>-<asset key>`, beside the first route of its network and of its kind |
| C3, C4 | one source chain id and one source-domain label per NETWORK, never shared by two networks (for every tree before round 20 this is the old "unique per route") |
| C9 (new) | no two routes share a decided custody address or a decided L2 token address, registry-wide |
| C10 (new) | one route per (network, asset key) and per (network, asset address), compared without case |
| C2, C5, C6, C7, C8 | unchanged, and they cover the further routes |

`tools/allnets/test_cross_route.py`: 12 x 12 release cells and 13 x 13 mint cells accepted only on the diagonal, with
one shared vault address for the first route of every network and an own address for each further route; the control
shows that two routes of one network at ONE vault address would accept each other's certificates (impossible on a
chain, and refused in the files by C9).

## 7. Operators (delta on `docs/BRIDGE-V3-OPERATOR-RUNBOOK.md`; applies only once a route is lifted)

- One more set of daemons per route (signer, source half, relayer, guardian, reserves), with its own files, database,
  signature directory and feed; never share any of them with the USDC route of the same network. The same node of
  the source network serves both routes.
- The source half prints, when it refuses a deposit, `the asset contract is not in the state this route pins` and the
  list of differences. That is an incident: the token changed. Do not edit the guard; report it. Deposits already in
  the vault stay there and are attested when the state is back.
- `python3 tools/evm-nets/asset_routes.py guard <route> --rpc <own node> --vault <vault>` prints the same reading at
  any time (exit 1 on a difference); run it from the monitor.
- Ethereum only: `vault_pontes.py verify` also requires `tokenState()` = known, not blacklisted, not replaced.

## 8. Audit scope note for the new routes

In scope for an auditor of these three routes, beyond the scopes they inherit (`docs/AUDIT-SCOPE-BRIDGE-V3.md` for the
frozen vault and the L2 token; `docs/BRIDGE-TRON-USDT.md` section 10 and `docs/TRON-VAULT-DIFF.md` for the
Tether-aware vault):

1. **`TronSourceVault` on the EVM, in the stock solc 0.8.24 build** (creation keccak `0x52144d19…2b0c`). The TRON
   reviews (R325-TRX, R342-TRX) examined this source for the TVM and TRON's compiler; nobody has reviewed it as an
   Ethereum deployment. Questions: are the two constants `ISSUER_FEE_MAX_BPS` 20 and `ISSUER_FEE_MAX` 50 USDT the
   bounds of the ETHEREUM contract's `setParams` (measured: 20 and 50 refused, 19 and 49 accepted); does the deposit
   gate read the right getters of the Ethereum contract; the 256-block window on Ethereum (the frozen vault's).
2. **No new Solidity.** The diff of `contracts/` against `main` is empty. The new on-chain surface is the choice of
   vault per token and the constructor arguments (transferMode 1 and `releaseFlat` 0 on Ethereum).
3. **The token guard** (`token_guard.py`, `eth_half.py asset_route / guard_deposit`): is every admin power of section
   2 visible to it; the interval between two reads; the decision that releases are not guarded; fail-closed on every
   read error.
4. **The asset-route registry and the two deploy tools**: the two-record rule, the held refusals, the lifted path,
   `expected_source_asset` (a token over another route's vault).
5. **The registry's restated checks** C1, C3, C4 and the new C9, C10.
6. **Token facts** of section 2, in particular the three not verified here: who signs for Tether's `owner()` contract,
   who holds the five keys of the USD₮0 Safe, and the OP Stack upgrade authority over the standard bridge.

Out of scope here and unchanged: the frozen vault's and the L2 token's own logic, the committee, the L2.

## 9. What did not move (decision 1)

- `git diff 135bdba -- contracts/` is empty; the creation keccaks of the frozen vault (`0x901d52d0…3a74`), the L2
  token (`0xe560441f…1de7`) and `TronSourceVault` (stock build `0x52144d19…2b0c`) are those of `135bdba`.
- `git diff 135bdba -- deployments/mainnet deployments/arbitrum-one deployments/op-mainnet deployments/linea
  deployments/base deployments/bnb deployments/bitcoin deployments/solana deployments/stellar deployments/tron
  tools/evm-nets/networks.json tools/evm-nets/launch.py tools/evm-nets/evm_nets.py` is empty.
- Every route entry of `deployments/bridges.json` that existed at `135bdba` is byte-identical (the generator adds the
  `route` key to further routes only); `tokenCreationCodeKeccak` unchanged. Pinned field by field in
  `tools/allnets/test_registry_multi.py::test_no_identity_of_an_earlier_route_moved`.
- A vault over USDC is decided from code alone in the signer's source half: it reads the vault's `token()` (one added
  read), finds no further route, loads no registry file and takes the path of before
  (`test_a_vault_over_usdc_has_no_guard_and_never_reads_the_registry_file`).

## 10. Not done / not proven

- Nothing is deployed; no real key was used; every rehearsal is a loopback fork under a rehearsal chain id.
- The three routes are held: no independent review, no external audit, no key ceremony.
- The ceremony kit (`ceremony_kit.py`) was not extended: it refuses the routes (held) and, as written, accepts only
  the frozen vault contract, so `ethereum-usdt` needs a kit change before its ceremony. The operator packages
  (`ops/`) have no entry for the routes; their templates exist only once a route is lifted (generated, and tested on
  a lifted copy, but no package was built or installed).
- The stock-solc build of `TronSourceVault` has never been reviewed as an EVM deployment (section 8, item 1).
- The token guard does not see a change that is made and undone between two finalized blocks a signer reads, and it
  reads the admin's addresses, not the admin's intentions: an upgrade is seen when it is executed, not when it is
  scheduled.
- Not examined: the signers of Tether's owner contract; the holders of the USD₮0 Safe keys; whether USD₮0 is
  redeemable for USDT; the OP Stack upgrade authority; the L1 data fee of a real release on Arbitrum One and OP
  Mainnet (as for USDC, R325-EVM-11).
- `deprecate` on Ethereum was rehearsed on the real token with a TEST upgraded token; what Tether's own upgraded
  contract would do is unknown. The vault refuses deposits from that moment and the signers attest nothing.
- The earlier offline observers (`docs/USDT-ETHEREUM-OBSERVER.md`, `docs/USDT-NETWORK-INTEGRATION.md`, September 2026)
  describe a different design (a native Bloch L1 asset) and are not used by these routes; their requirements that
  still hold (route by address and chain, never by symbol; separate books per route; the `finalized` selector) are
  met by the design above.
