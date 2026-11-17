// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.24;

import {ProvenanceSourceVault as V} from "../contracts/usdt/ProvenanceSourceVault.sol";

/// Review 329 demonstration, not product code. Run as the creation code of ONE read-only `eth_call` (no `to`) against a
/// node of the real network: inside that single simulated execution it creates a six-decimal stand-in token and the
/// frozen ProvenanceSourceVault (creation code passed in and checked against the freeze hash), opens it, deposits, and
/// sends `release` with a certificate whose anchor is what `evm_anchor.py` read from the same node. Nothing is sent to
/// the network. It shows the vault's `block.number` / `blockhash` anchor check under the node's own execution rules
/// (Arbitrum Nitro: Ethereum block numbers and ArbOS's block hashes), which anvil cannot show (R325-EVM-11).
contract R329Token {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mintTo(address to, uint256 v) external {
        balanceOf[to] += v;
    }

    function approve(address s, uint256 v) external returns (bool) {
        allowance[msg.sender][s] = v;
        return true;
    }

    function transfer(address to, uint256 v) external returns (bool) {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
        return true;
    }

    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        allowance[f][msg.sender] -= v;
        balanceOf[f] -= v;
        balanceOf[to] += v;
        return true;
    }
}

contract R329NitroSim {
    struct In {
        bytes vaultCreation;
        address[] signers; // 7, ascending
        uint256 validUntil;
        uint256 anchorNumber;
        bytes32 anchorHash;
        uint256 otherNumber; // control: an anchor the Ethereum rule would name (own block number, hash by number)
        bytes32 otherHash;
        bytes[] controlSigs; // empty in phase A
        bytes[] releaseSigs; // empty in phases A and B
        bytes[] otherSigs;
        bytes[] wrongHashSigs;
    }

    struct Out {
        uint256 phase;
        uint256 evmNumber;
        bytes32 evmHashOfAnchor;
        uint256 chainId;
        address vault;
        bytes32 controlDigest;
        bytes32 releaseDigest;
        bytes32 otherDigest;
        bytes32 wrongHashDigest;
        bytes4 otherRefusal;
        bytes4 wrongHashRefusal;
        uint256 paid;
        bool released;
        bytes4 replayRefusal;
        uint256 totalLocked;
    }

    address private constant BOB = 0xB0b0000000000000000000000000000000000329;
    address private constant FEE = 0x775a993F09Bd80aeCF8F8c2ADe0C84158E3a0544;

    constructor(In memory p) {
        Out memory o;
        o.evmNumber = block.number;
        o.evmHashOfAnchor = blockhash(p.anchorNumber);
        o.chainId = block.chainid;
        require(
            keccak256(p.vaultCreation) == 0x901d52d04b519c826bfb1e82a298d96ab1f33a1aec5721db55a7f9dfe2ce3a74,
            "not the frozen vault creation code"
        );
        R329Token usdc = new R329Token();
        V v = V(_create(p, address(usdc)));
        o.vault = address(v);
        o.controlDigest = v.controlDigest(true, true, 0, p.validUntil);
        if (p.controlSigs.length == 0) {
            o.phase = 1;
            _done(o);
        }
        v.setControls(true, true, 0, p.validUntil, p.controlSigs);
        usdc.mintTo(address(this), 5000e6);
        usdc.approve(address(v), type(uint256).max);
        v.deposit(1000e6, bytes32(uint256(uint160(address(this)))));
        V.Release memory item = V.Release(v.routeId(), 1, BOB, 300e6, bytes32(uint256(0x5a5a)), 1, 999500000, v.depositHead(1));
        V.ReleaseContext memory ctx = V.ReleaseContext(p.validUntil, p.anchorNumber, p.anchorHash, 7, bytes32(uint256(0x77)));
        V.ReleaseContext memory other = V.ReleaseContext(p.validUntil, p.otherNumber, p.otherHash, 7, bytes32(uint256(0x77)));
        V.ReleaseContext memory wrong =
            V.ReleaseContext(p.validUntil, p.anchorNumber, bytes32(uint256(p.anchorHash) ^ 1), 7, bytes32(uint256(0x77)));
        o.releaseDigest = v.releaseDigest(item, ctx);
        o.otherDigest = v.releaseDigest(item, other);
        o.wrongHashDigest = v.releaseDigest(item, wrong);
        if (p.releaseSigs.length == 0) {
            o.phase = 2;
            _done(o);
        }
        o.phase = 3;
        o.otherRefusal = _try(v, item, other, p.otherSigs);
        o.wrongHashRefusal = _try(v, item, wrong, p.wrongHashSigs);
        v.release(item, ctx, p.releaseSigs);
        o.paid = usdc.balanceOf(BOB);
        o.released = v.releasedBurn(item.nativeBurn);
        o.replayRefusal = _try(v, item, ctx, p.releaseSigs);
        o.totalLocked = v.totalLocked();
        _done(o);
    }

    function _create(In memory p, address usdc) private returns (address v) {
        bytes memory init = abi.encodePacked(
            p.vaultCreation,
            abi.encode(
                keccak256("arbitrum-one"),
                keccak256("bloch-l2-700770"),
                keccak256("USDC"),
                usdc,
                uint64(100_000e6),
                uint8(0),
                p.signers,
                uint8(5),
                V.Policy(10_000e6, 86400, 6, 1209600, 11e6, 10e6),
                V.Guard(new address[](0), 0, 0),
                V.Provenance(1, 0, address(0), V.Fees(FEE, 5, 5))
            )
        );
        assembly {
            v := create(0, add(init, 32), mload(init))
        }
        require(v != address(0), "vault creation failed");
    }

    function _try(V v, V.Release memory item, V.ReleaseContext memory ctx, bytes[] memory sigs) private returns (bytes4 sel) {
        try v.release(item, ctx, sigs) {
            sel = 0xffffffff; // accepted: must not happen for a control
        } catch (bytes memory why) {
            if (why.length >= 4) {
                assembly {
                    sel := mload(add(why, 32))
                }
            }
        }
    }

    function _done(Out memory o) private pure {
        bytes memory out = abi.encode(o);
        assembly {
            return(add(out, 32), mload(out))
        }
    }
}
