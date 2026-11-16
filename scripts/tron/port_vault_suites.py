#!/usr/bin/env python3
"""Port the Ethereum vault's forge suites to TronSourceVault, mechanically.

Reads the suites in solidity-tests/ that construct ProvenanceSourceVault and writes, for each,
solidity-tests/tron-ported/<Name>Tron.t.sol: the same tests, unchanged, run against
contracts/tron/TronSourceVault.sol. The transformation is purely textual and has five rules:

  1. every identifier `ProvenanceSourceVault` becomes `TronSourceVault`, and its import comes from
     contracts/tron/TronSourceVault.sol;
  2. the sixth constructor argument (`transferMode`) of every `new TronSourceVault(...)` goes from the literal `0`
     to `1` (TRON-2: the only mode the TRON vault accepts);
  3. every mock token defined in a suite (a contract with `decimals` and `transferFrom`) gains the two TetherToken
     getters the TRON vault requires (TRON-3/TRON-4), both answering a constant `false`:
     `isBlackListed(address)` and `deprecated()`;
  4. every top-level contract, interface and library a suite defines gets the suffix `Tron`, so that the ported
     artifacts never share a name with the originals; relative import paths are moved one directory down;
  5. the tests named in NOT_PORTED are kept in the file but renamed so that forge does not run them, with the
     reason written above them.

Nothing else is changed, so a ported suite that passes is evidence that the TRON vault satisfies the same test as
the Ethereum vault. Suites named in NOT_PORTED_SUITES are not generated at all.

Usage:
    scripts/tron/port_vault_suites.py            write the ported suites
    scripts/tron/port_vault_suites.py --check    exit 1 if a ported suite on disk differs from what would be written
    scripts/tron/port_vault_suites.py --list     print what is ported and what is not, with reasons
"""

import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "solidity-tests"
OUT = SRC / "tron-ported"

# Suites ported, in dependency order is not required. `R194Base.sol` is the shared base of the four R194 suites.
SUITES = [
    "R197BridgeFee.t.sol",
    "A172VaultReview.t.sol",
    "D6Provenance.t.sol",
    "D6Compose.t.sol",
    "R10BridgeParams.t.sol",
    "A123ReauditV3.t.sol",
    "A129FinalV3.t.sol",
    "AuditR7V3.t.sol",
    "R194Base.sol",
    "R194BucketRefund.t.sol",
    "R194PendingCap.t.sol",
    "R194T0Rule.t.sol",
    "R194VerifierCodehash.t.sol",
    "A239LcSwitch.t.sol",
    "A239Metamorphic.t.sol",
    "A276MintVerifier.t.sol",
    "R310SecondPass.t.sol",
    "RecoverableReleaseVerifierV3.t.sol",
    "RecoverableReleaseVerifierV3Groth16.t.sol",
]

# Suites that construct ProvenanceSourceVault but are not ported, and why.
_HELD = (
    "tests contracts/usdt/HeldStateSettlementVerifier.sol, whose Config, registerBurn and settledBurn are typed to the "
    "contract ProvenanceSourceVault and its Release struct; a textual port does not compile. It needs a TRON build of "
    "that verifier (or hand-written casts), which is outside a mechanical port."
)
NOT_PORTED_SUITES = {
    "R306HeldStateSettlement.t.sol": _HELD,
    "R306VerifierReview.t.sol": _HELD,
    "R310SettlementReview.t.sol": _HELD,
}

# (suite, test function) -> reason. The test stays in the ported file, renamed `tronNotPorted_<name>`.
NOT_PORTED = {}

GETTERS = (
    "    // TRON port: the two TetherToken getters TronSourceVault requires (TRON-3, TRON-4), always false.\n"
    "    function isBlackListed(address) external pure returns (bool) {\n"
    "        return false;\n"
    "    }\n"
    "\n"
    "    function deprecated() external pure returns (bool) {\n"
    "        return false;\n"
    "    }\n"
    "\n"
)

TOP_LEVEL = re.compile(r"^(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)


def ported_name(name: str) -> str:
    """R197BridgeFee.t.sol -> R197BridgeFeeTron.t.sol; R194Base.sol -> R194BaseTron.sol."""
    if name.endswith(".t.sol"):
        return name[: -len(".t.sol")] + "Tron.t.sol"
    return name[: -len(".sol")] + "Tron.sol"


def defined_names(text: str) -> list:
    return TOP_LEVEL.findall(text)


def matching(text: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index of the bracket closing the one at `start`. Strings in these suites hold no unbalanced brackets."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == open_ch:
            depth += 1
        elif text[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("unbalanced bracket")


def split_top_level(args: str) -> list:
    """Split a call's argument text on its top-level commas; returns (start, end) spans."""
    spans, depth, begin = [], 0, 0
    for i, ch in enumerate(args):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            spans.append((begin, i))
            begin = i + 1
    spans.append((begin, len(args)))
    return spans


def set_transfer_mode(text: str, suite: str) -> str:
    """Rule 2."""
    out, pos = [], 0
    for m in re.finditer(r"new TronSourceVault\(", text):
        open_at = m.end() - 1
        close_at = matching(text, open_at, "(", ")")
        args = text[open_at + 1 : close_at]
        spans = split_top_level(args)
        if len(spans) != 11:
            raise SystemExit(f"{suite}: a vault constructor call with {len(spans)} arguments")
        a, b = spans[5]
        mode = args[a:b]
        if mode.strip() != "0":
            raise SystemExit(f"{suite}: transferMode is `{mode.strip()}`, not the literal 0: port it by hand")
        out.append(text[pos : open_at + 1 + a])
        out.append(mode.replace("0", "1"))
        pos = open_at + 1 + b
    out.append(text[pos:])
    return "".join(out)


def add_getters(text: str) -> str:
    """Rule 3."""
    out, pos = [], 0
    for m in re.finditer(r"^contract\s+[A-Za-z_][A-Za-z0-9_]*[^{\n]*\{\n", text, re.M):
        end = matching(text, m.end() - 2, "{", "}")
        body = text[m.end() : end]
        if "function transferFrom(" in body and "decimals" in body and "isBlackListed" not in body:
            out.append(text[pos : m.end()])
            out.append(GETTERS)
            pos = m.end()
    out.append(text[pos:])
    return "".join(out)


def port(suite: str, renames: dict) -> str:
    source = (SRC / suite).read_text()
    digest = hashlib.sha256(source.encode()).hexdigest()
    rename_re = re.compile(r"\b(" + "|".join(sorted(map(re.escape, renames), key=len, reverse=True)) + r")\b")
    lines = []
    for line in source.split("\n"):
        if line.startswith("import "):
            path = re.search(r'"([^"]+)"', line).group(1)
            if path == "../contracts/usdt/ProvenanceSourceVault.sol":
                # Rule 1. Any other symbol this import brings (the verifier interfaces) still comes from the
                # Ethereum file, where TronSourceVault itself imports them from.
                names = [n.strip() for n in re.search(r"\{([^}]*)\}", line).group(1).split(",")]
                others = [n for n in names if n != "ProvenanceSourceVault"]
                line = 'import {TronSourceVault} from "../../contracts/tron/TronSourceVault.sol";'
                if others:
                    line += '\nimport {%s} from "../../contracts/usdt/ProvenanceSourceVault.sol";' % ", ".join(others)
            elif path.startswith("../"):
                line = line.replace('"../', '"../../')
            elif path.startswith("./") and path[2:] in SUITES:
                line = rename_re.sub(lambda m: renames[m.group(1)], line.split('"')[0]) + '"./%s";' % ported_name(path[2:])
            elif path.startswith("./"):
                line = line.replace('"./', '"../')
            else:
                raise SystemExit(f"{suite}: unexpected import {path}")
        else:
            line = line.replace("ProvenanceSourceVault", "TronSourceVault")  # rule 1
            line = rename_re.sub(lambda m: renames[m.group(1)], line)  # rule 4
        lines.append(line)
    text = "\n".join(lines)
    text = set_transfer_mode(text, suite)
    text = add_getters(text)
    for (s, test), reason in NOT_PORTED.items():  # rule 5
        if s != suite:
            continue
        pattern = re.compile(r"^(\s*)function " + re.escape(test) + r"\(", re.M)
        if len(pattern.findall(text)) != 1:
            raise SystemExit(f"{suite}: test {test} not found exactly once")
        text = pattern.sub(
            lambda m: "%s/// NOT PORTED to TRON: %s\n%sfunction tronNotPorted_%s(" % (m.group(1), reason, m.group(1), test),
            text,
        )
    header = (
        "// GENERATED by scripts/tron/port_vault_suites.py from solidity-tests/%s\n"
        "// (sha256 %s). Do not edit: change the source suite or the generator and regenerate.\n" % (suite, digest)
    )
    first, rest = text.split("\n", 1)  # keep the SPDX line first
    return first + "\n" + header + rest


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "--write"
    if mode not in ("--write", "--check", "--list"):
        print(__doc__)
        return 2
    if mode == "--list":
        print("ported suites:")
        for s in SUITES:
            print("  %s -> tron-ported/%s" % (s, ported_name(s)))
        print("suites not ported:")
        for s, why in NOT_PORTED_SUITES.items():
            print("  %s: %s" % (s, why))
        print("tests not ported:")
        for (s, t), why in NOT_PORTED.items():
            print("  %s %s: %s" % (s, t, why))
        return 0
    renames = {}
    for s in SUITES:
        for name in defined_names((SRC / s).read_text()):
            renames[name] = name + "Tron"
    # Every suite that constructs the Ethereum vault is either ported or listed with a reason.
    for path in sorted(SRC.glob("*.sol")):
        if path.name.startswith("Tron") or "new ProvenanceSourceVault(" not in path.read_text():
            continue
        if path.name not in SUITES and path.name not in NOT_PORTED_SUITES:
            raise SystemExit(f"{path.name} constructs ProvenanceSourceVault but is neither ported nor listed")
    stale = 0
    if mode == "--write":
        OUT.mkdir(exist_ok=True)
    for s in SUITES:
        text = port(s, renames)
        target = OUT / ported_name(s)
        if mode == "--check":
            if not target.exists() or target.read_text() != text:
                print("stale: %s" % target.relative_to(ROOT))
                stale += 1
        else:
            target.write_text(text)
            print("wrote %s" % target.relative_to(ROOT))
    if mode == "--check":
        extra = {p.name for p in OUT.glob("*.sol")} - {ported_name(s) for s in SUITES}
        for name in sorted(extra):
            print("unexpected: solidity-tests/tron-ported/%s" % name)
        return 1 if stale or extra else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
