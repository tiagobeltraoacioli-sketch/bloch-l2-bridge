#!/bin/bash
# Reviewer 408 (round 19): mutation check of the verifier-mode rule (`_stage_verifier`, scripts/usdt_observer/l2_settlement.py)
# against the pin test `test_a_group_or_other_writable_verifier_is_refused` (fb146b9). Scratch copies only.
# usage: r408_mut_verifier.sh REPO COMMIT OUTDIR      (needs cargo; set CARGO_TARGET_DIR and, offline, CARGO_HOME yourself)
# base: the rule as committed (the class must pass); V1: the mode condition removed; V2: only the group bit checked;
# V3: only the other bit checked. The rule is pinned when the pin test fails for V1, V2 and V3.
set -u
REPO=$1; COMMIT=$2; OUT=$3
for m in base V1 V2 V3; do
  d=$OUT/$m; mkdir -p "$d"; git -C "$REPO" archive "$COMMIT" | tar -x -C "$d"
  f=$d/scripts/usdt_observer/l2_settlement.py
  [ "$(grep -c 'and not before.st_mode & 0o022,' "$f")" = 1 ] || { echo "$m: the rule line was not found exactly once"; exit 3; }
  case $m in
    V1) sed -i 's/and not before.st_mode & 0o022,/and True,/' "$f";;
    V2) sed -i 's/and not before.st_mode & 0o022,/and not before.st_mode \& 0o020,/' "$f";;
    V3) sed -i 's/and not before.st_mode & 0o022,/and not before.st_mode \& 0o002,/' "$f";;
  esac
  echo "== $m: $(grep -n -A1 'before.st_size <= MAX_VERIFIER_BYTES' "$f" | tail -1)"
  ( cd "$d/scripts" && python3 -m unittest discover -s tests -p 'test_custody_deployment_ancestry.py' > "$OUT/$m.log" 2>&1; echo "rc=$?" >> "$OUT/$m.log" )
  grep -E '^(FAIL|ERROR):|^Ran |^OK|^FAILED|^rc=' "$OUT/$m.log" | sort | uniq -c
done
