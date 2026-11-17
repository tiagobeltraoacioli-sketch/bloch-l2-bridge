#!/usr/bin/env python3
"""R374-1 (round 18, agents 374 and 371): the in-process secp256k1 recovery of the Solana tools accepts exactly the
signatures the vault's native verifier accepts, and refuses everything it refuses.

The vault relies on the native secp256k1 precompile. In agave-precompiles 4.3.2 (src/secp256k1.rs, the crate the
test rig links) the signature is parsed by libsecp256k1 0.7.2 `Signature::parse_standard_slice` (refuses r >= n or
s >= n; accepts a HIGH s), the recovery id by `RecoveryId::parse` (raw byte 0 to 3, nothing else) and the key is
recovered by `libsecp256k1::recover` (no low-s rule). solana_lib.secp256k1_recover takes v as 0/1 or 27/28 (the
Ethereum form the signers print; `secp_instruction` writes it as 0/1) and refuses recovery ids 2 and 3, which the
program accepts: they exist only for r >= p - n (probability about 2^-127) and no signer produces them, so the
tools are stricter there and nowhere looser. A twin (r, n - s, v ^ 1) recovers the same address on both sides; a
signer counts once whatever form it signed in (the vault and `secp_instruction` require distinct signers).
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import solana_lib as S  # noqa: E402
import testkit as K  # noqa: E402


class SecpRuleEqualsTheProgram(unittest.TestCase):
    def setUp(self):
        self.key = 0x1234567 * 7919
        self.digest = S.keccak256(b'release authorization')
        self.sig = K.secp_sign(self.key, self.digest)
        self.address = K.secp_address(self.key)
        self.r, self.s, self.v = int.from_bytes(self.sig[:32], 'big'), int.from_bytes(self.sig[32:64], 'big'), self.sig[64]

    def form(self, r, s, v):
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([v])

    def test_accepted_like_the_program(self):
        self.assertEqual(S.secp256k1_recover(self.digest, self.sig), self.address)
        self.assertEqual(S.secp256k1_recover(self.digest, self.form(self.r, self.s, self.v - 27)), self.address)  # raw 0/1
        twin = self.form(self.r, S._SN - self.s, (self.v - 27) ^ 1)  # high s: parse_standard and recover accept it
        self.assertEqual(S.secp256k1_recover(self.digest, twin), self.address)
        self.assertEqual(S.secp256k1_recover(self.digest, self.form(self.r, S._SN - self.s, 55 - self.v)), self.address)

    def test_refused_like_the_program(self):
        for r, s in ((S._SN, self.s), (self.r, S._SN), (self.r + S._SN, self.s), (0, self.s), (self.r, 0)):
            if r < 2**256 and s < 2**256:
                self.assertIsNone(S.secp256k1_recover(self.digest, self.form(r, s, self.v)), (r, s))
        for v in (4, 5, 26, 29, 255):  # RecoveryId::parse refuses 4 and above; 27/28 are the Ethereum spelling of 0/1
            self.assertIsNone(S.secp256k1_recover(self.digest, self.form(self.r, self.s, v)), v)
        self.assertIsNone(S.secp256k1_recover(self.digest, self.sig[:64]))
        self.assertIsNone(S.secp256k1_recover(self.digest, self.sig + b'\0'))

    def test_stricter_only_for_recovery_ids_2_and_3(self):
        for v in (2, 3):  # accepted by the program (r >= p - n only), refused here: stricter, never looser
            self.assertIsNone(S.secp256k1_recover(self.digest, self.form(self.r, self.s, v)))

    def test_the_instruction_carries_the_programs_recovery_id_and_distinct_signers(self):
        auth = bytes(range(60))
        for v in (27, 28):
            ix = S.secp_instruction(auth, [(self.address, self.form(self.r, self.s, v))], 0)
            self.assertEqual(ix.data[1 + 11 + 64], v - 27)
        twin = self.form(self.r, S._SN - self.s, (self.v - 27) ^ 1)
        with self.assertRaises(S.Refused):  # one signer twice (its signature and its twin) is never two signers
            S.secp_instruction(auth, [(self.address, self.sig), (self.address, twin)], 0)


if __name__ == '__main__':
    unittest.main()
