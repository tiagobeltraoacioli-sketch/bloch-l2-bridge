#!/usr/bin/env python3
"""Bridge daemons review, round 10 (agents/173): secrets in reservas.py and sombra.py messages. No chain, no key.

  python3 -m unittest -v test_daemons_r10

A FAILURE IS THE REPRODUCTION of a finding. Provider URLs carry the API key in the path (Alchemy, Infura); the
`Unverifiable` text is logged to the journal and, for sombra, kept in the state file.
"""
from pathlib import Path
import sys
import unittest

import reservas

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'guardiao'))
import sombra  # noqa: E402

SECRET = 'r10secretapikey0123456789'
URL = f'http://127.0.0.1:9/v2/{SECRET}'


class R10SecretsInMessages(unittest.TestCase):
    def test_reservas_rpc_failure_does_not_name_the_url_key(self):
        with self.assertRaises(reservas.Unverifiable) as caught:
            reservas.rpc(URL, 'eth_chainId', [])
        self.assertNotIn(SECRET, str(caught.exception))

    def test_sombra_rpc_failure_does_not_name_the_url_key(self):
        with self.assertRaises(sombra.Unverifiable) as caught:
            sombra.Sombra.rpc(None, URL, 'eth_chainId', [])
        self.assertNotIn(SECRET, str(caught.exception))


if __name__ == '__main__':
    unittest.main()
