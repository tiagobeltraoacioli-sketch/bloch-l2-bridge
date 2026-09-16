#!/usr/bin/env python3
"""Read-only bUSDT/bUSDC observer using an explicit, jointly validated catalog."""
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location(
    'stablecoin_observer_cli', Path(__file__).with_name('observe-usdt-deposit.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

if __name__ == '__main__':
    sys.exit(module.main(stablecoins=True))
