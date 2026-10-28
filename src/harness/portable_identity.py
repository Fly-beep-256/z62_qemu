"""Normalize relocated paths before the original strict byte identity checks.

This changes path representation only. Size, digest, destination bounds and
classification checks remain in the original validators.
"""
from pathlib import Path
from host_env import ROOT


def normalized_identity(item):
    result = dict(item)
    path = Path(result['path'])
    result['path'] = str((path if path.is_absolute() else ROOT / path).resolve(strict=True))
    return result


def normalize_battery_spec(spec):
    spec['ROM'] = normalized_identity(spec['ROM'])
    spec['source_evidence'] = [normalized_identity(item) for item in spec['source_evidence']]
    for transaction in spec['exact_transactions']:
        transaction['source_paths'] = [str((Path(path) if Path(path).is_absolute() else ROOT / path).resolve(strict=True))
                                       for path in transaction['source_paths']]
    return spec
