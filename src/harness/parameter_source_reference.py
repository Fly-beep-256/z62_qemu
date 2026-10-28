"""Read-only recorded parameter references; never a RAM replay input."""
from pathlib import Path
import hashlib
import json
import re

EXPECTED = {
    'region50': (0x168000, '3131474120fa6a149b14709932bce810f9d801c2aabca01eda75e26bcc62fb93'),
    'region47': (0xD8000, '996d4ae717a00eb76d9b6ee42e92736bdf74069cc44a95af709ab228e0f6b76b'),
}
ROM_SHA = 'bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4'
HEADER = 'nikon-z6ii-parameter-stage-contract.h'
REGION47_TABLE_SHA = 'cb2c3e5b6314130e64933190d375c1cce13f619ad6a4128c9a05f40947ad2fa0'


def inspect_spec(path, manifest=None):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    spec = json.loads(raw)
    if (spec.get('schema') != 'z6ii.parameter-source-reference/1' or
            spec.get('guest_RAM_seed') is not False or
            spec.get('physical_Flash_container') is not False or
            spec.get('ROM_sha256') != ROM_SHA or
            set(spec.get('references', {})) != set(EXPECTED)):
        raise ValueError('Parameter reference spec must describe only pinned read-only recorded RAM')
    if ('ROM_region47_table_sha256' in spec and
            spec['ROM_region47_table_sha256'] != REGION47_TABLE_SHA):
        raise ValueError('Region47 original move table identity differs from pinned ROM')
    references, environment = {}, {}
    for region, (size, expected) in EXPECTED.items():
        item = spec['references'][region]
        ref = Path(item['path']).resolve(strict=True)
        if (item.get('source_kind') != 'recorded-camera-runtime-RAM' or
                item.get('use') != 'read-only-provenance-comparison' or
                item.get('guest_RAM_seed') is not False or not ref.is_file()):
            raise ValueError('Parameter reference source classification is invalid: ' + region)
        data = ref.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if len(data) != size or actual != expected or item.get('sha256') != expected or item.get('bytes') != size:
            raise ValueError('Parameter reference identity differs from recorded source: ' + region)
        references[region] = dict(path=str(ref), bytes=size, sha256=actual,
                                  source_kind=item['source_kind'], guest_RAM_seed=False)
        environment['Z6II_PARAMETER_RECORDED' + region[6:] + '_REFERENCE'] = str(ref)
    if manifest is not None:
        selected = manifest.get('immutable_model_sources', {}).get(HEADER)
        if not selected:
            raise ValueError('Selected immutable binary has no ROM stage source contract')
        header = Path(selected).read_bytes()
        digest = hashlib.sha256(header).hexdigest()
        if digest != manifest['z6ii_sources'][HEADER] or digest != spec.get('contract_header_sha256'):
            raise ValueError('Selected immutable contract differs from reference spec')
        checks = [('ROM_SHA256', spec['ROM_sha256']),
                  ('TABLE_SHA256', spec.get('ROM_table_sha256'))]
        # Historical binaries only declare region50. A binary that includes
        # the region47 contract must also bind its original table in the spec.
        if re.search(rb'#define\s+Z6II_PARAMETER_CONTRACT_REGION47_TABLE_SHA256\s', header):
            checks.append(('REGION47_TABLE_SHA256', spec.get('ROM_region47_table_sha256')))
        for key, expected in checks:
            match = re.search(rb'#define\s+Z6II_PARAMETER_CONTRACT_' + key.encode() + rb'\s+"([0-9a-f]{64})"', header)
            if not match or match[1].decode() != expected:
                raise ValueError('ROM-derived parameter contract identity mismatch: ' + key)
    return dict(schema=spec['schema'], spec_path=str(path),
                spec_sha256=hashlib.sha256(raw).hexdigest(), references=references,
                contract_header_sha256=spec.get('contract_header_sha256'),
                ROM_region47_table_sha256=spec.get('ROM_region47_table_sha256'),
                comparison_only=True, guest_RAM_seed=False, physical_Flash_container=False), environment
