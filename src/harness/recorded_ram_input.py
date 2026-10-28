"""Explicit replay of camera RAM resources at the original runtime entry.

These inputs are loaded RAM bodies, not the physical Flash containers. The
only allowed destinations are the complete region0B/0C descriptor extents.
No register, resource-table, callback or completion flag is supplied.
"""
from pathlib import Path
import hashlib
import json
from portable_identity import normalized_identity

HOOK = 0x104393AC
ROM_BASE = 0x10020000
MASTER_SHA256 = 'bb83613121f843d65101da936d942acdc513d86dbd3abc26259d0d870d03f5d4'
REGIONS = {'0B': (0x80400000, 0x24FFF8), '0C': (0x80660000, 0xDFFF8)}


def identity(path, data=None):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes() if data is None else data
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def inspect_spec(path, original_master):
    path = Path(path).resolve(strict=True)
    spec = json.loads(path.read_text())
    if spec.get('schema') != 'z6ii.recorded-master-resource-RAM/2':
        raise ValueError('Unsupported recorded RAM input schema')
    if hashlib.sha256(original_master).hexdigest() != MASTER_SHA256:
        raise ValueError('Recorded RAM replay requires the verified original Z6II V1.70 Master')
    point = spec['execution_point']
    expected_code = original_master[HOOK - ROM_BASE:HOOK - ROM_BASE + 16].hex()
    branch = point['normal_reset_branch']
    veneer = point['ARM_to_Thumb_veneer']
    if (int(point['address'], 0) != HOOK or point['original_code16_hex'] != expected_code or
            point['original_master_sha256'] != MASTER_SHA256 or
            branch != dict(address='0x1002bf98', original_code4_hex='013510ea', target='0x104393a4') or
            veneer != dict(address='0x104393a4', original_code8_hex='01c08fe21cff2fe1', target='0x104393ac') or
            original_master[0x1002BF98-ROM_BASE:0x1002BF9C-ROM_BASE].hex() != branch['original_code4_hex'] or
            original_master[0x104393A4-ROM_BASE:HOOK-ROM_BASE].hex() != veneer['original_code8_hex']):
        raise ValueError('Normal ARM reset path or common runtime replay point mismatch')
    bodies, checked, seen = [], [], set()
    for entry in spec['regions']:
        region = entry['region']
        if region not in REGIONS or region in seen:
            raise ValueError('Only distinct complete region0B/0C RAM bodies may be replayed')
        seen.add(region)
        address, length = REGIONS[region]
        if (int(entry['address'], 0) != address or entry['bytes'] != length or
                entry['classification'] != 'recorded_runtime_RAM_body'):
            raise ValueError('Recorded RAM destination, length or classification mismatch')
        first = Path(entry['pass1']['path']).resolve(strict=True).read_bytes()
        second = Path(entry['pass2']['path']).resolve(strict=True).read_bytes()
        for key, body in (('pass1', first), ('pass2', second)):
            if identity(entry[key]['path'], body) != normalized_identity(entry[key]):
                raise ValueError('Recorded RAM file identity changed: ' + key)
        if len(first) != length or first != second:
            raise ValueError('Recorded RAM bodies must cover the complete descriptor and match both reads')
        bodies.append((region, address, first))
        checked.append(entry)
    if '0B' not in seen:
        raise ValueError('Recorded resource replay requires region0B')
    return dict(spec=identity(path), execution_point=point, regions=checked,
                source_kind='camera-loaded RAM; physical Flash container unavailable',
                original_Flash_loader_generation_verified=False), bodies


def _read_neighbor(remote, region, side, address):
    """Keep the two observed unmapped boundaries explicit; reject other errors."""
    check = dict(side=side, address=hex(address), bytes=32)
    try:
        data = remote.memory(address, 32)
    except ValueError as error:
        observed = {('0B', 'prefix', 0x803FFFE0): 'cold106',
                    ('0C', 'suffix', 0x8073FFF8): 'cold107'}
        boundary = (region, side, address)
        if boundary not in observed or str(error) != f'RSP memory {address:#x}: E14':
            raise
        return None, dict(**check, readable=False, error=str(error),
                          byte_comparison_available=False,
                          observed_unmapped_boundary=observed[boundary])
    return data, dict(**check, readable=True, byte_comparison_available=True)


def replay(remote, original_master, bodies):
    """Apply once at common runtime entry, before original services consume RAM.

    The normal ARM reset path jumps through 0x104393A4 directly. Its r10/r11
    values do not describe the unused Thumb scatter loop at 0x10020038.
    """
    registers = remote.registers()
    expected_code = original_master[HOOK - ROM_BASE:HOOK - ROM_BASE + 16]
    if (int(registers['r15'], 16) != HOOK or
            not int(registers['cpsr'], 16) & 0x20 or
            remote.memory(HOOK, 16) != expected_code):
        raise ValueError('Original common Thumb runtime entry was not reached')
    prepared, results = [], []
    # Check every destination and both neighbors before making the first write.
    # An unsupported later boundary must not leave an earlier region replayed.
    for region, address, body in bodies:
        prior = remote.memory(address, len(body))
        prefix, prefix_before = _read_neighbor(remote, region, 'prefix', address - 32)
        suffix, suffix_before = _read_neighbor(remote, region, 'suffix', address + len(body))
        already_loaded = prior == body
        # A nonempty different body may belong to a naturally executed loader;
        # preserve it and reject this run rather than overwrite its output.
        if any(prior) and not already_loaded:
            raise ValueError('Original resource RAM is nonempty and differs from the recorded body: ' + region)
        prepared.append((region, address, body, prior, prefix, suffix,
                         prefix_before, suffix_before, already_loaded))
    for (region, address, body, prior, prefix, suffix,
         prefix_before, suffix_before, already_loaded) in prepared:
        if not already_loaded:
            for offset in range(0, len(body), 2048):
                part = body[offset:offset + 2048]
                if remote.command(f'M{address + offset:x},{len(part):x}:' + part.hex()) != 'OK':
                    raise RuntimeError('Recorded RAM replay write rejected: ' + region)
        actual = remote.memory(address, len(body))
        prefix_after, prefix_check = _read_neighbor(remote, region, 'prefix', address - 32)
        suffix_after, suffix_check = _read_neighbor(remote, region, 'suffix', address + len(body))
        if (actual != body or prefix_after != prefix or suffix_after != suffix or
                prefix_check != prefix_before or suffix_check != suffix_before):
            raise ValueError('Recorded RAM replay readback or neighbor verification failed: ' + region)
        neighbors = [dict(**check, unchanged=True if data is not None else None)
                     for data, check in ((prefix, prefix_before), (suffix, suffix_before))]
        complete_neighbors = all(check['readable'] for check in neighbors)
        results.append(dict(region=region, address=hex(address), bytes=len(body),
            sha256=hashlib.sha256(actual).hexdigest(),
            prior_RAM_sha256=hashlib.sha256(prior).hexdigest(),
            prior_RAM_all_zero=not any(prior), already_loaded=already_loaded,
            replay_performed=not already_loaded, readback_equal=True,
            adjacent_32_bytes_unchanged=True if complete_neighbors else None,
            adjacent_byte_verification_complete=complete_neighbors,
            all_readable_adjacent_bytes_unchanged=True,
            readable_adjacent_bytes_checked=sum(check['bytes'] for check in neighbors if check['readable']),
            unmapped_adjacent_bytes_not_compared=sum(check['bytes'] for check in neighbors if not check['readable']),
            adjacent_verification=neighbors,
            classification='recorded_runtime_RAM_body',
            source_loader_generation_omitted=not already_loaded,
            resource_table_or_ready_flag_written=False))
    if remote.registers() != registers or remote.memory(HOOK, 16) != expected_code:
        raise ValueError('CPU state or original instructions changed during RAM replay')
    return dict(execution_point=hex(HOOK), regions=results,
        all_resource_destinations_prechecked_before_any_write=True,
        original_common_Thumb_runtime_entry_verified=True,
        scatter_r10_r11_condition_used=False, original_CPU_state_unchanged=True,
        original_firmware_instructions_modified=False,
        software_ready_or_callback_written=False, physical_Flash_container_loaded=False)
