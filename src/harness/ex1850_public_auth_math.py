"""Inspect public MCU battery TX and immutable ROM without a guest or RX.

The field implementation is copied from the previously closed pure arithmetic
class in verify_usart1_auth_math.py (SHA256
6ae7033f3393368e2b949d183aac0f824f6202327ec63a0c035e8f38bd619871).
This standalone module never imports that script or reads retained SRAM. Its
CLI accepts only an original ROM and one public authentication TX. It produces
no response. Matching a candidate scalar to the public key is a mathematical
check, and is not proof of the scalar's origin or a standard battery identity.
"""

import argparse
import hashlib
import json
from pathlib import Path


ROM_BASE = 0x08000000
ROM_SHA = '4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1'
ROM_BYTES = 524288
SPECS = {
    'P_x': (0x08020000, 18, 'cf4e3fc5d93b3a3f762f86000f0fdc0f0000'),
    'sqrt_b': (0x0802001A, 18, '5e05801b9b5aede287f7cf1d708a073d0000'),
    'G_x': (0x0802002C, 18, '1f6085d2f5b6c44ed32f25501ba620070600'),
    'modulus': (0x0802003E, 18, '0d0100000000000000000000000000000800'),
    'zero': (0x08020050, 18, '000000000000000000000000000000000000'),
    'one': (0x08020062, 18, '010000000000000000000000000000000000'),
}


def identity(path, raw=None):
    raw = path.read_bytes() if raw is None else raw
    return {'path': str(path.resolve()), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


class OriginalField:
    def __init__(self, modulus, sqrt_b):
        self.modulus = modulus
        self.degree = modulus.bit_length() - 1
        self.sqrt_b = sqrt_b
        assert self.degree == 131
        assert modulus == (1 << 131) | (1 << 8) | (1 << 3) | (1 << 2) | 1

    def reduce(self, value):
        assert value >= 0
        while value.bit_length() > self.degree:
            value ^= self.modulus << (value.bit_length() - self.degree - 1)
        return value

    def mul(self, left, right):
        result = 0
        while right:
            if right & 1:
                result ^= left
            right >>= 1
            left <<= 1
        return self.reduce(result)

    def square(self, value):
        return self.mul(value, value)

    def inverse(self, value):
        value = self.reduce(value)
        if value == 0:
            raise ValueError('inverse of zero')
        u, v, g1, g2 = value, self.modulus, 1, 0
        while u != 1:
            if u == 0:
                raise ValueError('noninvertible field element')
            shift = u.bit_length() - v.bit_length()
            if shift < 0:
                u, v, g1, g2 = v, u, g2, g1
                shift = -shift
            u ^= v << shift
            g1 ^= g2 << shift
        return self.reduce(g1)

    def double(self, point):
        x, z = point
        xx, zz = self.square(x), self.square(z)
        return (self.square(xx ^ self.mul(self.sqrt_b, zz)), self.mul(xx, zz))

    def add(self, left, right, difference_x):
        x, z = left
        y, w = right
        a, b = self.mul(x, w), self.mul(y, z)
        nz = self.square(a ^ b)
        return (self.mul(a, b) ^ self.mul(difference_x, nz), nz)

    def ladder(self, base_x, scalar):
        assert 0 <= scalar < (1 << 128)
        r0, r1 = (1, 0), (base_x, 1)
        for bit in range(127, -1, -1):
            old0, old1 = r0, r1
            if (scalar >> bit) & 1:
                r0, r1 = self.add(old0, old1, base_x), self.double(old1)
            else:
                r0, r1 = self.double(old0), self.add(old0, old1, base_x)
        return self.mul(r0[0], self.inverse(r0[1]))


def load_original_rom(path):
    raw = path.read_bytes()
    rom_identity = identity(path, raw)
    if len(raw) != ROM_BYTES or rom_identity['sha256'] != ROM_SHA:
        raise ValueError('ROM identity does not match the retained original MCU sample')
    constants = {}
    for name, (address, length, expected_hex) in SPECS.items():
        data = raw[address-ROM_BASE:address-ROM_BASE+length]
        if data.hex() != expected_hex:
            raise ValueError(f'original ROM constant mismatch: {name}')
        constants[name] = {'address': f'{address:08x}', 'bytes': length,
                           'little_endian_hex': data.hex()}
    return rom_identity, constants


def parse_public_auth_tx(raw):
    if len(raw) != 21:
        raise ValueError('authentication TX must be exactly 21 bytes; preamble is separate')
    if raw[:3] != bytes.fromhex('020111'):
        raise ValueError('public TX header does not match the original 02/01/11 request')
    check = 0
    for byte in raw[:20]:
        check ^= byte
    if check != raw[20]:
        raise ValueError('authentication TX XOR mismatch')
    return {'raw_21_bytes': raw.hex(), 'header': raw[:3].hex(),
            'C_17_bytes': raw[3:20].hex(), 'checksum': f'{raw[20]:02x}',
            'XOR_valid': True, 'private_nonce_or_H_provided': False}


def candidate_public_key_matches(constants, scalar):
    """Return only a public-key match; does not derive H or establish origin."""
    if not 0 < scalar < (1 << 128):
        raise ValueError('candidate scalar must be nonzero and fit the original 128-bit ladder')
    value = lambda name: int.from_bytes(bytes.fromhex(constants[name]['little_endian_hex']), 'little')
    field = OriginalField(value('modulus'), value('sqrt_b'))
    return field.ladder(value('G_x'), scalar) == value('P_x')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rom', type=Path, required=True)
    parser.add_argument('--tx-hex', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists; retain the existing evidence')
    try:
        raw_tx = bytes.fromhex(args.tx_hex)
        tx = parse_public_auth_tx(raw_tx)
        before, constants = load_original_rom(args.rom)
        after = identity(args.rom)
        if before != after:
            raise ValueError('original ROM changed during inspection')
    except ValueError as error:
        parser.error(str(error))
    result = {
        'schema': 'z6ii.stage98-public-battery-auth/1',
        'ROM_before': before, 'ROM_after': after, 'ROM_unchanged': True,
        'constants': constants, 'public_TX': tx,
        'normal_peer_requirement': 'A sourced d with P_x=X([d]G) is required to calculate X([d]C) from the public TX.',
        'sourced_peer_scalar_available': False,
        'field_math_source': {'file': 'verify_usart1_auth_math.py',
            'sha256': '6ae7033f3393368e2b949d183aac0f824f6202327ec63a0c035e8f38bd619871',
            'pure_class_copied': 'OriginalField', 'legacy_main_imported_or_executed': False},
        'scope': {'firmware_executed': False, 'live_guest_accessed': False,
            'retained_SRAM_read': False, 'private_H_or_nonce_used': False,
            'battery_RX_generated': False, 'production_source_modified': False},
        'script': identity(Path(__file__)),
    }
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'output': identity(args.output), 'public_TX_XOR_valid': True,
                     'ROM_unchanged': True, 'battery_RX_generated': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
