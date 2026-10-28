"""Decode the public command 89 frame and reconstruct its ROM-defined fields.

Reconstruction is an offline evidence check. It neither sends a frame nor
decides whether the battery peer should acknowledge it. The peer still requires
an identity-bound, complete-byte transaction allowlist.
"""
import struct


CONFIG_BASE = 0x2001F438
INFO_BASE = 0x2001F4A0
INFO_BYTES = 72
AUX_BASE = 0x2000ED99
BODY_BASE = 0x2001FB40
BUILDERS = (0x080243DC, 0x080246C4)
ROM_WINDOWS = (
    (0x0802F160, 16, 'ROM_guard'),
    (0x08023824, 0x118, 'common_transaction'),
    (0x080243DC, 0x13C, 'cmd89_builder_a'),
    (0x080246C4, 0x128, 'cmd89_builder_b'),
)


def xor_bytes(data):
    value = 0
    for byte in data:
        value ^= byte
    return value


def parse_cmd89(frame):
    if len(frame) != 18 or frame[:3] != b'\x02\x89\x0e' or xor_bytes(frame):
        raise ValueError('command 89 requires 18 complete bytes and a valid XOR')
    return dict(frame_hex=frame.hex(), command='0x89', payload_bytes=14,
                config_word_a=struct.unpack_from('<H', frame, 3)[0],
                config_word_b=struct.unpack_from('<H', frame, 5)[0],
                config_code=frame[7], config_six_bytes=frame[8:14].hex(),
                auxiliary_bytes_in_wire_order=frame[14:16].hex(),
                mode_code=frame[16], xor_byte=f'{frame[17]:02x}',
                encryption_observed=False,
                physical_meaning_of_config_words='not established')


def reconstruct_cmd89(info72, auxiliary2, mode, builder, readpin_result):
    """Apply the two original builders to explicit immutable scalar inputs."""
    if len(info72) != INFO_BYTES or len(auxiliary2) != 2:
        raise ValueError('need the exact 72-byte config cache and two auxiliary bytes')
    if builder not in BUILDERS or type(mode) is not int or not 0 <= mode <= 255:
        raise ValueError('unknown original builder or invalid body mode')
    if readpin_result not in (0, 1):
        raise ValueError('READPIN branch must be an explicitly selected 0 or 1')

    def get(offset, size=1):
        index = CONFIG_BASE + offset - INFO_BASE
        if not 0 <= index <= INFO_BYTES - size:
            raise ValueError('field outside the saved group4 config cache')
        return int.from_bytes(info72[index:index + size], 'little')

    word_offsets = (0x7C, 0x80) if readpin_result == 0 else (0x7E, 0x82)
    a, b = (min(get(offset, 2), 999) for offset in word_offsets)
    code = get(0x71)
    if not 1 <= code <= 8:
        code = 8
    if builder == BUILDERS[0]:
        mode_rules = {0: (0x72, 3), 1: (0x73, 1), 2: (0x73, 1),
                      3: (0x73, 1), 4: (0x8E, 3)}
    else:
        mode_rules = {0: (0x8F, 1), 1: (0x90, 3), 2: (0x90, 3),
                      3: (0x90, 3), 4: (0x91, 1)}
    selected = mode_rules.get(mode)
    mode_code = 0
    if selected:
        mode_code = get(selected[0])
        if not 1 <= mode_code <= 6:
            mode_code = selected[1]
    frame = b'\x02\x89\x0e' + struct.pack('<HHB', a, b, code)
    frame += bytes(get(offset) for offset in range(0x74, 0x7A))
    frame += auxiliary2[::-1] + bytes([mode_code])
    frame += bytes([xor_bytes(frame)])
    return dict(builder=f'0x{builder:08X}', readpin_result=readpin_result,
                readpin_is_observed=False, body_mode=mode,
                word_source_addresses=[f'0x{CONFIG_BASE + o:08X}' for o in word_offsets],
                mode_source_address=f'0x{CONFIG_BASE + selected[0]:08X}' if selected else None,
                scope='reconstruction from explicit inputs; not a physical UART capture',
                **parse_cmd89(frame))
