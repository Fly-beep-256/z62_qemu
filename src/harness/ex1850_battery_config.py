"""Observe original group4 conversion and config copies without supplying state.

The scalar conversion below is an offline check against the unchanged Thumb
routine. It is never used to populate RAM, generate a peer reply or call guest
code. Unassigned cache bytes retain their observed previous values.
"""
import hashlib


ROM_BASE = 0x08000000
ROM_SHA256 = '4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1'
RAM_BASE = 0x20000000
RAM_BYTES = 0x40000
INFO_BASE = 0x2001F4A0
CACHE_BASE = 0x2001FAF8
GROUP4_BYTES = 0x168
MAX_HITS = 32
POINTS = {
    0x080294F4: 'original group4-to-battery-cache conversion entry',
    0x080298CC: 'original group4 conversion tail branch after register restoration',
    0x08024998: 'original 72-byte battery config copy entry',
}
ROM_WINDOWS = (
    (0x080294F4, 0x3E0, 'group4_conversion_and_cache_literal'),
    (0x08024998, 0x10, 'config_copy_and_destination_literal'),
    (0x08024BB2, 0x1C, 'group4_notification_tail_dispatch'),
    (0x08024C70, 0x50, 'initial_group4_getter_and_conversion'),
)
FIELD_COPIES = (
    *[(i, 0x40 + 4 * i, 1) for i in range(12)],
    (0x0C, 0x70, 4), (0x10, 0x74, 4),
    *[(0x14 + 2 * i, 0x78 + 4 * i, 2) for i in range(4)],
    (0x1C, 0x88, 1), (0x1D, 0x8C, 1), (0x1E, 0x90, 1),
    (0x20, 0x94, 2), (0x22, 0x9C, 1), (0x23, 0xA0, 1), (0x24, 0xA8, 2),
    *[(0x26 + i, 0xB0 + 4 * i, 1) for i in range(10)],
    (0x30, 0x110, 1), (0x32, 0x114, 2), (0x34, 0x120, 2),
    (0x36, 0x124, 2), (0x38, 0x128, 2), (0x3A, 0x12C, 2),
    *[(0x3C + i, 0x130 + 4 * i, 1) for i in range(8)],
    (0x46, 0x15C, 1), (0x44, 0x160, 1), (0x45, 0x164, 1),
)


def convert_group4(group4, previous_cache, correction):
    """Reconstruct 080294F4 from explicit entry bytes, including ARM wraparound."""
    if len(group4) != GROUP4_BYTES or len(previous_cache) != 72:
        raise ValueError('need the complete 0x168-byte group4 input and previous cache72')
    if type(correction) is not int or not 0 <= correction <= 0xFFFFFFFF:
        raise ValueError('correction must be the original unsigned r1 value')
    result = bytearray(previous_cache)
    for destination, source, size in FIELD_COPIES:
        result[destination:destination + size] = group4[source:source + size]
    if not correction:
        return bytes(result)

    def word(offset):
        return int.from_bytes(result[offset:offset + 2], 'little')

    def put_word(offset, value):
        result[offset:offset + 2] = value.to_bytes(2, 'little')

    for offset in range(9):
        result[offset] = min(result[offset], 100)
    result[9] = min(result[9], 8)
    for offset in (0x0A, 0x0B, 0x26, 0x27, 0x28, 0x29):
        if not 1 <= result[offset] <= 6:
            result[offset] = 6
    for offset in (0x14, 0x16, 0x18, 0x1A):
        put_word(offset, min(word(offset), 999))
    if result[0x1C] == 0:
        result[0x1C] = 1
    for offset, upper, default in (
            (0x1D, 99, 15), (0x1E, 99, 4), (0x22, 30, 6),
            (0x2A, 30, 6), (0x2C, 30, 6), (0x2E, 30, 6),
            (0x30, 50, 15), (0x3D, 28, 10), (0x3E, 28, 25),
            *[(o, 28, 0) for o in range(0x3F, 0x44)],
            (0x46, 16, 5), (0x44, 15, 15), (0x45, 15, 10)):
        if result[offset] > upper:
            result[offset] = default
    if word(0x20) > 0x1964:
        put_word(0x20, 0x1612)
    if word(0x24) > 0x1000:
        put_word(0x24, 0)
    if word(0x32) > 0x2328:
        put_word(0x32, 0x1770)
    for offset, lower, span, default in (
            (0x34, 600, 0xDA9, 0x0352), (0x36, 700, 0xD45, 0x03BA),
            (0x38, 600, 0xDA9, 0), (0x3A, 700, 0xD45, 0x0431)):
        if ((word(offset) - lower) & 0xFFFFFFFF) >= span:
            put_word(offset, default)
    return bytes(result)


class ConfigObserver:
    """Pair actual invocations by restored SP and original LR, bounded to32."""

    def __init__(self, rom):
        if hashlib.sha256(rom).hexdigest() != ROM_SHA256:
            raise ValueError('battery config observer requires the selected original MCU ROM')
        if (rom[0x294F4:0x294F8] != bytes.fromhex('2de9f34f') or
                rom[0x298CC:0x298D0] != bytes.fromhex('fbf764b8') or
                int.from_bytes(rom[0x298D0:0x298D4], 'little') != CACHE_BASE or
                int.from_bytes(rom[0x249A4:0x249A8], 'little') != INFO_BASE):
            raise ValueError('original config code/literals do not match the observer')
        self.rom_bytes = len(rom)
        self.initial_rom = bytes(rom)
        self.conversions = {}
        self.converted = {}
        self.copies = {}
        self.events = []

    @staticmethod
    def region(pointer, size):
        if ROM_BASE <= pointer and pointer + size <= ROM_BASE + 0x80000:
            return 'MCU_Flash_mapping'
        if RAM_BASE <= pointer and pointer + size <= RAM_BASE + RAM_BYTES:
            return 'SRAM'
        return 'outside_observed_ROM_and_SRAM'

    def read(self, remote, pointer, size):
        if self.region(pointer, size) == 'outside_observed_ROM_and_SRAM':
            return None
        data = remote.memory(pointer, size)
        if len(data) != size:
            raise ValueError('incomplete passive battery config read')
        return data.hex()

    def return_points(self):
        return {address for address, stack in self.copies}

    def on_stop(self, remote, address, registers, observation):
        stack = int(registers['r13'], 16)
        caller = int(registers['r14'], 16)
        key = (stack, caller)
        pending_key = (address, stack)
        matching_copy = self.copies.get(pending_key, [])
        if address not in POINTS and not matching_copy:
            return []
        base = dict(schema='original-battery-config-event/1', entry=hex(address),
            observation_sequence=observation['observation_sequence'],
            host_elapsed_seconds=observation['host_elapsed_seconds'],
            HAL_tick=observation['HAL_tick'], stack_address=hex(stack),
            caller_return_register=hex(caller),
            info72_hex=self.read(remote, INFO_BASE, 72),
            cache72_hex=self.read(remote, CACHE_BASE, 72),
            auxiliary2_hex=self.read(remote, 0x2000ED99, 2),
            body_mode=int.from_bytes(bytes.fromhex(self.read(remote, 0x2001FB6E, 1)), 'little'),
            group4_pointer_slot_2000e7f0_hex=self.read(remote, 0x2000E7F0, 4),
            original_ROM_bytes=observation['original_ROM_bytes'],
            guest_state_written=False, peripheral_MMIO_read_by_debugger=False,
            scope='Passive stopped original-code event; no cache or callback supplied')
        events = []
        if matching_copy:
            previous = matching_copy.pop()
            if not matching_copy:
                del self.copies[pending_key]
            events.append(dict(**base, phase='copy_completed',
                copy_entry_sequence=previous['observation_sequence'],
                expected_return_address=previous['expected_return_address'],
                stack_and_return_pair_match=True))
        if address == 0x080294F4:
            pointer = int(registers['r0'], 16)
            group4_hex = self.read(remote, pointer, GROUP4_BYTES)
            initial = (self.initial_rom[pointer - ROM_BASE:pointer - ROM_BASE + GROUP4_BYTES]
                       if self.region(pointer, GROUP4_BYTES) == 'MCU_Flash_mapping' else None)
            event = dict(**base, phase='conversion_entry',
                group4_address=hex(pointer), group4_bytes=GROUP4_BYTES,
                group4_region=self.region(pointer, GROUP4_BYTES),
                group4_hex=group4_hex,
                group4_source_sha256=hashlib.sha256(bytes.fromhex(group4_hex)).hexdigest() if group4_hex else None,
                group4_matches_initial_firmware_data=(bytes.fromhex(group4_hex) == initial
                    if group4_hex is not None and initial is not None else None),
                correction_R1=int(registers['r1'], 16))
            self.conversions.setdefault(key, []).append(event)
            events.append(event)
        elif address == 0x080298CC:
            pending = self.conversions.get(key, [])
            previous = pending.pop() if pending else None
            if not pending:
                self.conversions.pop(key, None)
            event = dict(**base, phase='conversion_completed',
                conversion_entry_sequence=previous['observation_sequence'] if previous else None,
                stack_and_return_pair_match=previous is not None,
                output_R0=registers['r0'])
            self.converted[key] = event
            events.append(event)
        elif address == 0x08024998:
            pointer = int(registers['r0'], 16)
            return_address = caller & ~1
            valid_return = bool(caller & 1 and ROM_BASE <= return_address < ROM_BASE + self.rom_bytes)
            previous = self.converted.pop(key, None)
            event = dict(**base, phase='copy_entry', copy_source_address=hex(pointer),
                copy_source_region=self.region(pointer, 72),
                copy_source72_hex=self.read(remote, pointer, 72),
                destination_address=hex(INFO_BASE), copy_bytes=72,
                conversion_completed_sequence=previous['observation_sequence'] if previous else None,
                expected_return_address=hex(return_address),
                return_point_is_original_Thumb_ROM=valid_return)
            if valid_return:
                self.copies.setdefault((return_address, stack), []).append(event)
            events.append(event)
        self.events.extend(events)
        return events
