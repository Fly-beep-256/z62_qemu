"""Observe battery refresh after the original nonzero group4 copy completes.

Only original ROM breakpoints and public SRAM control/configuration fields are
used. Authentication nonce, H and response buffers are outside this observer.
No refresh, queue message, callback, builder or reply is supplied to the guest.
"""
import hashlib

from ex1850_battery_config import ROM_BASE, ROM_SHA256, RAM_BASE, RAM_BYTES


MAX_HITS = 32
CONTROL_BASE = 0x2001F688
BODY_BASE = 0x2001FB40
CLASSIFICATION_INPUT = 0x2001F734
CLASSIFICATION_ENTRY = 0x080277C0
CLASSIFICATION_STORES = {0x080277F0: ('R1', 0), 0x080277F4: ('R2', 3),
                         0x080277F8: ('R3', 1)}
POINTS = {
    0x08023B2E: 'original battery initial update sequence entry',
    0x08023CEC: 'original battery compound update sequence entry',
    0x08023DF4: 'original battery state-2 update dispatch entry',
    0x08023AC0: 'original battery power-state guard entry',
    0x08023C54: 'original battery read/status refresh entry',
    0x08024078: 'original battery auxiliary-parameter update entry',
    0x080243DC: 'original cmd89 builder A entry',
    0x080246C4: 'original cmd89 builder B entry',
    0x08024B58: 'original battery comparison refresh guard entry',
    0x0802AA30: 'original main battery polling entry',
    0x0802ABE8: 'original main battery conditional refresh entry',
    0x0802AC50: 'original second battery conditional refresh entry',
    0x08023D32: 'original compound update read return',
    0x08023D44: 'original compound update parsed-status return',
    0x08023D7E: 'original compound update first status return',
    0x08023D9E: 'original compound update cmd89 return',
    0x08024198: 'original battery status transaction entry',
    0x08024242: 'original battery query transaction entry',
    0x08024308: 'original battery query parser entry',
    0x08024620: 'original alternate battery query parser entry',
    0x08024AC0: 'original battery transport error classification entry',
    0x08024B10: 'original transport error -1 store (class 1)',
    0x08024B18: 'original transport error store completed (class 1)',
    0x08024B26: 'original transport error -1 store (class 2)',
    0x08024B2E: 'original transport error store completed (class 2)',
    0x08024B3C: 'original transport error -1 store (class 3)',
    0x08024B46: 'original transport error store completed (class 3)',
    CLASSIFICATION_ENTRY: 'original battery global classification entry',
    0x080277F0: 'original battery classification-0 store',
    0x080277F4: 'original battery classification-3 store',
    0x080277F8: 'original battery classification-1 store',
}
PAIRED_RETURNS = {0x08023AC0, 0x08024B58, 0x0802AA30, 0x0802ABE8,
                  CLASSIFICATION_ENTRY, 0x08023B2E, 0x08023CEC, 0x08023DF4,
                  0x08023C54, 0x08024198, 0x08024242, 0x08024308, 0x08024620}
R1_BODY = {0x08023CEC, 0x08023DF4, 0x08023C54, 0x08024B58, 0x08024AC0}
R2_BODY = {0x08023B2E}
R0_BODY = {0x08023AC0, 0x08024078, 0x080243DC, 0x080246C4, 0x0802AA30,
           0x08024198, 0x08024242}


def classification_from_globals(status, body_state):
    """Recompute the fixed-ROM comparisons; this alone is not execution."""
    if len(status) != 8 or type(body_state) is not int or not 0 <= body_state <= 255:
        raise ValueError('classification requires eight global bytes and one body-state byte')
    if status[0] == 1 or status[4] == 1:
        return 3
    if status[4] in (2, 3) or body_state == 2:
        return 1
    return 3 if body_state == 5 else 0


class TaskObserver:
    def __init__(self, rom):
        if hashlib.sha256(rom).hexdigest() != ROM_SHA256:
            raise ValueError('battery task trace requires the selected original MCU ROM')
        if (int.from_bytes(rom[0x24B80:0x24B84], 'little') != 0x20023008 or
                int.from_bytes(rom[0x23AF4:0x23AF8], 'little') != 0x2001F440 or
                int.from_bytes(rom[0x2AC48:0x2AC4C], 'little') != CONTROL_BASE or
                int.from_bytes(rom[0x2AC4C:0x2AC50], 'little') != BODY_BASE or
                int.from_bytes(rom[0x277FC:0x27800], 'little') != CLASSIFICATION_INPUT):
            raise ValueError('original battery refresh literals changed')
        self.rom_bytes = len(rom)
        self.activation = None
        self.pending = {}
        self.events = []

    def activate(self, events):
        if self.activation is not None:
            return False
        for event in events:
            if (event['phase'] == 'copy_completed' and
                    event.get('stack_and_return_pair_match') is True and
                    any(bytes.fromhex(event['info72_hex']))):
                self.activation = dict(config_copy_sequence=event['observation_sequence'],
                    HAL_tick=event['HAL_tick'], host_elapsed_seconds=event['host_elapsed_seconds'],
                    info72_sha256=hashlib.sha256(bytes.fromhex(event['info72_hex'])).hexdigest(),
                    trigger='actual original nonzero group4 copy completion', guest_state_written=False)
                return True
        return False

    @staticmethod
    def read(remote, pointer, size):
        if not RAM_BASE <= pointer <= RAM_BASE + RAM_BYTES - size:
            return None
        data = remote.memory(pointer, size)
        if len(data) != size:
            raise ValueError('incomplete passive battery task SRAM read')
        return data.hex()

    def return_points(self):
        return {address for address, stack in self.pending}

    def on_stop(self, remote, address, registers, observation):
        stack = int(registers['r13'], 16)
        caller = int(registers['r14'], 16)
        key = (address, stack)
        pending = self.pending.get(key, [])
        if self.activation is None or (address not in POINTS and not pending):
            return []
        control = bytes.fromhex(self.read(remote, CONTROL_BASE, 0x60))
        body = bytes.fromhex(self.read(remote, BODY_BASE, 64))
        comparison = int.from_bytes(bytes.fromhex(self.read(remote, 0x20023008, 2)), 'little')
        voltage = int.from_bytes(control[0x34:0x36], 'little')
        tag = int.from_bytes(body[0x26:0x28], 'little')
        base = dict(schema='original-battery-task-event/1', entry=hex(address),
            observation_sequence=observation['observation_sequence'],
            host_elapsed_seconds=observation['host_elapsed_seconds'],
            HAL_tick=observation['HAL_tick'], stack_address=hex(stack),
            caller_return_register=hex(caller), original_ROM_bytes=observation['original_ROM_bytes'],
            control96_hex=control.hex(), main_body64_hex=body.hex(),
            info72_hex=self.read(remote, 0x2001F4A0, 72),
            auxiliary2_hex=self.read(remote, 0x2000ED99, 2),
            power_guard_byte=self.read(remote, 0x2001F444, 1),
            main_control_ushort_34=voltage, main_body_state=body[0x29],
            main_body_ready=body[0],
            main_body_error=int.from_bytes(body[0x14:0x18], 'little', signed=True),
            main_body_mode=body[0x2e],
            main_body_tag_26=tag, comparison_global_u16=comparison,
            raw_voltage_gate=(voltage > 0x2133 and body[0x29] in (2, 9) or
                              voltage < 0x2134 and body[0x29] == 5),
            raw_tag_difference_before_read_refresh=tag != comparison,
            guest_state_written=False, peripheral_MMIO_read_by_debugger=False,
            activation_config_copy_sequence=self.activation['config_copy_sequence'],
            scope='Passive post-configuration task entry/return; raw conditions are not branch execution')
        events = []
        def classification_fields():
            # This routine has no input-pointer ABI: its ROM literal selects
            # global SRAM. Retain only at its own entry/store/paired return so
            # existing event schemas remain reproducible from older RSP logs.
            return dict(classification_input_address=hex(CLASSIFICATION_INPUT),
                classification_input8_hex=self.read(remote, CLASSIFICATION_INPUT, 8),
                classification_byte=control[0x14])

        if pending:
            previous = pending.pop()
            if not pending:
                del self.pending[key]
            returned = dict(**base, phase='return', entry_sequence=previous['observation_sequence'],
                function_entry=previous['entry'], expected_return_address=hex(address),
                stack_and_return_pair_match=True, original_return_R0=registers['r0'])
            if int(previous['entry'], 16) == CLASSIFICATION_ENTRY:
                returned.update(classification_fields())
            events.append(returned)
        if address in POINTS:
            pointer = (int(registers['r1'], 16) if address in R1_BODY else
                       int(registers['r2'], 16) if address in R2_BODY else
                       int(registers['r0'], 16) if address in R0_BODY else None)
            event = dict(**base, phase='entry' if address in R0_BODY | R1_BODY | R2_BODY | PAIRED_RETURNS else 'instruction',
                argument_body_pointer=hex(pointer) if pointer is not None else None,
                argument_body64_hex=self.read(remote, pointer, 64) if pointer is not None else None,
                R0=registers['r0'], R1=registers['r1'], R2=registers['r2'], R3=registers['r3'])
            if address == CLASSIFICATION_ENTRY or address in CLASSIFICATION_STORES:
                event.update(classification_fields())
            if address in PAIRED_RETURNS:
                destination = caller & ~1
                valid = bool(caller & 1 and ROM_BASE <= destination < ROM_BASE + self.rom_bytes)
                event.update(expected_return_address=hex(destination),
                             return_point_is_original_Thumb_ROM=valid)
                if valid:
                    self.pending.setdefault((destination, stack), []).append(event)
            events.append(event)
        self.events.extend(events)
        return events

    def completion(self):
        return dict(activation=self.activation, observed_events=len(self.events),
            unmatched_return_entries=sum(len(v) for v in self.pending.values()),
            pending_return_points=[hex(p) for p in sorted(self.return_points())],
            guest_state_written=False, peripheral_MMIO_read_by_debugger=False,
            scope='At most32 stops per entry after the original nonzero config copy; unfinished calls remain unverified')
