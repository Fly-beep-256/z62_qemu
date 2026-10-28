"""Bind a frame-external NUL to retained original MCU send observations.

This checks an existing log and wire stream. It does not infer a physical
battery protocol meaning or accept unknown bytes through resynchronization.
"""
from collections import defaultdict


TOKENS = ('EX1850_USART1_RESET', 'EX1850_USART1_SEND_SETUP',
          'EX1850_USART1_ZERO_DR', 'EX1850_USART1_ZERO_TX')
RAM_BASE, RAM_END = 0x20000000, 0x20040000
HANDLE, TX_BASE, USART = 0x2001F518, 0x2001F558, 0x40011000


def load_uart_source_log(mcu, checked, ref):
    path = checked(mcu['QEMU_log'])
    events, seen = defaultdict(list), set()
    for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
        words = line.split()
        if not words or words[0] not in TOKENS or line in seen:
            continue
        seen.add(line)  # The bounded fault context can repeat an identical line.
        fields = dict(word.split('=', 1) for word in words[1:] if '=' in word)
        fields['log_line'] = number
        events[words[0]].append(fields)
    return dict(events), dict(log=ref(path), identity_verified=True,
        complete_raw_log_retained=False,
        scope='Exact retained observations; absence outside this log is unknown')


def _bl_target(rom, address):
    offset = address - 0x08000000
    raw = rom[offset:offset + 4] if offset >= 0 else b''
    if len(raw) != 4:
        raise ValueError('Original UART caller lies outside its ROM')
    a, b = (int.from_bytes(raw[n:n + 2], 'little') for n in (0, 2))
    if a & 0xF800 != 0xF000 or b & 0xD000 != 0xD000:
        raise ValueError('Original UART caller is not a Thumb BL instruction')
    sign, j1, j2 = (a >> 10) & 1, (b >> 13) & 1, (b >> 11) & 1
    delta = ((sign << 24) | ((1 ^ j1 ^ sign) << 23) | ((1 ^ j2 ^ sign) << 22)
             | ((a & 0x3FF) << 12) | ((b & 0x7FF) << 1))
    if sign:
        delta -= 1 << 25
    return (address + 4 + delta) & 0xFFFFFFFF, raw.hex()


def verify_original_zero(rom, tx, offset, events):
    """Require a reset, HAL setup, SRAM/DR store and completed wire byte."""
    def require(condition, message):
        if not condition:
            raise ValueError('UART zero at byte %d: %s' % (offset, message))

    def number(row, key, base=10):
        return int(row[key], base)

    require(type(offset) is int and 0 <= offset < len(tx) and tx[offset] == 0,
            'wire offset is not an actual NUL')
    complete = [r for r in events.get(TOKENS[3], [])
                if number(r, 'wire_offset') == offset]
    require(len(complete) == 1, 'missing or ambiguous completion observation')
    end = complete[0]
    generation = number(end, 'reset_generation')
    reset = [r for r in events.get(TOKENS[0], []) if number(r, 'generation') == generation]
    require(len(reset) == 1, 'missing or ambiguous reset generation')
    reset = reset[0]
    base = number(reset, 'wire_TX_bytes')
    completed = offset - base + 1
    require(generation > 0 and 0 <= base <= offset and
            reset['source'] == 'MCU_peripheral_reset', 'invalid reset origin')
    require(end['source'] == 'completed_guest_DR_data_frame' and
            number(end, 'word', 16) == 0 and number(end, 'completed') == completed and
            completed <= number(end, 'accepted') <= completed + 1,
            'completion does not match wire/count/source')
    stores = [r for r in events.get(TOKENS[2], [])
              if number(r, 'reset_generation') == generation and
              number(r, 'accepted_after') == completed]
    require(len(stores) == 1, 'missing or ambiguous original DR store')
    store = stores[0]
    require(store['source'] == 'guest_MMIO_write' and
            number(store, 'addr', 16) == USART + 4 and
            number(store, 'value', 16) == 0 and number(store, 'pc', 16) == 0x0804A0D6 and
            number(store, 'lr', 16) == 0x080236A9 and
            number(store, 'r0', 16) == HANDLE and number(store, 'r1', 16) == 0 and
            number(store, 'r2', 16) == USART and
            number(store, 'accepted_before') + 1 == completed and
            number(store, 'wire_TX_bytes') == offset,
            'DR instruction/registers/counters do not match')
    require(rom[0x4A0D6:0x4A0D8] == bytes.fromhex('5160'),
            'original DR instruction differs from supplied ROM')
    handle = bytes.fromhex(store['handle_hex'])
    data = bytes.fromhex(store['tx8_hex'])
    require(len(handle) == 64 and len(data) == 8 and data[:2] == b'\0\0' and
            int.from_bytes(handle[:4], 'little') == USART and
            int.from_bytes(handle[0x20:0x24], 'little') == TX_BASE and
            number(store, 'tx_pointer', 16) == TX_BASE and
            handle[0x24:0x28] == b'\x01\0\x01\0',
            'single-byte HAL SRAM source is missing or inconsistent')
    start_ns, store_ns, end_ns = (number(r, 'virtual_ns') for r in (reset, store, end))
    require(start_ns <= store_ns < end_ns, 'invalid reset/store/completion virtual order')
    setups = [r for r in events.get(TOKENS[1], [])
              if number(r, 'reset_generation') == generation and
              number(r, 'accepted') == completed - 1 and
              number(r, 'wire_TX_bytes') == offset and
              number(r, 'tx_pointer', 16) == TX_BASE and
              start_ns <= number(r, 'virtual_ns') <= store_ns]
    require(len(setups) == 1, 'missing or ambiguous original HAL send setup')
    setup = setups[0]
    require(setup['source'] == 'original_HAL_TXEIE_store' and
            number(setup, 'addr', 16) == USART + 0x0C and
            number(setup, 'pc', 16) == 0x0804677C and number(setup, 'value', 16) & 0x80 and
            number(setup, 'r0', 16) == USART and number(setup, 'handle', 16) == HANDLE and
            number(setup, 'completed') == completed - 1,
            'HAL setup does not match the original TXEIE store')
    require(rom[0x4677C:0x4677E] == bytes.fromhex('c160'),
            'original HAL TXEIE instruction differs from supplied ROM')
    setup_handle = bytes.fromhex(setup['handle_hex'])
    request = bytes.fromhex(setup['tx24_hex'])
    control = bytes.fromhex(setup['control6_hex'])
    stack = bytes.fromhex(setup['stack64_hex'])
    sp, lr = number(setup, 'sp', 16), number(setup, 'lr', 16)
    require(len(setup_handle) == 64 and setup_handle[:4] == handle[:4] and
            setup_handle[0x20:0x28] == handle[0x20:0x28] and
            len(request) == 24 and request[:8] == data and len(control) == 6 and
            len(stack) == 64 and RAM_BASE <= sp <= RAM_END - 64 and sp % 4 == 0,
            'HAL setup SRAM/stack does not match the observed DR source')
    require(lr == 0x080238BD and number(setup, 'r4', 16) == 0x2001F4E8,
            'frame-external zero is not the original transaction first-send path')
    target, instruction = _bl_target(rom, lr - 5)
    require(target == 0x0804674C, 'HAL caller BL does not target the original send routine')
    require(rom[0x23824:0x23828] == bytes.fromhex('2de9f843'),
            'original transaction stack layout differs from supplied ROM')
    upper_lr = int.from_bytes(stack[0x1C:0x20], 'little')
    require(upper_lr & 1, 'transaction saved caller lacks Thumb return state')
    upper_call = upper_lr - 5
    upper_target, upper_instruction = _bl_target(rom, upper_call)
    require(upper_target == 0x08023824, 'saved upstream caller does not call original transaction')
    # The upstream routine initializes one zero byte on its own stack, passes
    # R2=1 (TX length) and R3=0 (expected RX length). The common transaction
    # copies that byte, records both lengths, then asks HAL to send one byte.
    require(upper_call == 0x08024976 and
            rom[0x24964:0x2497A] == bytes.fromhex(
                '10b588b000218df804100b460091012201a9fef755ff'),
            'original upstream single-zero initializer differs from supplied ROM')
    require(rom[0x23838:0x2383A] == bytes.fromhex('1746') and
            rom[0x23850:0x23862] == bytes.fromhex(
                '3a46494604f17000fcf736fe677084f80380') and
            rom[0x238B4:0x238BC] == bytes.fromhex('0122403822f048ff'),
            'original transaction length/copy/first-send instructions differ from supplied ROM')
    require(control[1:6] == b'\x01\0\0\0\0' and request == bytes(24) and
            stack[0x20:0x25] == bytes(5),
            'zero is not sourced from the original single-zero transaction')
    return dict(wire_offset=offset, value=0, source_verified=True,
        status='verified_original_single_zero_transaction_first_send',
        original_send_setup_observed=True, physical_protocol_meaning_verified=False,
        reset_generation=generation, reset_wire_offset=base,
        reset_virtual_ns=start_ns, setup_virtual_ns=number(setup, 'virtual_ns'),
        DR_virtual_ns=store_ns, completion_virtual_ns=end_ns,
        accepted_before=completed - 1, accepted_after=completed,
        completed=completed, DR_PC='0x0804a0d6', DR_instruction='5160',
        HAL_PC='0x0804677c', HAL_instruction='c160',
        HAL_caller_return=hex(lr), HAL_caller_instruction=instruction,
        transaction_entry='0x08023824', transaction_saved_caller_return=hex(upper_lr),
        upstream_call=hex(upper_call), upstream_call_instruction=upper_instruction,
        upstream_entry='0x08024964', TX_length_bytes=1, expected_RX_bytes=0,
        upstream_stack_payload_offset=0x24, original_stack_payload_zero_verified=True,
        handle=hex(HANDLE), TX_pointer=hex(TX_BASE),
        control6_hex=control.hex(), cleared_TX24_hex=request.hex(),
        log_lines={name: row['log_line'] for name, row in (
            ('reset', reset), ('setup', setup), ('DR', store), ('completion', end))})
