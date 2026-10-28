"""Compile immutable external battery contracts before native guest execution.

The in-process QEMU endpoint receives completed UART TX bytes only. All field
math runs here against declared public entropy and identity-checked sources.
The 2ms turnaround is an explicit unmeasured virtual-time input hypothesis.
"""
import json
from pathlib import Path

from ex1850_battery_peer import BatteryProtocol, INPUT_KIND, file_identity, load_spec
from ex1850_usart1_peer import xor_bytes


SCHEMA = 'ex1850.virtual-battery-contracts/1'
TURNAROUND_NS = 2_000_000


def compile_contracts(specification, public_words, max_replies):
    spec, constants = load_spec(specification)
    if list(public_words) != spec['public_entropy']['words']:
        raise ValueError('MCU RNG words differ from the declared battery input')
    if type(max_replies) is not int or not 1 <= max_replies <= 8192:
        raise ValueError('Battery reply budget must be 1..8192')
    protocol = BatteryProtocol(spec, constants)
    contracts = []
    for challenge in protocol.challenges:
        prefix = b'\x02\x01\x11' + challenge
        tx = prefix + bytes([xor_bytes(prefix)])
        rx = protocol.reply(tx)
        contracts.append(dict(TX=tx.hex(), RX=rx.hex(), authentication=True,
            allowed_before_authentication=True, fields=dict(protocol.last_fields)))
    for transaction in spec['exact_transactions']:
        tx = bytes.fromhex(transaction['TX'])
        rx = protocol.reply(tx)
        contracts.append(dict(TX=tx.hex(), RX=rx.hex(), authentication=False,
            allowed_before_authentication=transaction.get('allowed_before_authentication', False),
            fields=dict(protocol.last_fields)))
    if not 1 <= len(contracts) <= 128 or len({c['TX'] for c in contracts}) != len(contracts):
        raise ValueError('Immutable battery contracts must be bounded and unique')
    if any(not 4 <= len(bytes.fromhex(c['RX'])) <= 68 for c in contracts):
        raise ValueError('Battery reply is outside the declared wire frame limit')
    return dict(schema=SCHEMA, specification=file_identity(specification),
        mode='public-entropy-battery', input_kind=INPUT_KIND,
        public_entropy=spec['public_entropy'], max_replies=max_replies,
        turnaround_ns=TURNAROUND_NS, clock='QEMU_CLOCK_VIRTUAL',
        turnaround_classification='unmeasured external battery input hypothesis',
        immutable_inputs_compiled_before_guest_start=True,
        physical_turnaround_verified=False, physical_battery_private_key_recovered=False,
        runtime_input='completed UART TX byte and virtual wire timestamp only',
        MCU_reset_does_not_reset_external_battery=True, contracts=contracts)


class VirtualBatteryPeer:
    """Run-local configuration and evidence reader; no socket or guest interface."""
    def __init__(self, directory, specification, public_words, max_replies=4096):
        self.directory = Path(directory)
        table = compile_contracts(specification, public_words, max_replies)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.table_path = self.directory / 'wire-contracts.json'
        with self.table_path.open('x') as stream:
            stream.write(json.dumps(table, ensure_ascii=False, indent=2) + '\n')
        self.table_identity = file_identity(self.table_path)
        self.specification = file_identity(specification)

    @property
    def environment(self):
        return dict(EX1850_BATTERY_WIRE_SPEC=str(self.table_path.resolve()),
            EX1850_BATTERY_WIRE_SHA256=self.table_identity['sha256'],
            EX1850_BATTERY_WIRE_OUTPUT=str(self.directory.resolve()))

    def wait_connected(self):
        # QEMU synchronously opens this endpoint during board initialization,
        # before its -S stopped architecture snapshot is available.
        opened = json.loads((self.directory / 'wire-opened.json').read_text())
        if opened.get('enabled') is not True or opened.get('clock') != 'QEMU_CLOCK_VIRTUAL':
            raise ValueError('Native virtual battery endpoint did not initialize')
        if opened.get('contract_sha256') != self.table_identity['sha256']:
            raise ValueError('QEMU loaded a different battery contract table')

    def finish(self):
        if file_identity(self.table_path) != self.table_identity:
            raise ValueError('Run-local battery contracts changed after launch')
        raw_path = self.directory / 'wire-closed.json'
        result = json.loads(raw_path.read_text())
        if result.get('endpoint_closed') is not True:
            raise ValueError('QEMU virtual battery endpoint lacks a completed closure')
        if result.get('contract_sha256') != self.table_identity['sha256']:
            raise ValueError('Closed endpoint contract identity mismatch')
        result.update(schema='ex1850.public-entropy-battery-wire-input/1',
            specification=self.specification, compiled_contracts=self.table_identity,
            endpoint_raw_closure=file_identity(raw_path),
            events_evidence=file_identity(self.directory / 'wire-events.jsonl'),
            host_worker_created=False, connection_kind='in-process declared virtual battery wire',
            original_battery_capture=False, physical_battery_private_key_recovered=False,
            private_RAM_RNG_or_register_access=False, guest_RAM_or_register_writes=False,
            captured_battery_parameters_used=True,
            response_is_function_of_public_TX_only=False,
            response_is_function_of_public_TX_and_declared_external_inputs_only=True,
            physical_turnaround_or_guest_clock_ordering_verified=False,
            actual_native_power_or_acquisition_success_observed=False,
            authentication_success_scope='Wire credential supplied; unchanged MCU result and power publication require separate run evidence',
            streams={key: file_identity(self.directory / name) for key, name in
                [('public_TX', 'UART1-TX.bin'), ('synthetic_RX', 'UART1-RX.bin')]})
        for key, stream in [('public_TX_bytes', 'public_TX'), ('synthetic_RX_bytes', 'synthetic_RX')]:
            if result[key] != result['streams'][stream]['bytes']:
                raise ValueError('QEMU wire byte counter differs from retained stream: ' + key)
        target = self.directory / 'closed.json'
        with target.open('x') as stream:
            stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        return result
