"""One explicit, source-bound MCU external-power configuration experiment.

Only F734[0] is overridden, once, at its unchanged native caller. This is an
auxiliary boot input; neither battery authentication nor natural boot evidence.
All other battery fields are produced by the original MCU instructions.
"""
from pathlib import Path
import hashlib
import json
import time

BASE = 0x08000000
ROM_SHA = '4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1'
ENTRY, CALLER, RETURN = 0x0802AA30, 0x0802A94A, 0x0802A94E
CONFIG, BODY = 0x2001F734, 0x2001FB40
POINTS = {ENTRY: 'explicit auxiliary configuration at original external-power producer',
          RETURN: 'original external-power producer return; no field repair'}
CONTRACT = dict(entry=hex(ENTRY), entry_bytes='2de9fc41', caller=hex(CALLER),
    caller_bytes='00f071f8', caller_LR='0x0802a94f', return_PC=hex(RETURN),
    return_bytes='7068', argument_R0=hex(BODY), address=hex(CONFIG),
    before_byte='00', after_byte='01', write_command='M2001f734,1:01',
    maximum_write_commands=1)


def identity(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


class AuxiliaryPower:
    def __init__(self, spec_path, source, directory):
        self.spec_path = Path(spec_path).resolve(strict=True)
        self.spec = json.loads(self.spec_path.read_text())
        if self.spec.get('schema') != 'z6ii.MCU-auxiliary-external-power-spec/1':
            raise ValueError('Unknown auxiliary power specification')
        if self.spec.get('contract') != CONTRACT:
            raise ValueError('Auxiliary power contract cannot change its one-byte extent or native caller')
        if (len(source) != 524288 or hashlib.sha256(source).hexdigest() != ROM_SHA or
                self.spec.get('ROM_SHA256') != ROM_SHA or
                self.spec.get('input_classification') != 'synthetic auxiliary configuration override'):
            raise ValueError('Auxiliary power input must bind the exact MCU ROM and synthetic classification')
        for address, expected in ((ENTRY, '2de9fc41'), (CALLER, '00f071f8'), (RETURN, '7068')):
            if source[address - BASE:address - BASE + len(bytes.fromhex(expected))].hex() != expected:
                raise ValueError('Original auxiliary producer bytes mismatch')
        for item in self.spec['source_evidence']:
            if identity(item['path']) != item:
                raise ValueError('Auxiliary producer source evidence changed')
        self.directory = Path(directory) / 'auxiliary-power'
        self.directory.mkdir(exist_ok=False)
        self.record = dict(schema='z6ii.MCU-auxiliary-external-power-run/1',
            input_classification=self.spec['input_classification'],
            specification=identity(self.spec_path), helper=identity(__file__),
            source_evidence=self.spec['source_evidence'], contract=CONTRACT,
            requested=True, state='prepared', write_commands_issued=0,
            actual_guest_state_write_count=0, actual_guest_bytes_written=0,
            actions=[], checkpoints=[], native_producer_verified=False,
            natural_battery_authentication_verified=False, full_natural_boot_verified=False,
            firmware_instruction_patches=False, battery_reply_supplied=False,
            ready_or_initialized_field_written=False, register_or_PC_written=False)
        self._checkpoint('prepared')

    def _checkpoint(self, state, **fields):
        self.record.update(state=state, **fields)
        path = self.directory / f'{len(self.record["checkpoints"]) + 1:02d}-{state}.json'
        save(path, dict(self.record, host_monotonic_ns=time.monotonic_ns()))
        event = dict(state=state, evidence=identity(path))
        self.record['checkpoints'].append(event)
        save(self.directory / '辅助供电结果.json', self.record)
        return event

    @staticmethod
    def _raw_registers(remote):
        raw = remote.command('g')
        data = bytes.fromhex(raw)
        if len(data) not in (68, 168):
            raise ValueError('Unrecognized ARM register packet')
        return raw, {f'r{i}': int.from_bytes(data[i * 4:i * 4 + 4], 'little') for i in range(16)}

    def on_stop(self, remote, address, registers):
        if address not in POINTS:
            return None
        try:
            if address == ENTRY:
                if self.record['state'] != 'prepared' or self.record['write_commands_issued'] != 0:
                    raise ValueError('Auxiliary configuration is strictly one-shot')
                raw_g, actual = self._raw_registers(remote)
                if (actual['r15'] != ENTRY or actual['r0'] != BODY or
                        actual['r14'] != CALLER + 5 or
                        any(actual[key] != int(registers[key], 16) for key in actual)):
                    raise ValueError('Original producer PC/R0/LR or stopped registers mismatch')
                original = dict(entry=remote.memory(ENTRY, 4).hex(),
                    caller=remote.memory(CALLER, 4).hex(), return_PC=remote.memory(RETURN, 2).hex())
                if original != dict(entry='2de9fc41', caller='00f071f8', return_PC='7068'):
                    raise ValueError('In-memory original producer/caller bytes mismatch')
                config = remote.memory(CONFIG, 5)
                body = remote.memory(BODY, 64)
                if config[0] != 0:
                    raise ValueError('Original auxiliary configuration must be zero before this experiment')
                preflight = dict(PC=hex(actual['r15']), R0=hex(actual['r0']),
                    LR=hex(actual['r14']), original_ROM=original, raw_register_packet=raw_g,
                    config_address=hex(CONFIG), config_hex=config.hex(),
                    body_address=hex(BODY), body_hex=body.hex())
                self._checkpoint('preflight', preflight=preflight)
                action = dict(command=CONTRACT['write_command'], address=hex(CONFIG), bytes=1,
                    old_byte='00', new_byte='01',
                    classification='synthetic auxiliary configuration override',
                    response=None, immediate_readback_verified=False)
                self.record['actions'].append(action)
                self._checkpoint('write-issued', write_commands_issued=1)
                response = remote.command(CONTRACT['write_command'])
                action['response'] = response
                if response != 'OK':
                    raise ValueError('Auxiliary single-byte command did not return OK')
                self.record.update(actual_guest_state_write_count=1, actual_guest_bytes_written=1)
                after_config = remote.memory(CONFIG, 5)
                after_body = remote.memory(BODY, 64)
                after_g, after_regs = self._raw_registers(remote)
                if (after_config != b'\x01' + config[1:] or after_body != body or after_g != raw_g):
                    raise ValueError('Auxiliary command changed an undeclared byte or register')
                action['immediate_readback_verified'] = True
                return self._checkpoint('applied', immediate_after=dict(config_hex=after_config.hex(),
                    body_hex=after_body.hex(), raw_register_packet=after_g,
                    body_unchanged=True, registers_unchanged=True, one_byte_extent_verified=True))
            if self.record['state'] != 'applied':
                raise ValueError('Native return observed without its verified one-shot auxiliary input')
            config = remote.memory(CONFIG, 5)
            body = remote.memory(BODY, 64)
            decoded = dict(body_first_byte=body[0], external_power_active=int.from_bytes(body[4:8], 'little'),
                millivolts=int.from_bytes(body[0x18:0x1a], 'little'),
                field28=body[0x28], battery_type=body[0x29], field2A=body[0x2a],
                status=body[0x2c], config_mode=config[0])
            original_body = bytes.fromhex(self.record['preflight']['body_hex'])
            if (int(registers['r15'], 16) != RETURN or remote.memory(RETURN, 2).hex() != '7068' or
                    decoded != dict(body_first_byte=original_body[0], external_power_active=1,
                        millivolts=9000, field28=0, battery_type=5, field2A=0, status=0, config_mode=1)):
                raise ValueError('Original 0802402E external-power producer output mismatch')
            return self._checkpoint('native-producer-verified', native_producer_verified=True,
                native_return=dict(PC=hex(RETURN), registers=registers,
                    config_hex=config.hex(), body_hex=body.hex(), decoded=decoded,
                    writer='unchanged 0802AA58..0802AA60 -> 0802402E',
                    ready_or_initialized_field_written_by_host=False))
        except Exception as error:
            self._checkpoint('failed', failure=type(error).__name__ + ': ' + str(error))
            raise

    def finish(self):
        if self.record['state'] == 'prepared':
            self._checkpoint('entry-not-reached')
        elif self.record['state'] == 'applied':
            self._checkpoint('native-return-not-reached')
        return self.record

