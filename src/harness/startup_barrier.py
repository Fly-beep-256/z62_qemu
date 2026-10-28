"""Run-local host barrier for the initial recorded-resource RAM replay only.

Each existing endpoint owner supplies its own QMP stopped-state observation.
The coordinator publishes one release; it never opens a debugger connection
or supplies a guest readiness message. Runtime virtual clocks remain separate.
"""
import json
import os
from pathlib import Path
import time
import uuid

SCHEMA = 'z6ii.initial-resource-replay-barrier/1'
ROLES = ('master', 'slave', 'MCU')


def _write_once(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.pending-' + str(os.getpid()))
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        # A hard link publishes a complete file atomically and rejects duplicates.
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read(path):
    path = Path(path)
    if path.stat().st_size > 16384:
        raise ValueError('Initial startup barrier record exceeds 16 KiB')
    return json.loads(path.read_text())


def create(directory, timeout_seconds):
    if not 1 <= timeout_seconds <= 180:
        raise ValueError('Initial startup barrier requires a 1..180s timeout')
    directory = Path(directory)
    directory.mkdir(exist_ok=False)
    state = dict(schema=SCHEMA, token=uuid.uuid4().hex,
        deadline_monotonic=time.monotonic() + timeout_seconds,
        timeout_seconds=timeout_seconds, roles=list(ROLES),
        scope='initial recorded-resource RAM replay only',
        runtime_virtual_clocks_synchronized=False, guest_ready_flag_written=False)
    _write_once(directory / 'configuration.json', state)
    return state


def configuration(directory):
    state = _read(Path(directory) / 'configuration.json')
    if (state.get('schema') != SCHEMA or state.get('roles') != list(ROLES) or
            not isinstance(state.get('token'), str) or len(state['token']) != 32 or
            type(state.get('deadline_monotonic')) not in (float, int)):
        raise ValueError('Initial startup barrier configuration mismatch')
    return state


def _stopped(status):
    if not isinstance(status, dict) or status.get('running') is not False:
        raise ValueError('Initial startup barrier requires actual QMP running=false')
    return status


def ready(directory, role, status, qemu_pid, verification):
    if role not in ROLES or type(qemu_pid) is not int or qemu_pid <= 0:
        raise ValueError('Initial startup barrier role or QEMU PID invalid')
    state = configuration(directory)
    value = dict(schema=SCHEMA, token=state['token'], role=role,
        owner_pid=os.getpid(), QEMU_pid=qemu_pid, QMP_status=_stopped(status),
        verification=verification, observed_monotonic=time.monotonic())
    if role == 'master' and (verification.get('resource_readback_equal') is not True or
            verification.get('original_CPU_state_unchanged') is not True):
        raise ValueError('Master resources and original CPU must be verified before release')
    if role == 'MCU' and (verification.get('reset_SP_PC_verified') is not True or
            verification.get('original_ROM_verified') is not True):
        raise ValueError('MCU reset and original ROM must be verified before release')
    _write_once(Path(directory) / (role + '-ready.json'), value)
    return value


def check_wait(directory, processes):
    state = configuration(directory)
    failed = Path(directory) / 'failure.json'
    if failed.exists():
        raise RuntimeError('Initial startup barrier failed: ' + str(_read(failed).get('reason')))
    if time.monotonic() >= state['deadline_monotonic']:
        raise TimeoutError('Initial resource replay startup barrier expired')
    for process in processes:
        if process.poll() is not None:
            raise RuntimeError('Initial startup barrier endpoint exited before release')
    return state


def release(directory, processes):
    state = check_wait(directory, processes)
    observations = {}
    for role in ROLES:
        path = Path(directory) / (role + '-ready.json')
        if not path.exists():
            return None
        value = _read(path)
        if (value.get('schema') != SCHEMA or value.get('token') != state['token'] or
                value.get('role') != role):
            raise ValueError('Initial startup barrier readiness identity mismatch')
        _stopped(value.get('QMP_status'))
        for pid_key in ('owner_pid', 'QEMU_pid'):
            pid = value.get(pid_key)
            if type(pid) is not int or pid <= 0:
                raise ValueError('Initial startup barrier process identity invalid')
            os.kill(pid, 0)
        observations[role] = value
    value = dict(schema=SCHEMA, token=state['token'], ready=observations,
        released_monotonic=time.monotonic(), runtime_virtual_clocks_synchronized=False,
        guest_ready_flag_written=False, original_firmware_message_supplied=False)
    _write_once(Path(directory) / 'release.json', value)
    return value


def wait_release(directory, processes):
    while True:
        state = check_wait(directory, processes)
        path = Path(directory) / 'release.json'
        if path.exists():
            value = _read(path)
            if (value.get('schema') != SCHEMA or value.get('token') != state['token'] or
                    set(value.get('ready', {})) != set(ROLES)):
                raise ValueError('Initial startup barrier release identity mismatch')
            return value
        time.sleep(0.02)


def fail(directory, error):
    state = configuration(directory)
    try:
        _write_once(Path(directory) / 'failure.json', dict(schema=SCHEMA,
            token=state['token'], reason=type(error).__name__ + ': ' + str(error),
            failed_monotonic=time.monotonic(), released=False))
    except FileExistsError:
        pass
