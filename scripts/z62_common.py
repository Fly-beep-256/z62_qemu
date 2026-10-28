"""Portable package paths, identities and atomic reports; no device access."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import shutil

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / 'runtime/python/bin/python3.12'
HARNESS = ROOT / 'src/harness'

def now():
    return datetime.now(timezone.utc).isoformat()

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def identity(path, base=ROOT):
    path = Path(path).resolve(strict=True)
    try:
        value = str(path.relative_to(base))
    except ValueError:
        value = str(path)
    return dict(path=value, bytes=path.stat().st_size, sha256=digest(path))

def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.writing')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temp.replace(path)

def read(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def profiles():
    return {p.parent.name: read(p) for p in sorted((ROOT / 'profiles').glob('*/profile.json'))}

def clean_environment():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('Z6_', 'Z6II_', 'Z62_', 'EX1850_', 'PYTHON', 'DYLD_'))}
    env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin',
               PYTHONPATH=str(HARNESS) + os.pathsep + str(HARNESS / 'tools'),
               PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1',
               OMP_THREAD_LIMIT='1')
    return env

def expand(value, run, prepare):
    if isinstance(value, str):
        return value.replace('@RUN@/prepare', str(prepare)).replace('@RUN@', str(run))
    if isinstance(value, list):
        return [expand(x, run, prepare) for x in value]
    if isinstance(value, dict):
        return {k: expand(v, run, prepare) for k, v in value.items()}
    return value

def runtime_environment(recipe, run, prepare):
    """Keep recipes relative; resolve model file arguments against this copy."""
    value = expand(recipe, run, prepare)
    for key, item in value.items():
        if isinstance(item, str) and item.startswith(('inputs/', 'runtime/', 'artifacts/', 'src/')):
            value[key] = str((ROOT / item).resolve(strict=True))
    return value

def freeze_native_plans(baseline, prepare, ui_plan=None):
    """Bind final and call-time observations to run-local pre-launch bytes."""
    argv = baseline.get('argv', [])
    if not isinstance(argv, list):
        raise ValueError('Native sampling recipe argv must be a list')
    if ui_plan is not None:
        option = '--ui-observation-plan'
        if option in argv:
            if argv.count(option) != 1 or argv.index(option) + 1 >= len(argv):
                raise ValueError('Native requires one UI plan argument')
            argv[argv.index(option) + 1] = str(ui_plan)
        else:
            argv.extend((option, str(ui_plan)))
    retained = []
    for option in ('--task-observation-plan', '--loader-runtime-reference-spec', '--ui-observation-plan'):
        if argv.count(option) != 1:
            raise ValueError('Native requires one launch-time sampling plan: ' + option)
        index = argv.index(option) + 1
        if index >= len(argv) or not isinstance(argv[index], str) or argv[index].startswith('--'):
            raise ValueError('Native sampling plan has no file argument: ' + option)
        source = Path(argv[index])
        source = (source if source.is_absolute() else ROOT / source).resolve(strict=True)
        source.relative_to(ROOT)
        target = prepare / (option[2:] + '.json')
        shutil.copy2(source, target)
        argv[index] = str(target)
        retained.append(identity(target))
    return retained

def evidence_path(value, envelope, locked):
    """Read retained evidence after a genuine directory copy or move."""
    path = Path(value)
    if not path.is_absolute():
        # identity() records run-local inputs relative to the package root.
        # When the whole envelope is archived, bind those references to this
        # envelope even if the original run is still present elsewhere.
        old_envelope = locked.get('envelope_at_run')
        old_root = locked.get('package_root_at_run')
        if old_envelope and old_root:
            try:
                prefix = Path(old_envelope).relative_to(old_root)
                remainder = path.relative_to(prefix)
            except ValueError:
                pass
            else:
                return envelope / remainder
        if path.parts and path.parts[0] in ('prepare', 'run', 'logs'):
            return envelope / path
        local = envelope / path
        return local if local.exists() else ROOT / path
    for old, replacement in ((locked.get('envelope_at_run'), envelope),
                              (locked.get('package_root_at_run'), ROOT)):
        if old:
            try:
                return replacement / path.relative_to(old)
            except ValueError:
                pass
    return path
