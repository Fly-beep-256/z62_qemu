"""Relocate package-owned Mach-O files without changing their program code."""
from pathlib import Path
import os
import re
import subprocess


def command(argv):
    result = subprocess.run([str(x) for x in argv], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(' '.join(map(str, argv)) + '\n' + result.stderr)
    return result.stdout


def dependencies(path):
    output = command(['/usr/bin/otool', '-L', path])
    return [line.strip().split(' (compatibility version', 1)[0]
            for line in output.splitlines()[1:] if ' (compatibility version' in line]


def system_library(name):
    return name.startswith(('/usr/lib/', '/System/Library/'))


def relocate(path, library_directory):
    path, library_directory = Path(path).resolve(strict=True), Path(library_directory).resolve(strict=True)
    changes = []
    for old in dependencies(path):
        if system_library(old):
            continue
        name = Path(old).name
        if path.suffix == '.dylib' and name == path.name:
            continue  # LC_ID_DYLIB is handled separately.
        target = library_directory / name
        if not target.is_file():
            raise FileNotFoundError('Unbundled Mach-O dependency: ' + old)
        new = '@loader_path/' + os.path.relpath(target, path.parent)
        if new != old:
            command(['/usr/bin/install_name_tool', '-change', old, new, path])
            changes.append(dict(kind='dependency', old=old, new=new))
    if path.suffix == '.dylib':
        command(['/usr/bin/install_name_tool', '-id', '@rpath/' + path.name, path])
        changes.append(dict(kind='dylib_id', new='@rpath/' + path.name))
    load_commands = command(['/usr/bin/otool', '-l', path])
    for old in re.findall(r'cmd LC_RPATH\s+cmdsize \d+\s+path (.*?) \(offset \d+\)', load_commands):
        command(['/usr/bin/install_name_tool', '-delete_rpath', old, path])
        changes.append(dict(kind='removed_rpath', old=old))
    command(['/usr/bin/codesign', '--force', '--sign', '-', path])
    command(['/usr/bin/codesign', '--verify', '--strict', path])
    return changes
