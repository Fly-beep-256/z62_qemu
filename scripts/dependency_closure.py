"""Check package-owned Mach-O dependencies and symlinks without loading code.

The macOS shared cache supplies Apple system libraries. All other dependencies
must resolve inside this particular copy through relative Mach-O load paths.
Historical provenance and disposable build caches are not active dependencies.
"""
from pathlib import Path
import re
import subprocess

MAGICS = {b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
          b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
          b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


def inspect(root):
    root = Path(root).resolve(strict=True)
    from z62_common import read
    bases = [root/name for name in ('runtime', 'bin', 'src', 'inputs', 'profiles',
                                   'scripts', 'artifacts/qemu', 'artifacts/formal-expeed',
                                   'artifacts/formal-mcu')]
    selected = read(root/'artifacts/rebuilt/latest.json', {})
    if selected.get('directory'):
        bases.append(root/selected['directory'])
    errors, links, rows, owned_edges = [], [], [], 0

    def otool(flag, path):
        result = subprocess.run(['/usr/bin/otool', flag, str(path)], capture_output=True,
                                text=True, timeout=15)
        if result.returncode:
            raise ValueError(result.stderr.strip())
        return result.stdout

    def expanded(path, owner):
        if path.startswith('@loader_path/'):
            return (owner.parent/path[len('@loader_path/'):]).resolve()
        if path.startswith('@executable_path/'):
            # Executables in this package provide their own executable directory.
            return (owner.parent/path[len('@executable_path/'):]).resolve()
        return None

    for base in bases:
        for path in sorted(base.rglob('*')):
            relative = str(path.relative_to(root))
            if path.is_symlink():
                target = path.resolve()
                if not target.exists() or not target.is_relative_to(root):
                    item = dict(path=relative, target=str(target))
                    links.append(item)
                    errors.append('External or broken symlink: ' + relative)
                continue
            if not path.is_file():
                continue
            if path.relative_to(root).parts[0] not in ('runtime', 'bin', 'artifacts'):
                # Input contracts retain historical binary hashes as read-only
                # provenance references. Runtime binaries come from manifests.
                continue
            with path.open('rb') as stream:
                magic = stream.read(4)
            if magic not in MAGICS:
                continue
            try:
                commands = otool('-l', path)
                rpaths = re.findall(r'cmd LC_RPATH\s+cmdsize \d+\s+path (.*?) \(offset \d+\)', commands)
                own_ids = re.findall(r'cmd LC_ID_DYLIB\s+cmdsize \d+\s+name (.*?) \(offset \d+\)', commands)
                dependencies = [line.strip().split(' (compatibility version', 1)[0]
                                for line in otool('-L', path).splitlines()[1:]
                                if ' (compatibility version' in line]
                resolved = []
                for rpath in rpaths:
                    if Path(rpath).is_absolute() and not rpath.startswith(('/usr/lib/', '/System/Library/')):
                        errors.append('Absolute non-system Mach-O rpath: %s: %s' % (relative, rpath))
                for dependency in dependencies:
                    if dependency in own_ids or dependency.startswith(('/usr/lib/', '/System/Library/')):
                        continue
                    candidates = []
                    if dependency.startswith('@rpath/'):
                        for rpath in rpaths:
                            parent = expanded(rpath, path)
                            if parent is not None:
                                candidates.append(parent/dependency[len('@rpath/'):])
                    else:
                        target = expanded(dependency, path)
                        if target is not None:
                            candidates.append(target)
                    target = next((p.resolve() for p in candidates
                                   if p.is_file() and p.resolve().is_relative_to(root)), None)
                    if target is None:
                        errors.append('Unbundled Mach-O dependency: %s: %s' % (relative, dependency))
                    else:
                        owned_edges += 1
                        resolved.append(dict(load_path=dependency, target=str(target.relative_to(root))))
                rows.append(dict(path=relative, dependencies=resolved, rpaths=rpaths))
            except Exception as error:
                errors.append('%s: %s' % (relative, error))
    return dict(schema='z62.dynamic-dependency-closure/1', passed=not errors,
                Mach_O_file_count=len(rows), owned_dependency_edges=owned_edges,
                external_or_broken_symlinks=links, files=rows, errors=errors,
                system_libraries='Apple /usr/lib and /System/Library supplied by macOS')
