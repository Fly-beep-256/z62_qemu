"""Seal a new static delivery baseline without overwriting an existing one."""
import argparse
import hashlib
import json
from pathlib import Path
import os

from z62_common import ROOT, now, identity


def inventory():
    files, links = [], []
    for path in sorted(ROOT.rglob('*')):
        relative = path.relative_to(ROOT)
        if relative.parts[0] in ('results', 'build', 'provenance'):
            continue
        if relative.parts[:2] == ('artifacts', 'rebuilt'):
            continue
        if any(part in ('.git', '__pycache__') for part in relative.parts):
            continue
        if path.name in ('.DS_Store', '.wraplock') or path.suffix == '.pyc':
            continue
        if path.is_symlink():
            target = os.readlink(path)
            if Path(target).is_absolute() or not path.resolve().is_relative_to(ROOT) or not path.exists():
                raise ValueError('Nonportable symlink: ' + str(relative))
            links.append(dict(path=str(relative), target=target))
        elif path.is_file():
            files.append(dict(**identity(path), executable=bool(path.stat().st_mode & 0o111)))
    tree = dict(files=files, symlinks=links)
    encoded = json.dumps(tree, sort_keys=True, separators=(',', ':')).encode()
    return dict(schema='z62.static-package-manifest/1', created=now(),
                files=files, symlinks=links, tree_sha256=hashlib.sha256(encoded).hexdigest(),
                excluded=['results/', 'build/', 'provenance/', 'artifacts/rebuilt/',
                          '.git/', '__pycache__/', '*.pyc', '.DS_Store', '.wraplock'],
                exclusion_scope='historical provenance, mutable outputs and rebuilds checked by their own manifests',
                camera_access=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='provenance/package-manifest.json',
                        help='New package-relative manifest; an existing file is never overwritten')
    args = parser.parse_args()
    output = ROOT / args.output
    if Path(args.output).is_absolute() or not output.resolve().is_relative_to(ROOT):
        raise ValueError('--output must remain inside this package')
    if output.exists():
        raise FileExistsError('Preserve the existing baseline; choose a new --output')
    result = inventory()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print('%s: %d files, %d relative symlinks, tree SHA256 %s' % (
        output.relative_to(ROOT), len(result['files']), len(result['symlinks']), result['tree_sha256']))


if __name__ == '__main__':
    main()
