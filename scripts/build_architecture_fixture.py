"""Assemble the explicitly synthetic, RAM-only topology regression programs.

Clang's integrated assembler is the only build dependency. The resulting
ELF section must contain no relocations; execution never needs an ELF loader.
"""
from pathlib import Path
import struct
import subprocess

from z62_common import ROOT, save, identity, clean_environment


def elf_text_and_symbols(raw):
    if raw[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('Expected an ELF32 little-endian relocatable object')
    offset = struct.unpack_from('<I', raw, 32)[0]
    stride, count, names_index = struct.unpack_from('<HHH', raw, 46)
    sections = [struct.unpack_from('<IIIIIIIIII', raw, offset + i * stride) for i in range(count)]
    def data(section):
        return raw[section[4]:section[4] + section[5]]
    def string(table, off):
        return table[off:table.index(b'\0', off)].decode('ascii')
    names = data(sections[names_index])
    text_index = next(i for i, s in enumerate(sections) if string(names, s[0]) == '.text')
    if any(s[1] in (4, 9) and s[7] == text_index and s[5] for s in sections):
        raise ValueError('RAM fixture has unresolved text relocations')
    symbols = {}
    for s in sections:
        if s[1] != 2:
            continue
        strings = data(sections[s[6]])
        records = data(s)
        for off in range(0, len(records), s[9]):
            name, value, size, info, other, section = struct.unpack_from('<IIIBBH', records, off)
            label = string(strings, name)
            if section == text_index and label.startswith(('e6_', 'mcu_')):
                symbols[label] = value & ~1
    return data(sections[text_index]), symbols


def main():
    folder = ROOT / 'tests/architecture'
    report = dict(schema='z62.architecture-fixture-code/1', classification='synthetic structural fixture',
                  original_firmware=False, Flash_patched=False, programs={})
    for role, arch, base in (('e6', 'armv7-a', 0x80000000), ('mcu', 'armv7e-m', 0x2003e000)):
        source = folder / (role + '.s')
        obj = folder / (role + '.o')
        command = ['/Library/Developer/CommandLineTools/usr/bin/clang', '-target', 'arm-none-eabi',
                   '-march=' + arch, '-c', str(source), '-o', str(obj)]
        subprocess.run(command, env=clean_environment(), check=True, capture_output=True, text=True)
        text, symbols = elf_text_and_symbols(obj.read_bytes())
        binary = folder / (role + '.bin')
        binary.write_bytes(text)
        obj.unlink()
        report['programs'][role] = dict(source=identity(source), binary=identity(binary),
                                       load_address=base, symbols=symbols)
    save(folder / 'fixture.json', report)
    print('Assembled independent structural fixture programs')


if __name__ == '__main__':
    main()
