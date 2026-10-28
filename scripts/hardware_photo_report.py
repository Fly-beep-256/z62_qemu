"""Annotate retained Z62 photographs using verified source identities.

Coordinates locate visible packages in the photographs, not PCB nets.
Original photographs and prior annotations are never overwritten.
"""
import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from z62_common import ROOT, identity, now, read, save


HARDWARE = Path('docs/assets/hardware/z62-user-board-20261025')
ANNOTATIONS = {
    'assets/z62-taobao-motherboard-1.png': [
        dict(number=1, box_xyxy=[645, 455, 841, 638],
             label='R5F56519AD: Renesas RX651; board role unresolved'),
        dict(number=2, box_xyxy=[1530, 644, 1815, 924],
             label='ST controller; complete ordering code unresolved'),
        dict(number=3, box_xyxy=[1150, 258, 1298, 416],
             label='L6524: NXP PCAL6524HE / HUQFN32; bus owner unresolved'),
    ],
    'assets/z62-taobao-motherboard-2.png': [
        dict(number=4, box_xyxy=[1010, 1042, 1400, 1350],
             label='SPANSION GL256S10FHV2: parallel NOR family; bus owner unresolved'),
        dict(number=5, box_xyxy=[754, 964, 955, 1142],
             label='Nikon E1-223 / 007636; device function unresolved'),
    ],
}


def retained(value):
    path = (ROOT / value).resolve(strict=True)
    if not path.is_relative_to(ROOT):
        raise ValueError('Source must remain inside this package')
    return path


def checked(expected):
    result = identity(retained(expected['path']))
    if any(result[key] != expected[key] for key in ('bytes', 'sha256')):
        raise ValueError('Source identity changed: ' + expected['path'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output', default=str(HARDWARE / 'annotations'),
                        help='New package-relative annotation directory')
    args = parser.parse_args()
    output = ROOT / args.output
    if Path(args.output).is_absolute() or not output.resolve().is_relative_to(ROOT):
        parser.error('Output must be a package-relative directory')
    source_file = retained(HARDWARE / 'source-confirmation.json')
    sources = read(source_file)
    source_map = {row['retained_file']: row for row in sources['photos']}
    manufacturer_file = retained(HARDWARE / 'manufacturer/PCAL6524DS-rev2.1-source.json')
    manufacturer = read(manufacturer_file)
    checked(manufacturer['PDF'])
    checked(manufacturer['selected_pages_text'])
    output.mkdir(parents=True, exist_ok=False)
    report = dict(schema='z62.hardware-photo-annotations/1', created=now(),
                  generator=identity(Path(__file__)), source_confirmation=identity(source_file),
                  manufacturer_source=identity(manufacturer_file),
                  processing='literal RGB photo plus numbered rectangles and a separate legend; no reconstruction, rotation or scale',
                  board_wiring_verified=False, camera_access=False, photos=[])
    font = ImageFont.load_default(size=36)
    for index, (source, markers) in enumerate(ANNOTATIONS.items(), 1):
        original = checked(dict(path=source, **{key: source_map[source][key]
                                               for key in ('bytes', 'sha256')}))
        with Image.open(retained(source)) as image:
            rgb = image.convert('RGB')
            canvas = Image.new('RGB', (rgb.width, rgb.height + 240), '#111820')
            canvas.paste(rgb, (0, 0))
            draw = ImageDraw.Draw(canvas)
            for marker in markers:
                box = marker['box_xyxy']
                if not (0 <= box[0] < box[2] <= rgb.width and
                        0 <= box[1] < box[3] <= rgb.height):
                    raise ValueError('Annotation outside source image')
                draw.rectangle(box, outline='#ffcf40', width=8)
                badge = (box[0], max(0, box[1] - 60))
                draw.rectangle([*badge, badge[0] + 60, badge[1] + 60], fill='#ffcf40')
                draw.text((badge[0] + 14, badge[1] + 8), str(marker['number']),
                          font=font, fill='#111820')
            for row, marker in enumerate(markers):
                draw.text((30, rgb.height + 18 + 48 * row),
                          '%d. %s' % (marker['number'], marker['label']), font=font, fill='white')
            draw.text((30, canvas.height - 58),
                      'User-confirmed Z62 photos. Numbered positions identify image regions; electrical nets remain untraced.',
                      font=font, fill='#b8c6d6')
            result_file = output / ('board-%d-annotated.png' % index)
            canvas.save(result_file)
            report['photos'].append(dict(source=original, source_dimensions=list(rgb.size),
                                         output=identity(result_file), output_dimensions=list(canvas.size),
                                         markers=markers))
    save(output / 'manifest.json', report)
    print(str((output / 'manifest.json').relative_to(ROOT)), flush=True)


if __name__ == '__main__':
    main()
