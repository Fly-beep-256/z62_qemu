"""Bounded CPU OCR of saved QEMU frames; never runs or controls a guest.

Apple Vision was timing out on every colored frame on this host. The workspace
Tesseract installation avoids the GPU path. OCR remains an inference; retained
images are authoritative for visual confirmation.
"""
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys


TESSERACT = Path(__file__).resolve().parents[2] / "runtime/ocr/bin/tesseract"


def recognize(path):
    from PIL import Image
    source = Path(path).resolve(strict=True)
    with Image.open(source) as frame:
        width, height = frame.size
    if not TESSERACT.is_file():
        raise FileNotFoundError("Workspace Tesseract is unavailable: " + str(TESSERACT))
    env = dict(os.environ, OMP_THREAD_LIMIT="1",
               TESSDATA_PREFIX=str(TESSERACT.parents[1] / "share/tessdata"))
    result = subprocess.run(
        [str(TESSERACT), str(source), "stdout", "-l", "eng", "--psm", "6", "tsv"],
        capture_output=True, text=True, timeout=15, env=env)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    lines = {}
    for item in csv.DictReader(io.StringIO(result.stdout), delimiter="\t"):
        if not item["text"].strip() or float(item["conf"]) < 0:
            continue
        key = tuple(item[k] for k in ("page_num", "block_num", "par_num", "line_num"))
        lines.setdefault(key, []).append(item)
    rows = []
    for words in lines.values():
        left = min(int(w["left"]) for w in words)
        top = min(int(w["top"]) for w in words)
        right = max(int(w["left"]) + int(w["width"]) for w in words)
        bottom = max(int(w["top"]) + int(w["height"]) for w in words)
        rows.append(dict(text=" ".join(w["text"] for w in words),
            confidence=sum(float(w["conf"]) for w in words) / (100 * len(words)),
            bbox_bottom_left_normalized=[left / width, 1 - bottom / height,
                                         (right - left) / width, (bottom - top) / height]))
    return dict(path=str(source), rows=rows, engine="Tesseract CPU OCR",
                backend=str(TESSERACT), source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                backend_sha256=hashlib.sha256(TESSERACT.read_bytes()).hexdigest(),
                kind="OCR of saved QEMU screenshot; text inference requires image confirmation")


def main():
    out = []
    for path in sys.argv[1:]:
        try:
            out.append(recognize(path))
        except Exception as error:
            out.append(dict(path=path, error=str(error), rows=[]))
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
