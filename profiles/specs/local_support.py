from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

PORT = Path(__file__).resolve().parents[2] / 'src/harness'
def identity(path):
    path = Path(path).resolve(strict=True)
    return dict(path=str(path), bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest())
def now():
    return datetime.now(timezone.utc).isoformat()
def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
