"""确定性的 JSON 文本与内容摘要，跨平台一致。"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def content_digest(values: Iterable[object]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(canonical_json(value).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()
