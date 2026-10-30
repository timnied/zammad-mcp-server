"""Read secrets from the environment or, preferably, from a file (Docker/K8s secrets).

``NAME`` wins when set; otherwise ``NAME_FILE`` names a file whose content (stripped) is
used. Keeping the value in a file keeps it out of ``docker inspect`` and process lists.
"""

from __future__ import annotations

import os
from pathlib import Path


def env_or_file(name: str) -> str | None:
    value = os.getenv(name)
    if value:
        return value
    file_name = os.getenv(f"{name}_FILE")
    if not file_name:
        return None
    try:
        content = Path(file_name).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"{name}_FILE is set but {file_name!r} cannot be read: {exc}") from exc
    if not content:
        raise ValueError(f"{name}_FILE is set but {file_name!r} is empty")
    return content
