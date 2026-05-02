from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ns_aeg.tasks.builder import basic_validate_dangerous_path_task


class TaskLoadError(ValueError):
    """Raised when a dangerous path task cannot be loaded safely."""


def load_dangerous_path_task(path: str) -> dict[str, Any]:
    task_path = Path(path)
    if not task_path.exists():
        raise TaskLoadError(f"dangerous path task does not exist: {path}")

    try:
        data = json.loads(task_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise TaskLoadError(f"failed to read dangerous path task: {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise TaskLoadError("dangerous path task must be a JSON object")

    errors = basic_validate_dangerous_path_task(data)
    if errors:
        raise TaskLoadError("invalid dangerous path task: " + "; ".join(errors))
    if not data.get("sources"):
        raise TaskLoadError("dangerous path task has no sources")
    if not data.get("sinks"):
        raise TaskLoadError("dangerous path task has no sinks")
    return data

