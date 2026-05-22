"""SGT/DGT dictionary load and lookup."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path


class UnknownSGTError(KeyError):
    """Raised when an SGT ID is not in the dictionary."""


@dataclass
class SGTDictionary:
    """Maps SGT/DGT numeric IDs to human-readable names.

    Use `register` to inject names interactively for IDs that show up in logs but were
    not present in the initial file.
    """

    names: dict[int, str]

    def get(self, sgt_id: int) -> str:
        if sgt_id not in self.names:
            raise UnknownSGTError(sgt_id)
        return self.names[sgt_id]

    def get_or_default(self, sgt_id: int) -> str:
        return self.names.get(sgt_id, f"SGT_{sgt_id}")

    def register(self, sgt_id: int, name: str) -> None:
        self.names[sgt_id] = name

    def missing_ids(self, ids: list[int]) -> list[int]:
        return sorted({i for i in ids if i not in self.names})


def load_from_file(path: str | Path) -> SGTDictionary:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        return load_from_json(text)
    return load_from_csv(text)


def load_from_json(text: str) -> SGTDictionary:
    data = json.loads(text)
    # Accept either {"100": "Employees"} or [{"id": 100, "name": "Employees"}]
    names: dict[int, str] = {}
    if isinstance(data, dict):
        for k, v in data.items():
            names[int(k)] = str(v)
    elif isinstance(data, list):
        for row in data:
            names[int(row["id"])] = str(row["name"])
    else:
        raise ValueError("Unsupported JSON structure for SGT dictionary")
    return SGTDictionary(names=names)


def load_from_csv(text: str) -> SGTDictionary:
    names: dict[int, str] = {}
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return SGTDictionary(names=names)
    # Accept columns named id/sgt + name, case-insensitive
    id_col = _pick_column(reader.fieldnames, {"id", "sgt", "sgt_id", "tag"})
    name_col = _pick_column(reader.fieldnames, {"name", "sgt_name", "label"})
    for row in reader:
        try:
            names[int(row[id_col])] = row[name_col].strip()
        except (KeyError, ValueError):
            continue
    return SGTDictionary(names=names)


def _pick_column(fieldnames: list[str], candidates: set[str]) -> str:
    for fn in fieldnames:
        if fn.lower() in candidates:
            return fn
    raise ValueError(
        f"CSV must contain one of {candidates} columns; got {fieldnames}"
    )
