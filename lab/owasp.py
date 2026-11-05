"""Mapeo de CWE a categorías del OWASP Top 10:2025.

Regla: nunca se adivina. Lo que no tiene un CWE reconocible en la tabla oficial
queda en UNMAPPED para que se vea en el informe.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Iterable

TABLE_PATH = Path(__file__).resolve().parent.parent / "data" / "owasp2025_cwe.json"
UNMAPPED = "Sin mapear"

_CWE_TEXT = re.compile(r"^\s*(?:CWE[-_ ]?)?(\d+)\b", re.IGNORECASE)


@lru_cache(maxsize=1)
def load_table() -> dict:
    return json.loads(TABLE_PATH.read_text(encoding="utf-8"))


def parse_cwe(raw: object) -> int | None:
    """Convierte 89, "89", "CWE-89" o "CWE-89: SQL Injection" en 89.

    Devuelve None si no es un CWE válido: ZAP usa -1 y 0 para "sin CWE".
    """
    if isinstance(raw, bool) or raw is None:
        return None
    match = _CWE_TEXT.match(str(raw))
    if not match:
        return None
    number = int(match.group(1))
    return number if number > 0 else None


def categories_for(raw_cwes: Iterable[object]) -> list[str]:
    """Categorías de un conjunto de CWE; [UNMAPPED] si ninguno está en la tabla."""
    table = load_table()["cwe_to_categories"]
    found: set[str] = set()
    for raw in raw_cwes:
        number = parse_cwe(raw)
        if number is not None:
            found.update(table.get(str(number), []))
    return sorted(found) or [UNMAPPED]


def category_ids() -> list[str]:
    return sorted(load_table()["categories"])
