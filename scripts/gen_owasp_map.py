#!/usr/bin/env python3
"""Genera data/owasp2025_cwe.json desde las páginas oficiales del OWASP Top 10:2025.

Falla (exit 1) si el número de CWE extraídos de una categoría no coincide con el
valor "CWEs Mapped" que la propia página declara: es preferible no tener tabla a
tener una tabla incompleta sin saberlo.

Solo usa la biblioteca estándar. El HTML descargado se trata como datos.
"""
from __future__ import annotations

import html
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

BASE = "https://top10.owasp.org/2025/"
INTRO = BASE + "0x00_2025-Introduction/"
OUTPUT = Path(__file__).resolve().parent.parent / "data" / "owasp2025_cwe.json"

CATEGORY_LINK = re.compile(r"""href=["'][^"']*?(A(\d{2})_2025-[A-Za-z_&-]+?)/?["']""")
CWE_LINK = re.compile(
    r"""cwe\.mitre\.org/data/definitions/(\d+)\.html["'][^>]*>\s*(.*?)\s*</a>""",
    re.DOTALL,
)
MAPPED_HEADER = re.compile(r"List of Mapped CWEs", re.IGNORECASE)
TAG = re.compile(r"<[^>]+>")


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "appsec-lab-owasp-map"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", "replace")


def declared_cwe_count(page: str) -> int | None:
    """Lee el valor de 'CWEs Mapped' de la tabla de puntuación de la página."""
    table = re.search(r"<table.*?</table>", page, re.DOTALL | re.IGNORECASE)
    if not table:
        return None
    rows = re.findall(r"<tr.*?</tr>", table.group(0), re.DOTALL | re.IGNORECASE)
    if len(rows) < 2:
        return None
    cell = re.compile(r"<t[hd][^>]*>(.*?)</t[hd]>", re.DOTALL | re.IGNORECASE)
    headers = [TAG.sub("", c).strip().lower() for c in cell.findall(rows[0])]
    values = [TAG.sub("", c).strip() for c in cell.findall(rows[1])]
    for name, value in zip(headers, values):
        if "cwes mapped" in name:
            digits = re.sub(r"\D", "", value)
            return int(digits) if digits else None
    return None


def main() -> int:
    intro = fetch(INTRO)
    slugs = {int(num): slug for slug, num in CATEGORY_LINK.findall(intro)}
    if sorted(slugs) != list(range(1, 11)):
        print(f"ERROR: categorías encontradas: {sorted(slugs)}", file=sys.stderr)
        return 1

    categories = {}
    cwe_to_categories: dict[str, list[str]] = {}
    failed = False

    for num in range(1, 11):
        slug = slugs[num]
        url = f"{BASE}{slug}/"
        page = fetch(url)

        title = re.search(r"<h1[^>]*>(.*?)</h1>", page, re.DOTALL)
        raw_title = TAG.sub("", title.group(1)) if title else slug
        name = html.unescape(raw_title).replace("\u00b6", "").strip()
        name = re.sub(r"^A\d{2}:2025\s*[-–—]?\s*", "", name)
        # El título puede llevar un emoji o icono decorativo al final.
        name = re.sub(r"[^\w\s&,()'/-]+", "", name).strip()

        section = MAPPED_HEADER.split(page)
        if len(section) < 2:
            print(f"ERROR: {slug}: sin sección 'List of Mapped CWEs'", file=sys.stderr)
            failed = True
            continue

        cwes: dict[str, str] = {}
        for number, label in CWE_LINK.findall(section[-1]):
            cwes[number] = html.unescape(TAG.sub("", label)).strip()

        declared = declared_cwe_count(page)
        status = "ok" if declared == len(cwes) else "NO COINCIDE"
        print(f"A{num:02d} {name}: extraídos={len(cwes)} declarados={declared} {status}")
        if declared != len(cwes):
            failed = True

        cat_id = f"A{num:02d}:2025"
        categories[cat_id] = {"name": name, "url": url, "cwes": sorted(cwes, key=int)}
        for number in cwes:
            cwe_to_categories.setdefault(number, []).append(cat_id)

    if failed:
        print("ERROR: tabla incompleta, no se escribe el archivo", file=sys.stderr)
        return 1

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(
            {
                "source": BASE,
                "generated": date.today().isoformat(),
                "categories": categories,
                "cwe_to_categories": dict(
                    sorted(cwe_to_categories.items(), key=lambda kv: int(kv[0]))
                ),
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    repeated = {c: v for c, v in cwe_to_categories.items() if len(v) > 1}
    print(f"CWE únicos: {len(cwe_to_categories)}; en más de una categoría: {repeated or 'ninguno'}")
    print(f"Escrito: {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
