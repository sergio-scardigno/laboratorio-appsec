"""Genera findings.json y el informe HTML autocontenido."""
from __future__ import annotations

import json
import secrets
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from lab.coverage import COVERAGE, COVERAGE_LABELS
from lab.models import SEVERITIES, SEVERITY_LABELS, TOOLS, Finding
from lab.owasp import UNMAPPED, load_table
from lab.runners.base import ToolResult

TEMPLATES = Path(__file__).resolve().parent / "templates"
TOOL_LABELS = {"semgrep": "Semgrep", "sonar": "SonarQube", "trivy": "Trivy", "zap": "ZAP"}
SEVERITY_ICONS = {"critical": "◆", "high": "▲", "medium": "●", "low": "○", "info": "·"}
STATUS_LABELS = {"ok": "Completo", "partial": "Parcial", "error": "Con error"}
# Rampa secuencial azul: (tope del tramo, fondo, usa texto claro).
RAMP = [(2, "#cde2fb", False), (5, "#9ec5f4", False), (15, "#5598e7", False), (40, "#256abf", True), (10**9, "#0d366b", True)]


def safe_url(url: str) -> str:
    """Solo http(s): una URL del informe viene de datos no confiables."""
    return url if urlparse(url or "").scheme in ("http", "https") else "#"


def ramp_cell(count: int) -> dict:
    for top, background, light_text in RAMP:
        if count <= top:
            return {"background": background, "light": light_text}
    return {"background": RAMP[-1][1], "light": True}


def build_matrix(findings: list[Finding], results: dict[str, ToolResult]) -> list[dict]:
    table = load_table()["categories"]
    rows = []
    for cat_id in [*sorted(table), UNMAPPED]:
        inside = [f for f in findings if cat_id in f.categories]
        cells = []
        for tool in TOOLS:
            count = sum(1 for f in inside if tool in f.tools)
            state = results[tool].status if tool in results else "skipped"
            cell = {"tool": tool, "count": count, "state": state}
            if count:
                cell.update(ramp_cell(count))
            cells.append(cell)
        by_severity = Counter(f.severity for f in inside)
        level, note = COVERAGE.get(cat_id, ("", "El CWE no está en la tabla oficial de 2025, o la herramienta no da ninguno. No se adivina la categoría."))
        rows.append({
            "id": cat_id,
            "slug": cat_id.split(":")[0] if cat_id != UNMAPPED else "sin-mapear",
            "name": table.get(cat_id, {}).get("name", ""),
            "url": table.get(cat_id, {}).get("url", ""),
            "total": len(inside),
            "cells": cells,
            "severity": [(s, by_severity[s]) for s in SEVERITIES if by_severity[s]],
            "review": sum(1 for f in inside if f.review_required),
            "coverage": level,
            "coverage_label": COVERAGE_LABELS.get(level, ""),
            "coverage_note": note,
            "findings": inside,
        })
    return rows


def summarize(findings: list[Finding], results: dict[str, ToolResult], status: str) -> dict:
    by_severity = Counter(f.severity for f in findings)
    by_category = Counter(c for f in findings for c in f.categories)
    return {
        "status": status,
        "total": len(findings),
        "review_required": sum(1 for f in findings if f.review_required),
        "by_severity": {s: by_severity[s] for s in SEVERITIES},
        "by_category": dict(sorted(by_category.items())),
        "tools": {
            name: {"status": r.status, "message": r.message, "duration_s": round(r.duration_s), "details": r.details}
            for name, r in results.items()
        },
    }


def headline(summary: dict) -> str:
    total = summary["total"]
    if summary["status"] == "error":
        return "El análisis no ha podido completarse"
    noun = "hallazgo" if total == 1 else "hallazgos"
    review = summary["review_required"]
    if not total:
        return "Ninguna herramienta ha encontrado nada"
    if review:
        return f"{total} {noun}, {review} por revisar a mano"
    return f"{total} {noun}"


def write_report(out_dir: Path, meta: dict, results: dict[str, ToolResult], findings: list[Finding]) -> dict:
    summary = summarize(findings, results, meta["status"])
    (out_dir / "findings.json").write_text(json.dumps(
        {**meta, "summary": summary, "findings": [f.to_dict() for f in findings]},
        indent=2, ensure_ascii=False,
    ))

    env = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=select_autoescape(["html"], default_for_string=True, default=True),
        trim_blocks=True, lstrip_blocks=True,
    )
    env.filters["safe_url"] = safe_url
    html = env.get_template("report.html").render(
        meta=meta, summary=summary, results=results, matrix=build_matrix(findings, results),
        headline=headline(summary), tools=TOOLS, tool_labels=TOOL_LABELS,
        severity_labels=SEVERITY_LABELS, severity_icons=SEVERITY_ICONS, severities=SEVERITIES,
        status_labels=STATUS_LABELS, ramp=RAMP, unmapped=UNMAPPED, nonce=secrets.token_urlsafe(16),
        findings_count=len(findings),
    )
    (out_dir / "report.html").write_text(html, encoding="utf-8")
    return summary
