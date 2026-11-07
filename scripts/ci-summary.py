#!/usr/bin/env python3
"""Escribe en Markdown el resumen del último análisis, para el resumen del job de CI."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABELS = {"ok": "Completo", "partial": "Parcial", "error": "Con error"}
TOOL_LABELS = {"semgrep": "Semgrep", "sonar": "SonarQube", "trivy": "Trivy", "zap": "ZAP"}
TOOL_STATUS = {"ok": "Correcto", "error": "Falló", "skipped": "No se ejecutó"}


def main() -> int:
    reports = sorted((ROOT / "runs").glob("*/findings.json"))
    if not reports:
        print("## Análisis\n\nNo se generó ningún informe.")
        return 0
    data = json.loads(reports[-1].read_text())
    summary = data["summary"]
    print(f"## {data['target']}\n")
    print(f"Estado: **{LABELS.get(data['status'], data['status'])}**. "
          f"{summary['total']} hallazgos, {summary['review_required']} por revisar a mano.\n")
    print("| Herramienta | Estado | Detalle |\n|---|---|---|")
    for tool, info in summary["tools"].items():
        print(f"| {TOOL_LABELS[tool]} | {TOOL_STATUS.get(info['status'], info['status'])} | {info['message'][:120]} |")
    print("\n| Categoría | Hallazgos |\n|---|---|")
    for category, count in summary["by_category"].items():
        print(f"| {category} | {count} |")
    print("\nUn hallazgo con varios CWE cuenta en cada categoría que le corresponde. "
          "El informe completo está en los artifacts del job.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
