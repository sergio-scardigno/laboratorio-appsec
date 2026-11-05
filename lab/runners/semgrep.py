"""Runner de Semgrep: sin red y con las reglas descargadas en la instalación."""
from __future__ import annotations

import json
from pathlib import Path

from lab import images
from lab.runners.base import ToolResult, docker_run, tail


def run(src: Path, out_dir: Path, rules_dir: Path, run_id: str, timeout_s: int = 1800) -> ToolResult:
    rule_files = sorted(rules_dir.glob("*.yaml"))
    if not rule_files:
        return ToolResult("semgrep", "error", message="No hay reglas: ejecuta scripts/fetch-semgrep-rules.py")

    raw = out_dir / "semgrep.json"
    log = out_dir / "semgrep.log"
    config_args = [arg for f in rule_files for arg in ("--config", f"/rules/{f.name}")]
    outcome = docker_run(
        f"lab-{run_id}-semgrep",
        images.SEMGREP,
        [
            "--network", "none",
            "--memory", "4g",
            "-v", f"{src.resolve()}:/src:ro",
            "-v", f"{rules_dir.resolve()}:/rules:ro",
            "-w", "/src",
        ],
        [
            "semgrep", "scan", *config_args,
            "--json", "--metrics", "off", "--disable-version-check", "--no-git-ignore",
            # Sin esto, un comentario "nosemgrep" en el repo oculta sus propios hallazgos.
            "--disable-nosem",
            "--timeout", "30", "--max-target-bytes", "2000000", "--jobs", "3",
            ".",
        ],
        timeout_s=timeout_s,
        stdout_path=raw,
        stderr_path=log,
    )
    if outcome.timed_out:
        return ToolResult("semgrep", "error", outcome.duration_s, message=f"Superó el límite de {timeout_s}s")
    try:
        data = json.loads(raw.read_text(errors="replace"))
    except ValueError:
        return ToolResult(
            "semgrep", "error", outcome.duration_s,
            message=f"Salida no válida (exit {outcome.returncode}): {tail(log)}",
        )
    return ToolResult(
        "semgrep", "ok", outcome.duration_s, [raw.name],
        details={
            "results": len(data.get("results", [])),
            "errors": len(data.get("errors", [])),
            "files_scanned": len(data.get("paths", {}).get("scanned", [])),
            "exit_code": outcome.returncode,
        },
    )
