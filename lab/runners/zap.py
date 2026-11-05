"""Runner de ZAP: baseline (pasivo) o full (activo, ataca de verdad)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from lab import images
from lab.runners.base import ToolResult, docker_run, tail

SPIDER_MINUTES = 5
PASSIVE_WAIT_MINUTES = 10


def run(
    target_url: str,
    out_dir: Path,
    run_id: str,
    *,
    active: bool,
    network: str | None = None,
    timeout_s: int = 3600,
) -> ToolResult:
    wrk = out_dir / "zap"
    wrk.mkdir(parents=True, exist_ok=True)
    wrk.chmod(0o777)  # El usuario "zap" del contenedor debe poder escribir aquí.
    script = "zap-full-scan.py" if active else "zap-baseline.py"
    docker_args = [
        "--memory", "4g",
        "--no-healthcheck",  # El healthcheck de la imagen no aplica al modo script.
        "-e", "_JAVA_OPTIONS=-Xmx3g",
        "-v", f"{wrk.resolve()}:/zap/wrk:rw",
    ]
    if network:
        docker_args += ["--network", network]
    log = out_dir / "zap.log"
    outcome = docker_run(
        f"lab-{run_id}-zap",
        images.ZAP,
        docker_args,
        [
            script, "-t", target_url,
            "-J", "zap.json", "-r", "zap.html",
            "-j",  # Spider AJAX: las SPA apenas exponen enlaces al spider clásico.
            "-m", str(SPIDER_MINUTES),
            "-T", str(PASSIVE_WAIT_MINUTES),
            "-I",  # Los avisos no cuentan como fallo: el informe decide.
        ],
        timeout_s=timeout_s,
        stdout_path=log,
        stderr_path=out_dir / "zap.err",
    )
    mode = "full" if active else "baseline"
    if outcome.timed_out:
        return ToolResult("zap", "error", outcome.duration_s, message=f"Superó el límite de {timeout_s}s", details={"mode": mode})
    report = wrk / "zap.json"
    if not report.exists():
        return ToolResult(
            "zap", "error", outcome.duration_s,
            message=f"Sin informe (exit {outcome.returncode}): {tail(log)}", details={"mode": mode},
        )
    try:
        data = json.loads(report.read_text(errors="replace"))
    except ValueError:
        return ToolResult("zap", "error", outcome.duration_s, message="Informe JSON no válido", details={"mode": mode})
    sites = data.get("site", [])
    alerts = sum(len(site.get("alerts", [])) for site in sites)
    urls = re.search(r"Total of (\d+) URLs", tail(log, 400))
    status = "ok" if outcome.returncode in (0, 1, 2) else "error"
    return ToolResult(
        "zap", status, outcome.duration_s, ["zap/zap.json"],
        message="" if status == "ok" else f"exit {outcome.returncode}: {tail(log)}",
        details={"mode": mode, "alerts": alerts, "urls": int(urls.group(1)) if urls else None, "sites": [s.get("@name") for s in sites], "exit_code": outcome.returncode},
    )
