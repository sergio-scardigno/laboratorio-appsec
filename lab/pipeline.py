"""Orquestación de un análisis, compartida por la CLI y la web."""
from __future__ import annotations

import fcntl
import json
import secrets
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from lab import images, source
from lab.dedupe import correlate, merge_sast
from lab.models import SEVERITIES, Finding, ParseResult
from lab.normalize import attach_snippets, parse_semgrep, parse_sonar, parse_zap
from lab.report import write_report
from lab.runners import semgrep, sonar, zap
from lab.runners.base import ToolResult
from lab.settings import Settings
from lab.store import Store

PRESET_JUICE_SHOP = "juice-shop"
JUICE_SHOP_URL = "http://juice-shop:3000"
JUICE_SHOP_NETWORK = "lab-internal"

Emit = Callable[[str, str, str], None]


class ScanRefused(Exception):
    """La petición no cumple las reglas de autorización o no es válida."""


class ScanBusy(Exception):
    """Ya hay otro análisis en curso."""


@dataclass
class ScanRequest:
    repo: str = ""
    ref: str = ""
    local_path: str = ""
    url: str = ""
    preset: str = ""
    active: bool = False
    # Declaraciones de quien lanza el análisis; quedan registradas en la ejecución.
    authorized: bool = False
    active_confirmed: bool = False

    @property
    def target(self) -> str:
        if self.preset == PRESET_JUICE_SHOP:
            return f"OWASP Juice Shop {images.JUICE_SHOP_TAG}"
        return " + ".join(part for part in (self.repo or self.local_path, self.url) if part)

    @property
    def runs_sast(self) -> bool:
        return bool(self.preset or self.repo or self.local_path)

    @property
    def runs_dast(self) -> bool:
        return bool(self.preset or self.url)


def validate_target_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScanRefused("La web debe ser una URL http:// o https:// completa")
    if parsed.username or parsed.password:
        raise ScanRefused("La URL de la web no debe llevar credenciales")


def validate(request: ScanRequest) -> None:
    if request.preset:
        if request.preset != PRESET_JUICE_SHOP:
            raise ScanRefused(f"Preset desconocido: {request.preset}")
        if request.repo or request.url or request.local_path:
            raise ScanRefused("Un preset no se combina con otro repo o web")
        return  # Objetivo propio del laboratorio, en una red aislada.
    if request.repo and request.local_path:
        raise ScanRefused("Indica un repo o una carpeta, no ambos")
    if not (request.repo or request.local_path or request.url):
        raise ScanRefused("Indica un repo o una web para analizar")
    if request.repo:
        try:
            source.validate_repo_url(request.repo)
        except source.SourceError as exc:
            raise ScanRefused(str(exc)) from exc
    if request.active and not request.url:
        raise ScanRefused("El modo activo necesita una web")
    if request.url:
        validate_target_url(request.url)
        if not request.authorized:
            raise ScanRefused(
                "Confirma que tienes autorización para analizar esta web: ZAP le envía peticiones "
                "incluso en modo pasivo"
            )
        if request.active and not request.active_confirmed:
            raise ScanRefused(
                "El modo activo ataca la web de verdad y puede alterar sus datos o tumbarla. "
                "Confírmalo de forma expresa"
            )


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{secrets.token_hex(2)}"


def restart_juice_shop(root: Path, timeout_s: int = 90) -> None:
    """Parte de una tienda limpia: un análisis activo anterior la deja alterada."""
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    subprocess.run(
        ["docker", "compose", "restart", "juice-shop"],
        cwd=root, check=True, capture_output=True, timeout=120,
    )
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        logs = subprocess.run(
            ["docker", "compose", "logs", "--since", started, "juice-shop"],
            cwd=root, capture_output=True, text=True, timeout=30,
        )
        if "Server listening on port" in logs.stdout:
            return
        time.sleep(2)
    raise TimeoutError(f"Juice Shop no arrancó en {timeout_s}s")


def _prepare_source(request: ScanRequest, dest: Path, github_token: str = "") -> list[str]:
    if request.preset:
        source.clone(images.JUICE_SHOP_REPO, dest, ref=images.JUICE_SHOP_TAG)
    elif request.repo:
        source.clone(request.repo, dest, ref=request.ref or None, github_token=github_token)
    else:
        source.copy_local(Path(request.local_path), dest)
    return source.sanitize(dest)


def _safely(tool: str, fn: Callable[[], ToolResult]) -> ToolResult:
    """El fallo de una herramienta no debe tumbar el análisis de las demás."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - se informa como ejecución parcial
        return ToolResult(tool, "error", message=f"{type(exc).__name__}: {exc}")


def _parse(result: ToolResult, out_dir: Path, parser: Callable[[dict], ParseResult]) -> ParseResult | None:
    try:
        return parser(json.loads((out_dir / result.raw_files[0]).read_text(errors="replace")))
    except Exception as exc:  # noqa: BLE001
        result.status = "error"
        result.message = f"No se pudo interpretar la salida: {type(exc).__name__}: {exc}"
        return None


def overall_status(results: dict[str, ToolResult]) -> str:
    ran = [r for r in results.values() if r.status != "skipped"]
    if not ran or all(r.status == "error" for r in ran):
        return "error"
    return "partial" if any(r.status == "error" for r in ran) else "ok"


def execute(
    request: ScanRequest, settings: Settings, store: Store, run_id: str | None = None,
    emit: Emit | None = None,
) -> dict:
    """Ejecuta el análisis. Lanza ScanBusy si ya hay otro en curso."""
    validate(request)
    settings.runs_dir.mkdir(parents=True, exist_ok=True)
    lock = open(settings.runs_dir / ".lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        lock.close()
        raise ScanBusy("Ya hay un análisis en curso") from exc

    try:
        run_id = run_id or new_run_id()
        if not store.get_run(run_id):
            store.create_run(run_id, request.target, asdict(request))
        return _execute_locked(request, settings, store, run_id, emit)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def _execute_locked(
    request: ScanRequest, settings: Settings, store: Store, run_id: str, emit: Emit | None
) -> dict:
    def event(stage: str, status: str, message: str = "") -> None:
        store.add_event(run_id, stage, status, message)
        if emit:
            emit(stage, status, message)

    store.set_status(run_id, "running")
    out_dir = settings.runs_dir / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "request.json").write_text(json.dumps(asdict(request), indent=2))
    started = time.monotonic()

    results = {name: ToolResult(name, "skipped") for name in ("semgrep", "sonar", "zap")}
    parsed: list[ParseResult] = []
    src = out_dir / "src"
    source_ready = False
    removed: list[str] = []

    if request.runs_sast:
        event("source", "running", "Obteniendo el código")
        try:
            removed = _prepare_source(request, src, settings.github_token)
            source_ready = True
            detail = f"Eliminados: {', '.join(removed)}" if removed else ""
            event("source", "ok", detail)
        except (source.SourceError, OSError) as exc:
            event("source", "error", str(exc))
            for name in ("semgrep", "sonar"):
                results[name] = ToolResult(name, "error", message=f"Sin código que analizar: {exc}")

    if source_ready:
        event("semgrep", "running")
        results["semgrep"] = _safely("semgrep", lambda: semgrep.run(src, out_dir, settings.rules_dir, run_id))
        if results["semgrep"].status == "ok" and (p := _parse(results["semgrep"], out_dir, parse_semgrep)):
            parsed.append(p)
        event("semgrep", results["semgrep"].status, results["semgrep"].message)

        event("sonar", "running")
        if not settings.sonar_token:
            results["sonar"] = ToolResult("sonar", "error", message="Falta SONAR_TOKEN: ejecuta make sonar")
        else:
            results["sonar"] = _safely(
                "sonar", lambda: sonar.run(src, out_dir, run_id, settings.sonar_url, settings.sonar_token)
            )
        if results["sonar"].status == "ok" and (p := _parse(results["sonar"], out_dir, parse_sonar)):
            parsed.append(p)
        event("sonar", results["sonar"].status, results["sonar"].message)

    if request.runs_dast:
        event("zap", "running", "Modo activo" if request.active else "Modo pasivo")

        def run_zap() -> ToolResult:
            if request.preset:
                restart_juice_shop(settings.root)
                return zap.run(JUICE_SHOP_URL, out_dir, run_id, active=request.active, network=JUICE_SHOP_NETWORK)
            return zap.run(request.url, out_dir, run_id, active=request.active)

        results["zap"] = _safely("zap", run_zap)
        if results["zap"].status == "ok" and (p := _parse(results["zap"], out_dir, parse_zap)):
            parsed.append(p)
        event("zap", results["zap"].status, results["zap"].message)

    event("report", "running", "Mapeando al OWASP Top 10:2025")
    findings: list[Finding] = [f for p in parsed for f in p.findings]
    if source_ready:
        attach_snippets(findings, src)
    normalized_total = len(findings)
    findings = merge_sast(findings)
    correlated = correlate(findings)
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.review_required, f.title))

    warnings = [w for p in parsed for w in p.warnings]
    for p in parsed:
        if not p.reconciled:
            warnings.append(f"{p.tool}: los recuentos no cuadran y puede faltar algún hallazgo")
            results[p.tool].status = "error"
            results[p.tool].message = "Los recuentos no cuadran"

    status = overall_status(results)
    stats = {
        p.tool: {"raw": p.raw_count, "normalized": len(p.findings), "discarded": p.discarded}
        for p in parsed
    }
    report_meta = {
        "run_id": run_id,
        "target": request.target,
        "request": asdict(request),
        "status": status,
        "duration_s": round(time.monotonic() - started),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stats": stats,
        "merged": normalized_total - len(findings),
        "correlated": correlated,
        "warnings": warnings,
        "removed_control_files": removed,
    }
    summary = write_report(out_dir, report_meta, results, findings)

    if src.exists():
        shutil.rmtree(src, ignore_errors=True)
    event("report", "ok")
    store.finish_run(run_id, status, summary)
    event("done", status)
    return {"run_id": run_id, "status": status, "summary": summary, "out_dir": str(out_dir)}
