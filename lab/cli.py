"""CLI del laboratorio."""
from __future__ import annotations

from typing import Optional

import typer

from lab.models import SEVERITIES
from lab.pipeline import ScanBusy, ScanRefused, ScanRequest, execute
from lab.settings import load_settings
from lab.store import Store

app = typer.Typer(add_completion=False, help="Laboratorio AppSec: Semgrep, SonarQube y ZAP con mapeo al OWASP Top 10:2025")

STAGES = {
    "source": "Código", "semgrep": "Semgrep", "sonar": "SonarQube", "trivy": "Trivy", "zap": "ZAP",
    "report": "Informe", "done": "Fin",
}


@app.command()
def scan(
    repo: str = typer.Option("", help="Repo público https:// a analizar"),
    ref: str = typer.Option("", help="Rama o etiqueta del repo"),
    path: str = typer.Option("", help="Carpeta local a analizar"),
    url: str = typer.Option("", help="Web a analizar con ZAP"),
    preset: str = typer.Option("", help="Objetivo preparado: juice-shop"),
    active: bool = typer.Option(False, "--active", help="ZAP en modo activo: ataca la web de verdad"),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized", help="Declaro que tengo autorización para analizar esta web"),
    confirm_active: bool = typer.Option(False, "--confirm-active", help="Confirmo el modo activo contra esta web"),
    fail_on: Optional[str] = typer.Option(None, help="Sale con código 1 si hay hallazgos de esta gravedad o mayor: " + ", ".join(SEVERITIES)),
) -> None:
    """Analiza un repo, una web o ambos.

    Códigos de salida: 0 correcto, 1 superado --fail-on, 2 parcial o con error, 3 rechazado.
    """
    if fail_on and fail_on not in SEVERITIES:
        typer.echo(f"--fail-on debe ser uno de: {', '.join(SEVERITIES)}", err=True)
        raise typer.Exit(3)
    settings = load_settings()
    store = Store(settings.db_path)
    request = ScanRequest(
        repo=repo, ref=ref, local_path=path, url=url, preset=preset, active=active,
        authorized=i_am_authorized, active_confirmed=confirm_active,
    )

    def emit(stage: str, status: str, message: str) -> None:
        line = f"[{STAGES.get(stage, stage)}] {status}"
        typer.echo(f"{line}: {message}" if message else line)

    try:
        result = execute(request, settings, store, emit=emit)
    except (ScanRefused, ScanBusy) as exc:
        typer.echo(f"Rechazado: {exc}", err=True)
        raise typer.Exit(3) from exc

    summary = result["summary"]
    typer.echo(f"\nEstado: {result['status']}  Hallazgos: {summary['total']}  Por revisar: {summary['review_required']}")
    for severity, count in summary["by_severity"].items():
        if count:
            typer.echo(f"  {severity}: {count}")
    typer.echo(f"Informe: {result['out_dir']}/report.html")

    if result["status"] != "ok":
        raise typer.Exit(2)
    if fail_on:
        threshold = SEVERITIES.index(fail_on)
        if any(summary["by_severity"].get(s) for s in SEVERITIES[: threshold + 1]):
            typer.echo(f"Hay hallazgos de gravedad {fail_on} o mayor", err=True)
            raise typer.Exit(1)


@app.command()
def runs(limit: int = 20) -> None:
    """Lista los últimos análisis."""
    settings = load_settings()
    for run in Store(settings.db_path).list_runs(limit):
        total = (run["summary"] or {}).get("total", "-")
        typer.echo(f"{run['id']}  {run['status']:8} {total!s:>5}  {run['target']}")


@app.command()
def web(
    host: str = "127.0.0.1",
    port: int = 8000,
    no_link: bool = typer.Option(False, "--no-link", help="No muestra el enlace con el token (para el servicio: acabaría en el journal)"),
) -> None:
    """Arranca la interfaz web."""
    import uvicorn

    settings = load_settings()
    if not settings.web_token:
        typer.echo("Falta LAB_WEB_TOKEN: ejecuta make env", err=True)
        raise typer.Exit(3)
    if not no_link:
        typer.echo(f"Abre: http://{host}:{port}/?token={settings.web_token}")
    uvicorn.run("lab.web.app:create_app", factory=True, host=host, port=port, log_level="warning")


@app.command("web-url")
def web_url(port: int = 8000) -> None:
    """Muestra el enlace de acceso a la web, con su token."""
    settings = load_settings()
    if not settings.web_token:
        typer.echo("Falta LAB_WEB_TOKEN: ejecuta make env", err=True)
        raise typer.Exit(3)
    typer.echo(f"http://127.0.0.1:{port}/?token={settings.web_token}")

gate_app = typer.Typer(add_completion=False, help="Puerta antes del push: bloquea lo crítico, lo alto y los secretos nuevos")
app.add_typer(gate_app, name="gate")

GATE_LABELS = {"critical": "CRÍTICA", "high": "ALTA", "medium": "MEDIA", "low": "BAJA", "info": "INFO"}


def _gate_fail(exc: Exception) -> None:
    typer.echo(f"Rechazado: {exc}", err=True)
    raise typer.Exit(3) from exc


def _print_gate(result: dict) -> None:
    summary = result["summary"]
    typer.echo(f"\nAnálisis {result['run_id']}: {summary['total']} hallazgos en total")
    for tool, info in summary.get("tools", {}).items():
        if info.get("status") not in ("ok", "skipped"):
            typer.echo(f"  {tool}: {info.get('status')} {info.get('message', '')[:160]}")
    if result["accepted"]:
        typer.echo(f"Aceptados en la línea base: {len(result['accepted'])}")
    if result["new"]:
        typer.echo(f"\nBLOQUEADO: {len(result['new'])} hallazgos nuevos críticos, altos o secretos")
        for item in result["new"]:
            where = item["file"] + (f":{item['line']}" if item["line"] and not item["file"].startswith("historial") else "")
            kind = "SECRETO" if item["secret"] else GATE_LABELS.get(item["severity"], item["severity"])
            typer.echo(f"  [{kind}] {item['title'][:120]}")
            typer.echo(f"      {where}  ({item['tool']} {item['rule_id']})  clave {item['key']}")
    elif result["status"] != "ok":
        typer.echo("\nBLOQUEADO: el análisis quedó incompleto, así que no se puede asegurar nada")
    else:
        typer.echo("\nSin hallazgos nuevos que bloqueen")
    typer.echo(f"GATE-RUN: {result['run_id']}")


@gate_app.command("run")
def gate_run(
    name: str = typer.Option(..., help="Nombre del repo, para su línea base"),
    path: str = typer.Option("", help="Carpeta a analizar"),
    stdin: bool = typer.Option(False, "--stdin", help="Lee el código como tar por la entrada estándar"),
) -> None:
    """Analiza lo que se va a subir. Sale con 0 si puede subir, 1 si hay hallazgos nuevos que bloquean y 2 si el análisis queda incompleto."""
    import sys
    from pathlib import Path

    from lab import gate
    from lab.pipeline import ScanBusy, ScanRefused

    if bool(path) == stdin:
        _gate_fail(ValueError("Indica --path o --stdin, uno de los dos"))
    settings = load_settings()
    store = Store(settings.db_path)

    def emit(stage: str, status: str, message: str) -> None:
        line = f"[{STAGES.get(stage, stage)}] {status}"
        typer.echo(f"{line}: {message}" if message else line)

    try:
        if stdin:
            result = gate.run_gate_from_tar(sys.stdin.buffer, name, settings, store, emit)
        else:
            result = gate.run_gate(Path(path), name, settings, store, emit)
    except (gate.GateError, ScanRefused, ScanBusy) as exc:
        _gate_fail(exc)
    _print_gate(result)
    if result["new"]:
        raise typer.Exit(1)
    if result["status"] != "ok":
        raise typer.Exit(2)


@gate_app.command("accept")
def gate_accept(
    name: str = typer.Option(..., help="Nombre del repo"),
    run: str = typer.Option(..., "--run", help="Id del análisis que bloqueó"),
    reason: str = typer.Option(..., help="Por qué se acepta; '-' lo lee de la entrada estándar"),
    key: Optional[list[str]] = typer.Option(None, help="Solo estas claves (por defecto, todas las que bloquearon)"),
) -> None:
    """Acepta en la línea base los hallazgos que bloquearon un análisis."""
    import sys

    from lab import gate

    if reason == "-":
        reason = sys.stdin.read(2000)
    try:
        accepted = gate.accept(load_settings(), name, run, reason, key or None)
    except gate.GateError as exc:
        _gate_fail(exc)
    typer.echo(f"Aceptados {len(accepted)} hallazgos en la línea base de {name}")
    for item in accepted:
        typer.echo(f"  {item['key']}  {item['title'][:100]}")


@gate_app.command("list")
def gate_list(name: str = typer.Option(..., help="Nombre del repo")) -> None:
    """Muestra la línea base de un repo."""
    from lab import gate

    try:
        entries = gate.load_baseline(load_settings(), name)["entries"]
    except gate.GateError as exc:
        _gate_fail(exc)
    if not entries:
        typer.echo("La línea base está vacía")
    for key, entry in entries.items():
        typer.echo(f"{key}  {entry['accepted_at'][:10]}  {entry['title'][:80]}")
        typer.echo(f"    {entry['file']}  motivo: {entry['reason'][:160]}")


@gate_app.command("remove")
def gate_remove(name: str = typer.Option(..., help="Nombre del repo"), key: str = typer.Option(..., help="Clave a quitar")) -> None:
    """Quita un hallazgo de la línea base: volverá a bloquear."""
    from lab import gate

    try:
        removed = gate.remove(load_settings(), name, key)
    except gate.GateError as exc:
        _gate_fail(exc)
    if not removed:
        typer.echo("Esa clave no está en la línea base", err=True)
        raise typer.Exit(3)
    typer.echo("Quitado")


@gate_app.command("report")
def gate_report(run: str = typer.Option(..., "--run", help="Id del análisis")) -> None:
    """Escribe el informe HTML de un análisis de la puerta en la salida estándar."""
    import sys

    from lab import gate

    settings = load_settings()
    try:
        gate.check_run_id(run)
    except gate.GateError as exc:
        _gate_fail(exc)
    folder = settings.runs_dir / run
    if not (folder / "gate.json").exists() or not (folder / "report.html").exists():
        _gate_fail(ValueError("No hay informe de la puerta con ese id"))
    sys.stdout.buffer.write((folder / "report.html").read_bytes())


if __name__ == "__main__":
    app()
