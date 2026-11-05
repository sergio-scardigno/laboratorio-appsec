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
    "source": "Código", "semgrep": "Semgrep", "sonar": "SonarQube", "zap": "ZAP",
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
def web(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Arranca la interfaz web."""
    import uvicorn

    settings = load_settings()
    if not settings.web_token:
        typer.echo("Falta LAB_WEB_TOKEN: ejecuta make env", err=True)
        raise typer.Exit(3)
    typer.echo(f"Abre: http://{host}:{port}/?token={settings.web_token}")
    uvicorn.run("lab.web.app:create_app", factory=True, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    app()
