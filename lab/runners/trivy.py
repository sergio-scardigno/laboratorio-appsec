"""Runner de Trivy: dependencias vulnerables y secretos.

El proyecto sufrió un compromiso de cadena de suministro en marzo de 2026, así que la
imagen está fijada por digest y corre con el mínimo acceso. Actualizar la base necesita
red, pero no ve el código; analizar ve el código, pero no tiene red. Ninguno de los dos
recibe secretos ni el socket de Docker.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from lab import images
from lab.runners.base import ToolResult, docker_run, tail

CACHE_VOLUME = "lab-trivy-cache"
CACHE_DIR = "/cache"
# Se cambia en una prueba para simular que no hay red al actualizar la base.
DB_UPDATE_DOCKER_ARGS: list[str] = []
DB_TIMEOUT_S = 900

# Lo mismo da una salida vacía con un lockfile sin vulnerabilidades que sin lockfile, así
# que se distinguen por nombre de archivo.
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "npm-shrinkwrap.json",
    "requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock",
    "Gemfile.lock", "composer.lock", "go.mod", "Cargo.lock",
    "pom.xml", "gradle.lockfile", "packages.lock.json", "mix.lock", "pubspec.lock",
    "Package.resolved", "conan.lock",
}
_SKIP_DIRS = {"node_modules", "vendor", ".git"}
SCAN_FLAGS = [
    "--cache-dir", CACHE_DIR, "--cache-backend", "memory",
    "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--skip-check-update",
    "--no-progress", "--quiet", "--format", "json",
]
_MEMORY = ["--memory", "4g"]
_HARDENING = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "2048"]


def find_lockfiles(src: Path) -> list[str]:
    found = []
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        found += [str((Path(root) / name).relative_to(src)) for name in files if name in LOCKFILES]
    return sorted(found)


def _run_quiet(args: list[str], timeout_s: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "run", "--rm", *_HARDENING, *_MEMORY, *args],
        capture_output=True, text=True, timeout=timeout_s,
    )


def database_info() -> dict:
    """Fecha de la base que hay en la caché. Vacío si todavía no hay ninguna."""
    try:
        result = _run_quiet(
            ["--network", "none", "-v", f"{CACHE_VOLUME}:{CACHE_DIR}:ro", images.TRIVY,
             "version", "--cache-dir", CACHE_DIR, "--format", "json"],
            timeout_s=120,
        )
        return json.loads(result.stdout).get("VulnerabilityDB") or {} if result.returncode == 0 else {}
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return {}


def update_db() -> str:
    """Actualiza las bases sin ver el código. Devuelve el motivo del fallo, o cadena vacía."""
    for flag in ("--download-db-only", "--download-java-db-only"):
        try:
            result = _run_quiet(
                [*DB_UPDATE_DOCKER_ARGS, "-v", f"{CACHE_VOLUME}:{CACHE_DIR}", images.TRIVY,
                 "image", "--cache-dir", CACHE_DIR, flag, "--no-progress"],
                timeout_s=DB_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            return f"la descarga superó {DB_TIMEOUT_S}s"
        if result.returncode != 0:
            return result.stderr.strip()[-200:] or f"exit {result.returncode}"
    return ""


def _strip_secret_values(report: dict) -> None:
    """Lo que se guarda en disco tampoco lleva el valor ni el contexto de los secretos."""
    for result in report.get("Results") or []:
        for secret in result.get("Secrets") or []:
            secret.pop("Match", None)
            secret.pop("Code", None)


def _scan(
    kind: str, label: str, mounts: list[str], command: list[str],
    out_dir: Path, run_id: str, timeout_s: int,
) -> dict:
    output, log = out_dir / f"trivy-{kind}.raw", out_dir / f"trivy-{kind}.log"
    try:
        outcome = docker_run(
            f"lab-{run_id}-trivy-{kind}",
            images.TRIVY,
            ["--network", "none", *_MEMORY, "-w", "/", "-v", f"{CACHE_VOLUME}:{CACHE_DIR}:ro", *mounts],
            command,
            timeout_s=timeout_s,
            stdout_path=output,
            stderr_path=log,
        )
        if outcome.timed_out:
            raise RuntimeError(f"El análisis {label} superó {timeout_s}s")
        if outcome.returncode != 0:
            raise RuntimeError(f"El análisis {label} falló (exit {outcome.returncode}): {tail(log, 3)}")
        try:
            report = json.loads(output.read_text(errors="replace"))
        except ValueError as exc:
            raise RuntimeError(f"Trivy no devolvió JSON válido en el análisis {label}") from exc
    finally:
        # Sin filtrar puede llevar el valor de los secretos: nunca se queda en disco.
        output.unlink(missing_ok=True)
    _strip_secret_values(report)
    return {"kind": kind, "label": label, "report": report}


def run(src: Path, out_dir: Path, run_id: str, image_ref: str | None = None, timeout_s: int = 1200) -> ToolResult:
    started = time.monotonic()
    warnings: list[str] = []

    failure = update_db()
    database = database_info()
    if failure and not database:
        return ToolResult("trivy", "error", time.monotonic() - started, message=f"No hay base de vulnerabilidades: {failure}")
    if failure:
        warnings.append(
            f"Trivy no pudo actualizar su base y usó la del {str(database.get('UpdatedAt', ''))[:10]}: "
            "pueden faltar vulnerabilidades recientes"
        )

    lockfiles = find_lockfiles(src)
    if not lockfiles:
        warnings.append(
            "El repo no trae lockfile: sus dependencias se analizaron en la imagen"
            if image_ref else
            "El repo no trae ningún lockfile reconocible: Trivy no pudo analizar sus dependencias. "
            "Un cero en dependencias no significa que no haya vulnerables"
        )

    scans = [_scan(
        "fs", "del repo", ["-v", f"{src.resolve()}:/src:ro"],
        ["fs", *SCAN_FLAGS, "--scanners", "vuln,secret", "/src"],
        out_dir, run_id, timeout_s,
    )]

    if image_ref:
        tarball = out_dir / "trivy-image.tar"
        try:
            # Sin montar el socket de Docker: Trivy solo recibe una copia de la imagen.
            subprocess.run(["docker", "save", image_ref, "-o", str(tarball)], check=True, capture_output=True, timeout=600)
            tarball.chmod(0o644)
            scans.append(_scan(
                "image", "de la imagen", ["-v", f"{tarball.resolve()}:/image.tar:ro"],
                ["image", *SCAN_FLAGS, "--scanners", "vuln", "--input", "/image.tar"],
                out_dir, run_id, timeout_s,
            ))
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"No se pudo copiar la imagen: {exc.stderr.decode(errors='replace')[-200:]}") from exc
        finally:
            tarball.unlink(missing_ok=True)

    raw = out_dir / "trivy.json"
    raw.write_text(json.dumps({"scans": scans, "warnings": warnings, "database": database, "lockfiles": lockfiles}))
    results = [r for scan in scans for r in (scan["report"].get("Results") or [])]
    return ToolResult(
        "trivy", "ok", time.monotonic() - started, [raw.name],
        details={
            "vulnerabilities": sum(len(r.get("Vulnerabilities") or []) for r in results),
            "secrets": sum(len(r.get("Secrets") or []) for r in results),
            "lockfiles": lockfiles,
            "image": image_ref or "",
            "database_updated": str(database.get("UpdatedAt", ""))[:10],
        },
    )
