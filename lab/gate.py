"""Puerta antes del push: analiza lo que se va a subir y bloquea lo grave que sea nuevo.

Bloquea los hallazgos de gravedad crítica o alta y cualquier posible secreto, salvo
los que estén en la línea base del repo. La línea base vive en el laboratorio
(`gate/baselines/<repo>.json`), nunca en el repo analizado, y cada entrada exige un
motivo. ZAP no participa: en un push no hay una web en marcha.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable

from lab.normalize import SECRET_CWES
from lab.pipeline import Emit, ScanBusy, ScanRequest, execute
from lab.runners import sonar
from lab.settings import Settings
from lab.store import Store

BLOCKING_SEVERITIES = ("critical", "high")
HISTORY_DIR = ".lab-history"
HISTORY_FILE = f"{HISTORY_DIR}/commits.patch"
REPO_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4}$")
MAX_TAR_BYTES = 500 * 1024 * 1024
MIN_REASON = 10
BUSY_WAIT_S = 900
BUSY_POLL_S = 10


class GateError(Exception):
    """Entrada no válida para la puerta."""


def check_repo_name(name: str) -> str:
    if not REPO_NAME.fullmatch(name or "") or ".." in name:
        raise GateError("Nombre de repo no válido: letras, números, '.', '_' y '-', hasta 100 caracteres")
    return name


def check_run_id(run_id: str) -> str:
    if not RUN_ID.fullmatch(run_id or ""):
        raise GateError("Id de análisis no válido")
    return run_id


def gate_dir(settings: Settings) -> Path:
    return settings.root / "gate"


def baseline_path(settings: Settings, name: str) -> Path:
    return gate_dir(settings) / "baselines" / f"{check_repo_name(name)}.json"


# --- Clave estable -----------------------------------------------------------

def is_secret(finding: dict) -> bool:
    return bool(SECRET_CWES & set(finding.get("cwes") or [])) or "secret" in str(finding.get("rule_id", "")).lower()


def is_blocking(finding: dict) -> bool:
    return finding.get("severity") in BLOCKING_SEVERITIES or is_secret(finding)


def is_history(finding: dict) -> bool:
    return str(finding.get("file", "")).replace("\\", "/").removeprefix("./").startswith(HISTORY_DIR + "/")


def _line_text(src: Path, rel: str, line: int, cache: dict[str, list[str]]) -> str | None:
    """Texto de la línea, sin salir de `src`: las rutas vienen de las herramientas."""
    if not rel or line <= 0:
        return None
    root = src.resolve()
    path = (root / rel).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        return None
    if rel not in cache:
        try:
            cache[rel] = path.read_text(errors="replace").splitlines()
        except OSError:
            cache[rel] = []
    lines = cache[rel]
    return lines[line - 1] if line <= len(lines) else None


def _normalize(text: str, history: bool) -> str:
    if history and text[:1] in "+- ":
        text = text[1:]  # Marca del diff: la misma línea añadida o borrada es el mismo hallazgo.
    return re.sub(r"\s+", "", text)


def baseline_key(finding: dict, src: Path | None = None, cache: dict[str, list[str]] | None = None) -> str:
    """Clave que no cambia si el código se mueve de línea.

    Los `fingerprint` del informe no sirven: Semgrep usa offsets y Sonar la clave del
    issue. Aquí cuenta el contenido de la línea (solo su hash, así un secreto no se
    guarda), y la línea solo si no se puede leer. En el historial no cuenta el archivo,
    porque es un parche distinto en cada push.
    """
    tool, rule = finding.get("tool", ""), finding.get("rule_id", "")
    if tool == "trivy" and not is_secret(finding):
        parts = ["dep", rule, finding.get("title", "")]
    else:
        history = is_history(finding)
        text = None
        if src is not None:
            text = _line_text(src, finding.get("file", ""), int(finding.get("line") or 0), cache if cache is not None else {})
        if text is None and not is_secret(finding):
            snippet = finding.get("snippet") or ""
            text = snippet if snippet and not snippet.startswith("(oculto") else None
        anchor = _normalize(text, history) if text is not None else f"line:{finding.get('line', 0)}"
        parts = ["code", tool, rule, "" if history else finding.get("file", ""), anchor]
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:24]


# --- Línea base ----------------------------------------------------------------

def load_baseline(settings: Settings, name: str) -> dict:
    path = baseline_path(settings, name)
    if not path.exists():
        return {"repo": name, "entries": {}}
    return json.loads(path.read_text())


def save_baseline(settings: Settings, name: str, data: dict) -> None:
    path = baseline_path(settings, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    tmp.replace(path)


def _describe(finding: dict) -> dict:
    location = "historial de commits nuevos" if is_history(finding) else finding.get("file", "")
    return {
        "tool": finding.get("tool", ""),
        "rule_id": finding.get("rule_id", ""),
        "title": finding.get("title", ""),
        "severity": finding.get("severity", ""),
        "secret": is_secret(finding),
        "file": location,
        "line": finding.get("line", 0),
    }


def evaluate(findings: list[dict], baseline: dict, src: Path | None) -> tuple[list[dict], list[dict]]:
    """Devuelve (bloquean y son nuevos, bloquean pero están aceptados), con su clave."""
    cache: dict[str, list[str]] = {}
    new, accepted = [], []
    entries = baseline.get("entries", {})
    seen: set[str] = set()
    for finding in findings:
        if not is_blocking(finding):
            continue
        item = {"key": baseline_key(finding, src, cache), **_describe(finding)}
        if item["key"] in seen:
            continue  # La misma línea añadida y borrada en el historial: un solo hallazgo.
        seen.add(item["key"])
        (accepted if item["key"] in entries else new).append(item)
    return new, accepted


def accept(settings: Settings, name: str, run_id: str, reason: str, keys: list[str] | None = None) -> list[dict]:
    """Acepta los hallazgos que bloquearon en un análisis. Exige un motivo."""
    check_repo_name(name)
    check_run_id(run_id)
    reason = (reason or "").strip()
    if len(reason) < MIN_REASON:
        raise GateError(f"Explica el motivo en al menos {MIN_REASON} caracteres")
    gate_file = settings.runs_dir / run_id / "gate.json"
    if not gate_file.exists():
        raise GateError(f"El análisis {run_id} no es de la puerta")
    result = json.loads(gate_file.read_text())
    if result.get("repo") != name:
        raise GateError(f"El análisis {run_id} es de otro repo")
    chosen = [item for item in result.get("new", []) if not keys or item["key"] in keys]
    if keys and len(chosen) != len(set(keys)):
        raise GateError("Alguna clave no está entre los hallazgos que bloquearon en ese análisis")
    data = load_baseline(settings, name)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for item in chosen:
        data["entries"][item["key"]] = {**{k: v for k, v in item.items() if k != "key"},
                                        "reason": reason, "accepted_at": now, "run_id": run_id}
    save_baseline(settings, name, data)
    return chosen


def remove(settings: Settings, name: str, key: str) -> bool:
    data = load_baseline(settings, name)
    if data["entries"].pop(key, None) is None:
        return False
    save_baseline(settings, name, data)
    return True


# --- Entrada por tar -------------------------------------------------------------

def read_tar(stream: BinaryIO, dest: Path, max_bytes: int = MAX_TAR_BYTES) -> None:
    """Extrae un tar recibido por stdin con el filtro `data` de tarfile.

    El filtro quita la barra inicial de las rutas absolutas y rechaza `..`, enlaces que
    salgan de `dest`, dispositivos y permisos especiales. El tamaño se limita antes de abrirlo.
    """
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile(dir=dest.parent) as buffer:
        total = 0
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise GateError(f"El código enviado supera {max_bytes // (1024 * 1024)} MB")
            buffer.write(chunk)
        if total == 0:
            raise GateError("No llegó ningún código")
        buffer.seek(0)
        try:
            with tarfile.open(fileobj=buffer, mode="r:") as archive:
                archive.extractall(dest, filter="data")
        except (tarfile.TarError, OSError) as exc:
            raise GateError(f"El tar recibido no es válido: {exc}") from exc


# --- Ejecución ---------------------------------------------------------------------

def _execute_waiting(request: ScanRequest, settings: Settings, store: Store, emit: Emit | None,
                     wait_s: int, sleep: Callable[[float], None]) -> dict:
    deadline = time.monotonic() + wait_s
    announced = False
    while True:
        try:
            return execute(request, settings, store, emit=emit)
        except ScanBusy:
            if time.monotonic() >= deadline:
                raise
            if emit and not announced:
                emit("source", "waiting", "Hay otro análisis en curso; espero a que termine")
                announced = True
            sleep(BUSY_POLL_S)


def run_gate(path: Path, name: str, settings: Settings, store: Store, emit: Emit | None = None,
             wait_s: int = BUSY_WAIT_S, sleep: Callable[[float], None] = time.sleep) -> dict:
    check_repo_name(name)
    if not path.is_dir():
        raise GateError(f"No existe el directorio {path}")
    request = ScanRequest(local_path=str(path), label=f"Push de {name}")
    result = _execute_waiting(request, settings, store, emit, wait_s, sleep)
    run_id, out_dir = result["run_id"], Path(result["out_dir"])
    try:
        report = json.loads((out_dir / "findings.json").read_text())
    except (OSError, ValueError):
        report = {"findings": []}
    new, accepted = evaluate(report.get("findings", []), load_baseline(settings, name), path)
    gate = {
        "repo": name, "run_id": run_id, "status": result["status"],
        "blocked": bool(new) or result["status"] != "ok",
        "new": new, "accepted": accepted,
        "history_included": (path / HISTORY_FILE).is_file(),
    }
    (out_dir / "gate.json").write_text(json.dumps(gate, indent=2, ensure_ascii=False))
    if settings.sonar_token:
        try:
            sonar.delete_project(settings.sonar_url, settings.sonar_token, sonar.project_key(run_id))
        except Exception:  # noqa: BLE001 - no impide el resultado; queda el proyecto en Sonar
            pass
    return {**gate, "summary": result["summary"], "out_dir": str(out_dir)}


def run_gate_from_tar(stream: BinaryIO, name: str, settings: Settings, store: Store,
                      emit: Emit | None = None) -> dict:
    check_repo_name(name)
    work_root = gate_dir(settings) / "incoming"
    work_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=work_root))
    try:
        src = work / "src"
        read_tar(stream, src)
        return run_gate(src, name, settings, store, emit)
    finally:
        shutil.rmtree(work, ignore_errors=True)
