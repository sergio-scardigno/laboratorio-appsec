"""Utilidades comunes para lanzar escáneres en contenedores efímeros."""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

# Límites para todo escáner: analizan código y webs no confiables.
HARDENING = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "2048"]


@dataclass
class ToolResult:
    tool: str
    status: str  # ok | error | skipped
    duration_s: float = 0.0
    raw_files: list[str] = field(default_factory=list)
    message: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class DockerOutcome:
    returncode: int
    timed_out: bool
    duration_s: float


def docker_run(
    container_name: str,
    image: str,
    docker_args: list[str],
    command: list[str],
    *,
    timeout_s: int,
    stdout_path: Path,
    stderr_path: Path,
    env: dict[str, str] | None = None,
) -> DockerOutcome:
    """Ejecuta un contenedor efímero con límite de tiempo.

    Al vencer el plazo mata el contenedor con `docker kill`: matar solo el cliente
    dejaría el escáner corriendo. Los valores de `env` llegan al contenedor por el
    entorno del cliente, así no aparecen en los argumentos del proceso.
    """
    env_args = [arg for name in (env or {}) for arg in ("-e", name)]
    argv = [
        "docker", "run", "--rm", "--name", container_name,
        *HARDENING, *env_args, *docker_args, image, *command,
    ]
    started = time.monotonic()
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = subprocess.Popen(argv, stdout=out, stderr=err, env={**os.environ, **(env or {})})
        try:
            returncode = proc.wait(timeout=timeout_s)
            timed_out = False
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", container_name], capture_output=True, check=False)
            returncode = proc.wait()
            timed_out = True
    return DockerOutcome(returncode, timed_out, time.monotonic() - started)


def tail(path: Path, lines: int = 6) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])
    except OSError:
        return ""
