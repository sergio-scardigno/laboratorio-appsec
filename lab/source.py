"""Obtención del código a analizar. Nunca se compila ni se ejecuta nada del repo."""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

# Archivos con los que un repo podría ocultar su propio código a los escáneres.
SCANNER_CONTROL_FILES = {
    ".semgrepignore", "sonar-project.properties",
    ".trivyignore", ".trivyignore.yaml", "trivy.yaml", "trivy-secret.yaml",
}


class SourceError(Exception):
    pass


def validate_repo_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise SourceError("Solo se admiten repos https://")
    if parsed.username or parsed.password:
        raise SourceError("La URL del repo no debe llevar credenciales")


GITHUB_HOST = "github.com"


def github_auth_env(url: str, token: str) -> dict[str, str]:
    """Credencial para git solo si el repo está en github.com.

    Va por variables de entorno: ni en la URL, que acaba en logs e historial, ni en
    argumentos, que cualquier usuario ve con ps. La cabecera se limita a github.com.
    """
    if not token or urlparse(url).hostname != GITHUB_HOST:
        return {}
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": f"http.https://{GITHUB_HOST}/.extraheader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
    }


_AUTH_ERRORS = ("could not read Username", "Authentication failed", "returned error: 401", "returned error: 403")


def clone(url: str, dest: Path, ref: str | None = None, timeout_s: int = 600, github_token: str = "") -> str:
    """Clona el repo. Devuelve un aviso si hubo que prescindir del token, o una cadena vacía.

    Un token caducado o revocado hace fallar también los repos públicos, porque GitHub
    rechaza la credencial antes de mirar el repo. Por eso se reintenta sin él.
    """
    validate_repo_url(url)
    auth = github_auth_env(url, github_token)
    result = _run_clone(url, dest, ref, timeout_s, auth)
    if result.returncode == 0:
        return ""
    if auth and any(marker in result.stderr for marker in _AUTH_ERRORS):
        shutil.rmtree(dest, ignore_errors=True)
        retry = _run_clone(url, dest, ref, timeout_s, {})
        if retry.returncode == 0:
            return "GitHub rechazó LAB_GITHUB_TOKEN y el repo se clonó sin él: renueva o quita ese token de .env"
        raise SourceError(
            "No se pudo clonar el repo. GitHub rechazó LAB_GITHUB_TOKEN, o caducó o no tiene acceso a este "
            "repo, y sin el token tampoco se puede leer, así que probablemente es privado"
        )
    message = f"git clone falló: {result.stderr.strip()[-400:]}"
    if any(marker in result.stderr for marker in _AUTH_ERRORS) or "not found" in result.stderr:
        message += ". Si el repo es privado, pon un token de solo lectura en LAB_GITHUB_TOKEN (.env)"
    raise SourceError(message)


def _run_clone(
    url: str, dest: Path, ref: str | None, timeout_s: int, auth: dict[str, str]
) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_TEMPLATE_DIR": "",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        **auth,
    }
    argv = [
        "git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false",
        "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
        "clone", "--quiet", "--depth", "1", "--no-recurse-submodules",
    ]
    if ref:
        argv += ["--branch", ref]
    argv += ["--", url, str(dest)]
    try:
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        raise SourceError(f"git clone superó {timeout_s}s") from exc


def sanitize(src: Path) -> list[str]:
    """Quita .git y los archivos de control de los escáneres. Devuelve lo que borró."""
    removed = []
    git_dir = src / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir)
    for path in src.rglob("*"):
        if path.is_file() and path.name in SCANNER_CONTROL_FILES:
            removed.append(str(path.relative_to(src)))
            path.unlink()
    return removed


def copy_local(path: Path, dest: Path) -> None:
    """Copia un directorio local (solo CLI), sin seguir enlaces simbólicos."""
    if not path.is_dir():
        raise SourceError(f"No existe el directorio {path}")
    shutil.copytree(path, dest, symlinks=True, ignore=shutil.ignore_patterns("node_modules", ".git"))
