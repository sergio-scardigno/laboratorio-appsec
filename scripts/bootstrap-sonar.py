#!/usr/bin/env python3
"""Secretos del laboratorio y configuración inicial de SonarQube.

  bootstrap-sonar.py init-env    crea .env (modo 600) con secretos aleatorios
  bootstrap-sonar.py configure   espera a Sonar, cambia la contraseña de admin y
                                 genera el token de análisis

Ambos se pueden repetir: no sobrescriben lo que ya es válido. Nunca imprime secretos.
Solo usa la biblioteca estándar, porque corre antes de crear el venv.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = Path(os.environ.get("LAB_ENV_FILE", ROOT / ".env"))
DEFAULT_URL = "http://127.0.0.1:9000"
TOKEN_NAME = "appsec-lab"
STARTUP_TIMEOUT_S = int(os.environ.get("SONAR_STARTUP_TIMEOUT", "600"))


def read_env() -> dict[str, str]:
    if not ENV_FILE.exists():
        return {}
    values = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def write_env(values: dict[str, str]) -> None:
    """Escribe .env de forma atómica y sin ventana con permisos abiertos."""
    tmp = ENV_FILE.with_name(ENV_FILE.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, ENV_FILE)


def new_secret() -> str:
    # El alfabeto de token_urlsafe no necesita escape en .env ni en compose.
    return secrets.token_urlsafe(24)


def new_sonar_password() -> str:
    # Sonar exige mayúscula, minúscula, dígito y carácter especial.
    return secrets.token_urlsafe(24) + "aA1-"


def init_env() -> int:
    values = read_env()
    defaults = {
        "POSTGRES_PASSWORD": new_secret,
        "SONAR_ADMIN_PASSWORD": new_sonar_password,
        "LAB_WEB_TOKEN": new_secret,
    }
    for key, factory in defaults.items():
        if not values.get(key):
            values[key] = factory()
    values.setdefault("SONAR_URL", DEFAULT_URL)
    values.setdefault("SONAR_TOKEN", "")
    write_env(values)
    print(f"Secretos listos en {ENV_FILE} (modo 600)")
    return 0


class Sonar:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def call(self, path: str, auth=None, data: dict | None = None):
        """Devuelve (status, json o None). auth es (usuario, clave) o (token, '')."""
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.base_url + path, data=body)
        if auth:
            raw = f"{auth[0]}:{auth[1]}".encode()
            req.add_header("Authorization", "Basic " + base64.b64encode(raw).decode())
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status, payload = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, exc.read()
        try:
            return status, json.loads(payload) if payload else None
        except ValueError:
            return status, None

    def wait_until_up(self) -> None:
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        last = "sin respuesta"
        while time.monotonic() < deadline:
            try:
                _, payload = self.call("/api/system/status")
                last = (payload or {}).get("status", "desconocido")
                if last == "UP":
                    return
            except OSError as exc:
                last = f"sin conexión ({exc})"
            print(f"  Sonar todavía no está listo: {last}")
            time.sleep(5)
        raise SystemExit(f"Sonar no arrancó en {STARTUP_TIMEOUT_S}s (último estado: {last})")

    def is_valid(self, auth) -> bool:
        status, payload = self.call("/api/authentication/validate", auth=auth)
        return status == 200 and bool((payload or {}).get("valid"))


def configure() -> int:
    values = read_env()
    password = values.get("SONAR_ADMIN_PASSWORD")
    if not password:
        print("Falta SONAR_ADMIN_PASSWORD: ejecuta primero init-env", file=sys.stderr)
        return 1

    sonar = Sonar(values.get("SONAR_URL") or DEFAULT_URL)
    print("Esperando a SonarQube…")
    sonar.wait_until_up()

    admin = ("admin", password)
    if not sonar.is_valid(admin):
        default = ("admin", "admin")
        if not sonar.is_valid(default):
            print(
                "Ni la contraseña de .env ni la de fábrica son válidas para admin.",
                file=sys.stderr,
            )
            return 1
        status, payload = sonar.call(
            "/api/users/change_password",
            auth=default,
            data={"login": "admin", "previousPassword": "admin", "password": password},
        )
        if status not in (200, 204) or not sonar.is_valid(admin):
            print(f"No se pudo cambiar la contraseña (HTTP {status}): {payload}", file=sys.stderr)
            return 1
        print("Contraseña de admin cambiada")

    token = values.get("SONAR_TOKEN")
    if token and sonar.is_valid((token, "")):
        print("El token existente sigue siendo válido")
        return 0

    # Un token con el mismo nombre impediría generar otro; su valor no se puede recuperar.
    sonar.call("/api/user_tokens/revoke", auth=admin, data={"name": TOKEN_NAME})
    status, payload = sonar.call(
        "/api/user_tokens/generate",
        auth=admin,
        data={"name": TOKEN_NAME, "type": "USER_TOKEN"},
    )
    new_token = (payload or {}).get("token")
    if status != 200 or not new_token:
        print(f"No se pudo generar el token (HTTP {status})", file=sys.stderr)
        return 1
    if not sonar.is_valid((new_token, "")):
        print("El token generado no pasa la validación", file=sys.stderr)
        return 1

    values["SONAR_TOKEN"] = new_token
    write_env(values)
    print("Token de análisis generado y guardado en .env")
    return 0


def main() -> int:
    commands = {"init-env": init_env, "configure": configure}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print(f"Uso: {sys.argv[0]} {{{'|'.join(commands)}}}", file=sys.stderr)
        return 2
    return commands[sys.argv[1]]()


if __name__ == "__main__":
    sys.exit(main())
