"""Configuración: .env del laboratorio, con prioridad para las variables de entorno."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


@dataclass
class Settings:
    root: Path
    runs_dir: Path
    rules_dir: Path
    sonar_url: str
    sonar_token: str
    web_token: str
    # Token de solo lectura para clonar repos privados de GitHub. Nunca sale de github.com.
    github_token: str = ""

    @property
    def db_path(self) -> Path:
        return self.runs_dir / "lab.db"


def load_settings(root: Path = ROOT) -> Settings:
    values = {**_read_env_file(root / ".env"), **os.environ}
    runs_dir = Path(values.get("LAB_RUNS_DIR", root / "runs"))
    runs_dir.mkdir(parents=True, exist_ok=True)
    return Settings(
        root=root,
        runs_dir=runs_dir,
        rules_dir=root / "rules",
        sonar_url=values.get("SONAR_URL", "http://127.0.0.1:9000"),
        sonar_token=values.get("SONAR_TOKEN", ""),
        web_token=values.get("LAB_WEB_TOKEN", ""),
        github_token=values.get("LAB_GITHUB_TOKEN", ""),
    )
