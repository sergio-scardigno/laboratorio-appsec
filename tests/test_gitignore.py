import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / ".git").exists(), reason="Hace falta el repo de git"
)


def is_ignored(path: str) -> bool:
    return subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=ROOT).returncode == 0


@pytest.mark.parametrize("path", [
    # Secretos
    ".env", ".env.local", ".env.tmp", "sub/.env", "server.pem", "private.key", "cert.p12", "cert.pfx",
    "store.jks", "app.keystore", "id_rsa", "id_rsa.pub", "id_ed25519", "api.token", ".netrc",
    ".git-credentials", "credentials.json", "secrets.yaml",
    # Resultados
    "runs/x/report.html", "runs/lab.db", "lab.db", "data.sqlite", "out.sarif", "scan.log",
    "findings.json", "report.html", "zap.html", "zap.json", "semgrep.json", "sonar.json",
    "trivy.json", "trivy-image.tar.log", ".scannerwork/report-task.txt",
    # Descargas y cachés
    "rules/default.yaml", ".cache/x", ".trivycache/db", ".venv/bin/lab",
    # Editores y privado
    "..env.swp", "a.swo", "a~", ".vscode/settings.json", ".idea/x", ".DS_Store",
    "publicacion/privado.md",
])
def test_sensitive_files_and_results_are_ignored(path):
    assert is_ignored(path), path


@pytest.mark.parametrize("path", [
    ".env.example", "tests/fixtures/zap.json", "tests/fixtures/semgrep.json", "tests/fixtures/sonar.json",
    "tests/fixtures/trivy.json", "lab/templates/report.html", "data/owasp2025_cwe.json", "lab/report.py",
    "lab/runners/trivy.py", "lab/runners/zap.py", "README.md", "docs/img/informe-matriz.png",
])
def test_project_files_are_not_ignored(path):
    assert not is_ignored(path), path


def test_no_tracked_file_is_ignored():
    result = subprocess.run(
        ["git", "ls-files", "-ci", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    assert result.stdout == ""
