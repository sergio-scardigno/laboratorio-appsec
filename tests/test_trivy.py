import json
import subprocess
from pathlib import Path

import pytest

from lab import images
from lab.runners import trivy
from lab.runners.base import DockerOutcome

ROOT = Path(__file__).resolve().parent.parent
REPORT = {"Results": [{"Target": "a.key", "Secrets": [{"RuleID": "k", "Match": "SECRETO", "Code": {"Lines": ["SECRETO"]}, "StartLine": 1}]}]}


def test_image_is_pinned_by_digest_and_not_a_compromised_version():
    assert "@sha256:" in images.TRIVY
    for bad in ("0.69.4", "0.69.5", "0.69.6", ":latest"):
        assert bad not in images.TRIVY


def test_juice_shop_image_matches_compose_and_the_cloned_tag():
    assert f"image: {images.JUICE_SHOP_IMAGE}\n" in (ROOT / "compose.yaml").read_text()
    assert f":{images.JUICE_SHOP_TAG}@" in images.JUICE_SHOP_IMAGE


def test_find_lockfiles_ignores_dependencies_folders(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "node_modules/x").mkdir(parents=True)
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "sub/go.mod").write_text("")
    (tmp_path / "node_modules/x/yarn.lock").write_text("")
    (tmp_path / "package.json").write_text("{}")
    assert trivy.find_lockfiles(tmp_path) == ["package-lock.json", "sub/go.mod"]


@pytest.fixture
def docker(monkeypatch):
    """Registra cada contenedor sin ejecutar Docker."""
    calls = {"scan": [], "quiet": []}

    def fake_docker_run(name, image, docker_args, command, *, timeout_s, stdout_path, stderr_path, env=None):
        calls["scan"].append({"name": name, "image": image, "args": docker_args, "command": command, "env": env})
        Path(stdout_path).write_text(json.dumps(REPORT))
        Path(stderr_path).write_text("")
        return DockerOutcome(0, False, 1.0)

    monkeypatch.setattr(trivy, "docker_run", fake_docker_run)
    monkeypatch.setattr(trivy, "update_db", lambda: "")
    monkeypatch.setattr(trivy, "database_info", lambda: {"UpdatedAt": "2026-11-05T19:00:00Z"})
    return calls


def test_scan_has_no_network_no_secrets_and_no_docker_socket(tmp_path, docker):
    (tmp_path / "out").mkdir()
    (tmp_path / "src").mkdir()
    assert trivy.run(tmp_path / "src", tmp_path / "out", "r").status == "ok"
    call = docker["scan"][0]
    args = " ".join(call["args"])
    assert "--network none" in args
    assert "docker.sock" not in args
    assert not call["env"]
    assert f"{tmp_path / 'src'}:/src:ro" in args
    assert f"{trivy.CACHE_VOLUME}:{trivy.CACHE_DIR}:ro" in args
    assert "-w /" in args  # Fuera del código: no lee trivy.yaml ni .trivyignore del repo.


def test_secret_values_are_not_written_to_disk(tmp_path, docker):
    (tmp_path / "src").mkdir()
    trivy.run(tmp_path / "src", tmp_path, "r")
    assert "SECRETO" not in (tmp_path / "trivy.json").read_text()
    assert not list(tmp_path.glob("*.raw"))


def test_no_lockfile_warns_that_dependencies_were_not_analyzed(tmp_path, docker):
    (tmp_path / "src").mkdir()
    trivy.run(tmp_path / "src", tmp_path, "r")
    warnings = json.loads((tmp_path / "trivy.json").read_text())["warnings"]
    assert "no significa que no haya" in warnings[0]


def test_clean_lockfile_does_not_warn(tmp_path, docker):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/package-lock.json").write_text("{}")
    trivy.run(tmp_path / "src", tmp_path, "r")
    assert json.loads((tmp_path / "trivy.json").read_text())["warnings"] == []


def test_db_update_failure_with_a_previous_db_warns_with_its_date(tmp_path, docker, monkeypatch):
    monkeypatch.setattr(trivy, "update_db", lambda: "sin red")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/yarn.lock").write_text("")
    assert trivy.run(tmp_path / "src", tmp_path, "r").status == "ok"
    warnings = json.loads((tmp_path / "trivy.json").read_text())["warnings"]
    assert "2026-11-05" in warnings[0] and "pueden faltar" in warnings[0]


def test_db_update_failure_without_any_db_is_an_error(tmp_path, docker, monkeypatch):
    monkeypatch.setattr(trivy, "update_db", lambda: "sin red")
    monkeypatch.setattr(trivy, "database_info", lambda: {})
    (tmp_path / "src").mkdir()
    result = trivy.run(tmp_path / "src", tmp_path, "r")
    assert result.status == "error" and "No hay base" in result.message
    assert docker["scan"] == []


def test_preset_image_is_saved_scanned_and_removed(tmp_path, docker, monkeypatch):
    def fake_save(argv, **kwargs):
        assert argv[:2] == ["docker", "save"] and argv[2] == images.JUICE_SHOP_IMAGE
        Path(argv[4]).write_text("tar")
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(trivy.subprocess, "run", fake_save)
    (tmp_path / "src").mkdir()
    result = trivy.run(tmp_path / "src", tmp_path, "r", image_ref=images.JUICE_SHOP_IMAGE)
    assert result.status == "ok" and len(docker["scan"]) == 2
    assert "/image.tar:ro" in " ".join(docker["scan"][1]["args"])
    assert not (tmp_path / "trivy-image.tar").exists()
    warnings = json.loads((tmp_path / "trivy.json").read_text())["warnings"]
    assert warnings == ["El repo no trae lockfile: sus dependencias se analizaron en la imagen"]


def test_failed_scan_raises_with_the_reason(tmp_path, docker, monkeypatch):
    def failing(name, image, docker_args, command, *, timeout_s, stdout_path, stderr_path, env=None):
        Path(stdout_path).write_text("salida parcial con SECRETO")
        Path(stderr_path).write_text("fallo de prueba")
        return DockerOutcome(1, False, 1.0)

    monkeypatch.setattr(trivy, "docker_run", failing)
    (tmp_path / "src").mkdir()
    with pytest.raises(RuntimeError, match="fallo de prueba"):
        trivy.run(tmp_path / "src", tmp_path, "r")
    assert not list(tmp_path.glob("*.raw"))


def test_db_update_container_does_not_see_the_code(monkeypatch):
    seen = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(trivy.subprocess, "run", fake_run)
    assert trivy.update_db() == ""
    assert len(seen) == 2
    for argv in seen:
        joined = " ".join(argv)
        assert ":/src" not in joined and "docker.sock" not in joined and " -e " not in joined
        assert "--cap-drop ALL" in joined
