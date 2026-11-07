import json

import pytest

from lab import pipeline
from lab.pipeline import ScanRefused, ScanRequest, execute, overall_status, validate
from lab.runners.base import ToolResult
from lab.settings import Settings
from lab.store import Store


def refused(**kwargs):
    with pytest.raises(ScanRefused):
        validate(ScanRequest(**kwargs))


def test_nothing_to_scan_is_refused():
    refused()


def test_external_url_without_authorization_is_refused():
    refused(url="https://example.com")


def test_external_url_with_authorization_is_accepted_in_passive_mode():
    validate(ScanRequest(url="https://example.com", authorized=True))


def test_active_mode_needs_a_second_confirmation():
    refused(url="https://example.com", authorized=True, active=True)
    validate(ScanRequest(url="https://example.com", authorized=True, active=True, active_confirmed=True))


def test_active_confirmation_does_not_replace_authorization():
    refused(url="https://example.com", active=True, active_confirmed=True)


def test_active_without_url_is_refused():
    refused(repo="https://github.com/a/b", active=True)


def test_preset_needs_no_authorization_even_when_active():
    validate(ScanRequest(preset="juice-shop", active=True))


def test_preset_cannot_smuggle_another_target():
    refused(preset="juice-shop", url="https://example.com")
    refused(preset="juice-shop", repo="https://github.com/a/b")


def test_unknown_preset_is_refused():
    refused(preset="otro")


@pytest.mark.parametrize("url", ["ftp://x", "javascript:alert(1)", "-J/etc/passwd", "juice-shop:3000", "https://u:p@x.com"])
def test_bad_target_urls_are_refused(url):
    refused(url=url, authorized=True)


def test_repo_alone_needs_no_web_authorization():
    validate(ScanRequest(repo="https://github.com/a/b"))


def test_overall_status():
    ok, err, skip = ToolResult("a", "ok"), ToolResult("b", "error"), ToolResult("c", "skipped")
    assert overall_status({"a": ok, "c": skip}) == "ok"
    assert overall_status({"a": ok, "b": err}) == "partial"
    assert overall_status({"b": err, "c": skip}) == "error"
    assert overall_status({"c": skip}) == "error"


REAL_PREPARE_SOURCE = pipeline._prepare_source


@pytest.fixture
def lab(tmp_path, monkeypatch, semgrep_raw, sonar_raw, trivy_raw, zap_raw):
    settings = Settings(tmp_path, tmp_path / "runs", tmp_path / "rules", "http://x", "tok", "web")
    settings.runs_dir.mkdir()

    def fake_trivy(src, out, run_id, image_ref=None):
        (out / "trivy.json").write_text(json.dumps(trivy_raw))
        return ToolResult("trivy", "ok", 1, ["trivy.json"], details={"image": image_ref or ""})

    def fake_source(request, dest, github_token="", warnings=None):
        dest.mkdir()
        return []

    def fake_semgrep(src, out, rules, run_id):
        (out / "semgrep.json").write_text(json.dumps(semgrep_raw))
        return ToolResult("semgrep", "ok", 1, ["semgrep.json"])

    def fake_sonar(src, out, run_id, url, token):
        (out / "sonar.json").write_text(json.dumps(sonar_raw))
        return ToolResult("sonar", "ok", 1, ["sonar.json"])

    def fake_zap(url, out, run_id, *, active, network=None):
        (out / "zap.json").write_text(json.dumps(zap_raw))
        return ToolResult("zap", "ok", 1, ["zap.json"], details={"mode": "full" if active else "baseline"})

    monkeypatch.setattr(pipeline, "_prepare_source", fake_source)
    monkeypatch.setattr(pipeline.semgrep, "run", fake_semgrep)
    monkeypatch.setattr(pipeline.sonar, "run", fake_sonar)
    monkeypatch.setattr(pipeline.zap, "run", fake_zap)
    monkeypatch.setattr(pipeline.trivy, "run", fake_trivy)
    monkeypatch.setattr(pipeline, "restart_juice_shop", lambda root: None)
    return settings, Store(settings.db_path)


def test_full_run_all_ok(lab):
    settings, store = lab
    result = execute(ScanRequest(preset="juice-shop"), settings, store)
    assert result["status"] == "ok"
    out = settings.runs_dir / result["run_id"]
    assert (out / "report.html").exists() and not (out / "src").exists()
    data = json.loads((out / "findings.json").read_text())
    assert data["summary"]["total"] == len(data["findings"]) > 0
    assert store.get_run(result["run_id"])["status"] == "ok"


def test_authorization_is_recorded(lab):
    settings, store = lab
    result = execute(ScanRequest(url="https://example.com", authorized=True), settings, store)
    assert store.get_run(result["run_id"])["request"]["authorized"] is True


def test_failed_tool_makes_the_run_partial_and_the_report_says_so(lab, monkeypatch):
    settings, store = lab
    monkeypatch.setattr(pipeline.semgrep, "run", lambda *a, **k: ToolResult("semgrep", "error", message="contenedor eliminado"))
    result = execute(ScanRequest(preset="juice-shop"), settings, store)
    assert result["status"] == "partial"
    html = (settings.runs_dir / result["run_id"] / "report.html").read_text()
    assert "Resultado incompleto" in html and "contenedor eliminado" in html
    assert 'class="cell failed"' in html


def test_tool_crash_does_not_stop_the_others(lab, monkeypatch):
    settings, store = lab

    def boom(*a, **k):
        raise RuntimeError("explotó")

    monkeypatch.setattr(pipeline.sonar, "run", boom)
    result = execute(ScanRequest(preset="juice-shop"), settings, store)
    assert result["status"] == "partial"
    assert result["summary"]["tools"]["zap"]["status"] == "ok"
    assert "explotó" in result["summary"]["tools"]["sonar"]["message"]


def test_unparseable_output_is_an_error_not_an_empty_result(lab, monkeypatch):
    settings, store = lab

    def garbage(src, out, rules, run_id):
        (out / "semgrep.json").write_text("no es json")
        return ToolResult("semgrep", "ok", 1, ["semgrep.json"])

    monkeypatch.setattr(pipeline.semgrep, "run", garbage)
    result = execute(ScanRequest(preset="juice-shop"), settings, store)
    assert result["status"] == "partial"
    assert result["summary"]["tools"]["semgrep"]["status"] == "error"


def test_clone_failure_is_reported(lab, monkeypatch):
    settings, store = lab

    def fail(request, dest, github_token="", warnings=None):
        raise pipeline.source.SourceError("repo inexistente")

    monkeypatch.setattr(pipeline, "_prepare_source", fail)
    result = execute(ScanRequest(repo="https://github.com/a/b"), settings, store)
    assert result["status"] == "error"
    assert "repo inexistente" in result["summary"]["tools"]["semgrep"]["message"]


def test_only_url_does_not_run_sast(lab):
    settings, store = lab
    result = execute(ScanRequest(url="https://example.com", authorized=True), settings, store)
    assert result["summary"]["tools"]["semgrep"]["status"] == "skipped"
    html = (settings.runs_dir / result["run_id"] / "report.html").read_text()
    assert "no se ejecutó" in html


def test_second_scan_at_the_same_time_is_refused(lab):
    import fcntl

    settings, store = lab
    with open(settings.runs_dir / ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with pytest.raises(pipeline.ScanBusy):
            execute(ScanRequest(preset="juice-shop"), settings, store)


def test_github_token_reaches_clone_but_is_never_recorded(lab, monkeypatch):
    settings, store = lab
    settings.github_token = "ghp_secreto"
    seen = {}

    def fake_clone(url, dest, ref=None, github_token=""):
        seen["token"] = github_token
        dest.mkdir()

    monkeypatch.setattr(pipeline, "_prepare_source", REAL_PREPARE_SOURCE)
    monkeypatch.setattr(pipeline.source, "clone", fake_clone)
    result = execute(ScanRequest(repo="https://github.com/org/privado"), settings, store)
    assert seen["token"] == "ghp_secreto"
    out = settings.runs_dir / result["run_id"]
    for path in out.rglob("*"):
        if path.is_file():
            assert "ghp_secreto" not in path.read_text(errors="replace")
    assert "ghp_secreto" not in json.dumps(store.get_run(result["run_id"]))


def test_trivy_runs_with_the_code_and_scans_the_image_only_for_the_preset(lab, monkeypatch):
    settings, store = lab
    seen = []
    real = pipeline.trivy.run

    def spy(src, out, run_id, image_ref=None):
        seen.append(image_ref)
        return real(src, out, run_id, image_ref=image_ref)

    monkeypatch.setattr(pipeline.trivy, "run", spy)
    execute(ScanRequest(preset="juice-shop"), settings, store)
    execute(ScanRequest(repo="https://github.com/a/b"), settings, store)
    assert seen == [pipeline.images.JUICE_SHOP_IMAGE, None]


def test_trivy_findings_reach_the_report(lab):
    settings, store = lab
    result = execute(ScanRequest(preset="juice-shop"), settings, store)
    assert result["summary"]["tools"]["trivy"]["status"] == "ok"
    data = json.loads((settings.runs_dir / result["run_id"] / "findings.json").read_text())
    assert any(f["tool"] == "trivy" and f["categories"] == ["A03:2025"] for f in data["findings"])
    html = (settings.runs_dir / result["run_id"] / "report.html").read_text()
    assert "Trivy" in html and "Aviso de seguridad" in html and "no trae lockfile" in html


def test_trivy_failure_makes_the_run_partial(lab, monkeypatch):
    settings, store = lab

    def boom(*a, **k):
        raise RuntimeError("Trivy cayó")

    monkeypatch.setattr(pipeline.trivy, "run", boom)
    result = execute(ScanRequest(preset="juice-shop"), settings, store)
    assert result["status"] == "partial"
    html = (settings.runs_dir / result["run_id"] / "report.html").read_text()
    assert "Resultado incompleto" in html and "Trivy cayó" in html


def test_url_only_does_not_run_trivy(lab):
    settings, store = lab
    result = execute(ScanRequest(url="https://example.com", authorized=True), settings, store)
    assert result["summary"]["tools"]["trivy"]["status"] == "skipped"


def test_clone_failure_also_marks_trivy(lab, monkeypatch):
    settings, store = lab

    def fail(request, dest, github_token="", warnings=None):
        raise pipeline.source.SourceError("repo inexistente")

    monkeypatch.setattr(pipeline, "_prepare_source", fail)
    result = execute(ScanRequest(repo="https://github.com/a/b"), settings, store)
    assert result["summary"]["tools"]["trivy"]["status"] == "error"


def test_rejected_token_warning_reaches_the_report(lab, monkeypatch):
    settings, store = lab

    def source_with_warning(request, dest, github_token="", warnings=None):
        dest.mkdir()
        warnings.append("GitHub rechazó LAB_GITHUB_TOKEN")
        return []

    monkeypatch.setattr(pipeline, "_prepare_source", source_with_warning)
    result = execute(ScanRequest(repo="https://github.com/a/b"), settings, store)
    assert result["status"] == "ok"
    html = (settings.runs_dir / result["run_id"] / "report.html").read_text()
    assert "GitHub rechazó LAB_GITHUB_TOKEN" in html
