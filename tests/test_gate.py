import io
import json
import tarfile

import pytest

from lab import gate
from lab.pipeline import ScanBusy
from lab.settings import Settings
from lab.store import Store


@pytest.fixture
def settings(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    return Settings(root=tmp_path, runs_dir=runs, rules_dir=tmp_path / "rules",
                    sonar_url="http://127.0.0.1:9", sonar_token="", web_token="t")


def code_finding(**kw):
    base = {"tool": "semgrep", "rule_id": "sqli", "title": "Inyección SQL", "severity": "high",
            "cwes": [89], "file": "app/db.py", "line": 2, "snippet": ""}
    return {**base, **kw}


def secret_finding(**kw):
    base = {"tool": "trivy", "rule_id": "github-pat", "title": "GitHub PAT", "severity": "low",
            "cwes": [798], "file": "config.py", "line": 1, "snippet": "(oculto: posible secreto)"}
    return {**base, **kw}


def test_key_survives_the_code_moving_down(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app/db.py").write_text("import x\nq = 'SELECT ' + uid\n")
    before = gate.baseline_key(code_finding(line=2), tmp_path)
    (tmp_path / "app/db.py").write_text("import x\n\n\n# nuevo\nq  =  'SELECT ' + uid\n")
    assert gate.baseline_key(code_finding(line=5), tmp_path) == before


def test_key_changes_when_the_flagged_line_changes(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app/db.py").write_text("import x\nq = 'SELECT ' + uid\n")
    before = gate.baseline_key(code_finding(), tmp_path)
    (tmp_path / "app/db.py").write_text("import x\nq = 'DELETE ' + uid\n")
    assert gate.baseline_key(code_finding(), tmp_path) != before


def test_key_never_reads_outside_the_source(tmp_path):
    (tmp_path / "outside.txt").write_text("fuera\n")
    src = tmp_path / "src"
    src.mkdir()
    key = gate.baseline_key(code_finding(file="../outside.txt", line=1), src)
    assert key == gate.baseline_key(code_finding(file="../outside.txt", line=1), None)


def test_secret_key_does_not_fall_back_to_the_hidden_snippet(tmp_path):
    (tmp_path / "config.py").write_text("TOKEN = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n")
    with_src = gate.baseline_key(secret_finding(), tmp_path)
    (tmp_path / "config.py").write_text("TOKEN = 'ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'\n")
    assert gate.baseline_key(secret_finding(), tmp_path) != with_src


def test_dependency_key_ignores_the_line():
    dep = {"tool": "trivy", "rule_id": "CVE-1", "title": "CVE-1 en lodash 4.0.0", "severity": "high",
           "cwes": [1395], "file": "package-lock.json", "line": 0}
    assert gate.baseline_key(dep) == gate.baseline_key({**dep, "line": 99})


def test_history_key_is_the_same_for_added_and_removed_lines(tmp_path):
    hist = tmp_path / ".lab-history"
    hist.mkdir()
    (hist / "commits.patch").write_text("+TOKEN = 'abc'\n-TOKEN = 'abc'\n")
    added = gate.baseline_key(secret_finding(file=".lab-history/commits.patch", line=1), tmp_path)
    removed = gate.baseline_key(secret_finding(file=".lab-history/commits.patch", line=2), tmp_path)
    assert added == removed


@pytest.mark.parametrize("finding,blocks", [
    (code_finding(severity="critical"), True),
    (code_finding(severity="high"), True),
    (code_finding(severity="medium"), False),
    (code_finding(severity="info", cwes=[798]), True),
    (code_finding(severity="low", rule_id="generic-secret", cwes=[]), True),
])
def test_blocking_rules(finding, blocks):
    assert gate.is_blocking(finding) is blocks


def test_baseline_lets_accepted_findings_through_and_blocks_new_ones(tmp_path):
    accepted = code_finding(file="a.py", line=1)
    fresh = code_finding(file="b.py", line=1)
    baseline = {"entries": {gate.baseline_key(accepted): {}}}
    new, ok = gate.evaluate([accepted, fresh, code_finding(severity="low")], baseline, None)
    assert [i["file"] for i in new] == ["b.py"]
    assert [i["file"] for i in ok] == ["a.py"]


def write_gate_run(settings, run_id, repo, new):
    folder = settings.runs_dir / run_id
    folder.mkdir()
    (folder / "gate.json").write_text(json.dumps({"repo": repo, "new": new}))


def test_accept_requires_a_reason(settings):
    write_gate_run(settings, "20261107-120000-abcd", "mi-app", [{"key": "k1", "title": "t"}])
    with pytest.raises(gate.GateError):
        gate.accept(settings, "mi-app", "20261107-120000-abcd", "porque sí")


def test_accept_adds_to_the_baseline_and_checks_the_repo(settings):
    run_id = "20261107-120000-abcd"
    write_gate_run(settings, run_id, "mi-app", [{"key": "k1", "title": "t", "file": "a.py"}])
    with pytest.raises(gate.GateError):
        gate.accept(settings, "otro", run_id, "falso positivo comprobado a mano")
    gate.accept(settings, "mi-app", run_id, "falso positivo comprobado a mano")
    entry = gate.load_baseline(settings, "mi-app")["entries"]["k1"]
    assert entry["reason"] == "falso positivo comprobado a mano"
    assert entry["run_id"] == run_id
    assert gate.remove(settings, "mi-app", "k1")
    assert gate.load_baseline(settings, "mi-app")["entries"] == {}


def test_accept_rejects_unknown_keys(settings):
    write_gate_run(settings, "20261107-120000-abcd", "mi-app", [{"key": "k1", "title": "t"}])
    with pytest.raises(gate.GateError):
        gate.accept(settings, "mi-app", "20261107-120000-abcd", "falso positivo comprobado", ["nope"])


@pytest.mark.parametrize("name", ["", "../x", ".oculto", "a/b", "a b", "x" * 101, "a..b"])
def test_repo_names_that_could_escape_are_refused(name):
    with pytest.raises(gate.GateError):
        gate.check_repo_name(name)


def make_tar(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    buffer.seek(0)
    return buffer


def test_read_tar_extracts_regular_files(tmp_path):
    gate.read_tar(make_tar([("app/main.py", b"print(1)\n")]), tmp_path / "src")
    assert (tmp_path / "src/app/main.py").read_text() == "print(1)\n"


def test_read_tar_refuses_parent_paths(tmp_path):
    with pytest.raises(gate.GateError):
        gate.read_tar(make_tar([("../fuera.txt", b"x")]), tmp_path / "src")
    assert not (tmp_path / "fuera.txt").exists()


def test_read_tar_keeps_absolute_paths_inside(tmp_path):
    gate.read_tar(make_tar([("/fuera.txt", b"x")]), tmp_path / "src")
    assert (tmp_path / "src/fuera.txt").exists()
    assert not (tmp_path / "fuera.txt").exists()


def test_read_tar_refuses_links_outside(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        archive.addfile(info)
    buffer.seek(0)
    with pytest.raises(gate.GateError):
        gate.read_tar(buffer, tmp_path / "src")


def test_read_tar_limits_the_size(tmp_path):
    with pytest.raises(gate.GateError):
        gate.read_tar(make_tar([("big.bin", b"x" * 4096)]), tmp_path / "src", max_bytes=1024)


def test_read_tar_refuses_empty_input(tmp_path):
    with pytest.raises(gate.GateError):
        gate.read_tar(io.BytesIO(b""), tmp_path / "src")


def fake_execute(settings, findings, status="ok", busy_times=0):
    calls = {"n": 0}

    def execute(request, settings_, store, emit=None):
        calls["n"] += 1
        if calls["n"] <= busy_times:
            raise ScanBusy("ocupado")
        run_id = "20261107-120000-abcd"
        out = settings.runs_dir / run_id
        out.mkdir(exist_ok=True)
        (out / "findings.json").write_text(json.dumps({"findings": findings}))
        return {"run_id": run_id, "status": status, "summary": {"total": len(findings), "tools": {}},
                "out_dir": str(out), "request": request}

    return execute, calls


def test_run_gate_blocks_new_findings_and_records_them(settings, tmp_path, monkeypatch):
    src = tmp_path / "push"
    src.mkdir()
    execute, _ = fake_execute(settings, [code_finding(), code_finding(severity="low")])
    monkeypatch.setattr(gate, "execute", execute)
    result = gate.run_gate(src, "mi-app", settings, Store(settings.db_path))
    assert result["blocked"] and len(result["new"]) == 1
    saved = json.loads((settings.runs_dir / result["run_id"] / "gate.json").read_text())
    assert saved["repo"] == "mi-app" and saved["new"][0]["key"] == result["new"][0]["key"]


def test_run_gate_blocks_an_incomplete_scan(settings, tmp_path, monkeypatch):
    src = tmp_path / "push"
    src.mkdir()
    execute, _ = fake_execute(settings, [], status="partial")
    monkeypatch.setattr(gate, "execute", execute)
    result = gate.run_gate(src, "mi-app", settings, Store(settings.db_path))
    assert result["blocked"] and not result["new"]


def test_run_gate_waits_for_another_scan(settings, tmp_path, monkeypatch):
    src = tmp_path / "push"
    src.mkdir()
    execute, calls = fake_execute(settings, [], busy_times=2)
    monkeypatch.setattr(gate, "execute", execute)
    sleeps = []
    result = gate.run_gate(src, "mi-app", settings, Store(settings.db_path), sleep=sleeps.append)
    assert not result["blocked"] and calls["n"] == 3 and len(sleeps) == 2


def test_run_gate_gives_up_waiting(settings, tmp_path, monkeypatch):
    src = tmp_path / "push"
    src.mkdir()
    execute, _ = fake_execute(settings, [], busy_times=99)
    monkeypatch.setattr(gate, "execute", execute)
    with pytest.raises(ScanBusy):
        gate.run_gate(src, "mi-app", settings, Store(settings.db_path), wait_s=0, sleep=lambda s: None)


def test_run_gate_from_tar_cleans_up(settings, monkeypatch):
    execute, _ = fake_execute(settings, [])
    monkeypatch.setattr(gate, "execute", execute)
    gate.run_gate_from_tar(make_tar([("a.py", b"x = 1\n")]), "mi-app", settings, Store(settings.db_path))
    assert list((settings.root / "gate" / "incoming").iterdir()) == []


def test_the_same_history_line_counts_once(tmp_path):
    hist = tmp_path / ".lab-history"
    hist.mkdir()
    (hist / "commits.patch").write_text("+TOKEN = 'abc'\n-TOKEN = 'abc'\n")
    findings = [secret_finding(file=".lab-history/commits.patch", line=n) for n in (1, 2)]
    new, _ = gate.evaluate(findings, {"entries": {}}, tmp_path)
    assert len(new) == 1
