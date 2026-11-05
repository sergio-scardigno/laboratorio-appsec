from lab.models import Finding, Instance
from lab.report import build_matrix, headline, safe_url, summarize, write_report
from lab.runners.base import ToolResult

PAYLOAD = "<script>alert(1)</script>"


def results(**overrides):
    base = {name: ToolResult(name, "ok") for name in ("semgrep", "sonar", "zap")}
    base.update(overrides)
    return base


def meta(status="ok"):
    return {
        "run_id": "r", "target": PAYLOAD, "request": {"active": False}, "status": status, "duration_s": 60,
        "generated_at": "2026-11-04T21:00:00+00:00", "stats": {}, "merged": 0, "correlated": 0,
        "warnings": [PAYLOAD], "removed_control_files": [],
    }


def finding(**kwargs):
    defaults = dict(fingerprint="f", tool="zap", rule_id="r", title="T", severity="high", categories=["A05:2025"], cwes=[79])
    return Finding(**{**defaults, **kwargs})


def test_scanned_content_is_escaped(tmp_path):
    evil = finding(
        title=PAYLOAD, message=PAYLOAD, solution=PAYLOAD, snippet=PAYLOAD, rule_id=PAYLOAD,
        instances=[Instance(url="javascript:alert(1)", param=PAYLOAD, evidence=PAYLOAD)], instance_count=1,
    )
    write_report(tmp_path, meta(), results(), [evil])
    html = (tmp_path / "report.html").read_text()
    assert PAYLOAD not in html
    assert 'href="javascript:' not in html


def test_report_has_a_nonce_csp(tmp_path):
    write_report(tmp_path, meta(), results(), [finding()])
    html = (tmp_path / "report.html").read_text()
    assert "default-src 'none'" in html and "script-src 'nonce-" in html


def test_safe_url():
    assert safe_url("https://x") == "https://x"
    assert safe_url("JaVaScRiPt:alert(1)") == "#"
    assert safe_url("data:text/html,x") == "#"


def test_zero_skipped_and_failed_cells_are_different():
    rows = build_matrix([], results(sonar=ToolResult("sonar", "skipped"), zap=ToolResult("zap", "error")))
    assert [c["state"] for c in rows[0]["cells"]] == ["ok", "skipped", "error"]


def test_matrix_has_every_category_even_without_findings():
    rows = build_matrix([], results())
    assert [r["id"] for r in rows][:2] == ["A01:2025", "A02:2025"]
    assert len(rows) == 11 and rows[-1]["id"] == "Sin mapear"
    assert all(r["coverage"] for r in rows[:10])


def test_merged_finding_counts_for_both_tools():
    merged = finding(tool="semgrep", also_found_by=[{"tool": "sonar", "rule_id": "x", "title": "x", "line": 1, "severity": "low"}])
    row = build_matrix([merged], results())[4]
    assert {c["tool"]: c["count"] for c in row["cells"]} == {"semgrep": 1, "sonar": 1, "zap": 0}
    assert row["total"] == 1


def test_finding_in_two_categories_counts_once_in_the_total():
    summary = summarize([finding(categories=["A01:2025", "A05:2025"])], results(), "ok")
    assert summary["total"] == 1
    assert summary["by_category"] == {"A01:2025": 1, "A05:2025": 1}


def test_headline_does_not_call_an_empty_result_clean():
    summary = summarize([], results(), "ok")
    assert "limpi" not in headline(summary).lower() and "segur" not in headline(summary).lower()


def test_headline_when_everything_failed():
    assert "no ha podido" in headline(summarize([], results(), "error"))


def test_decoded_html_from_zap_is_escaped_again_in_the_report(tmp_path, zap_raw):
    from lab.normalize import parse_zap

    zap_raw["site"][0]["alerts"][0]["solution"] = "&lt;script&gt;alert(1)&lt;/script&gt;"
    write_report(tmp_path, meta(), results(), parse_zap(zap_raw).findings)
    assert "<script>alert(1)</script>" not in (tmp_path / "report.html").read_text()
