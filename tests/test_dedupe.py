from lab.dedupe import correlate, merge_sast
from lab.models import Finding
from lab.normalize import parse_semgrep, parse_sonar, parse_zap


def make(tool, line=10, cwes=(89,), file="a.ts", severity="medium", fp=None, categories=("A05:2025",)):
    return Finding(fp or f"{tool}-{line}-{file}", tool, "rule", "title", severity, list(categories), list(cwes), file=file, line=line)


def test_same_file_cwe_and_near_line_merge():
    merged = merge_sast([make("semgrep", 10), make("sonar", 13)])
    assert len(merged) == 1 and merged[0].tools == ["semgrep", "sonar"]


def test_line_outside_tolerance_does_not_merge():
    assert len(merge_sast([make("semgrep", 10), make("sonar", 14)])) == 2


def test_different_cwe_does_not_merge():
    assert len(merge_sast([make("semgrep", cwes=(89,)), make("sonar", cwes=(79,))])) == 2


def test_different_file_does_not_merge():
    assert len(merge_sast([make("semgrep", file="a.ts"), make("sonar", file="b.ts")])) == 2


def test_same_tool_never_merges_with_itself():
    assert len(merge_sast([make("semgrep", 10, fp="a"), make("semgrep", 11, fp="b")])) == 2


def test_merge_keeps_the_most_severe_and_all_categories():
    merged = merge_sast([
        make("sonar", severity="low", cwes=(89, 79), categories=("A05:2025",)),
        make("semgrep", severity="high", cwes=(89, 918), categories=("A05:2025", "A01:2025")),
    ])
    assert merged[0].severity == "high"
    assert merged[0].categories == ["A01:2025", "A05:2025"]
    assert merged[0].cwes == [79, 89, 918]


def test_dast_is_never_merged_with_sast():
    merged = merge_sast([make("semgrep"), make("zap", file="")])
    assert len(merged) == 2


def test_correlation_links_by_cwe_without_merging():
    sast, dast = make("semgrep", cwes=(79,)), make("zap", cwes=(79,), file="")
    assert correlate([sast, dast]) == 1
    assert dast.related == [sast.fingerprint] and sast.related == [dast.fingerprint]


def test_real_outputs_merge_semgrep_and_sonar_on_the_same_line(semgrep_raw, sonar_raw, zap_raw):
    findings = parse_semgrep(semgrep_raw).findings + parse_sonar(sonar_raw).findings + parse_zap(zap_raw).findings
    merged = merge_sast(findings)
    key = next(f for f in merged if f.file == "lib/insecurity.ts" and f.line == 42 and 798 in f.cwes)
    assert key.tools == ["semgrep", "sonar"]
    assert len(merged) < len(findings)


def test_real_outputs_correlate_login_sqli_between_code_and_web(semgrep_raw, zap_raw):
    findings = parse_semgrep(semgrep_raw).findings + parse_zap(zap_raw).findings
    correlate(findings)
    code = next(f for f in findings if f.file == "routes/login.ts")
    web = next(f for f in findings if f.title == "SQL Injection")
    assert web.fingerprint in code.related and code.fingerprint in web.related
