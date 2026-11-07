from lab.normalize import attach_snippets, parse_semgrep, parse_sonar, parse_zap
from lab.owasp import UNMAPPED


def test_semgrep_real_output_reconciles(semgrep_raw):
    result = parse_semgrep(semgrep_raw)
    assert result.reconciled
    assert result.raw_count == len(semgrep_raw["results"])


def test_semgrep_detects_login_sqli_as_injection(semgrep_raw):
    login = [f for f in parse_semgrep(semgrep_raw).findings if f.file == "routes/login.ts"]
    assert any("A05:2025" in f.categories and 89 in f.cwes and f.line == 34 for f in login)


def test_semgrep_fingerprints_are_unique(semgrep_raw):
    findings = parse_semgrep(semgrep_raw).findings
    assert len({f.fingerprint for f in findings}) == len(findings)


def test_semgrep_same_start_different_end_are_two_findings(semgrep_raw):
    same = [f for f in parse_semgrep(semgrep_raw).findings if "restfulXssChallenge_2" in f.file]
    assert len(same) == 2


def test_semgrep_exact_duplicate_is_discarded_with_reason(semgrep_raw):
    semgrep_raw["results"].append(semgrep_raw["results"][0])
    result = parse_semgrep(semgrep_raw)
    assert result.reconciled
    assert result.discarded[-1]["reason"].startswith("Duplicado")


def test_semgrep_malformed_item_is_discarded_not_lost(semgrep_raw):
    semgrep_raw["results"].append({"check_id": "x"})
    result = parse_semgrep(semgrep_raw)
    assert result.reconciled
    assert "Formato inesperado" in result.discarded[-1]["reason"]


def test_semgrep_cwe_outside_the_table_stays_unmapped(semgrep_raw):
    subnet = [f for f in parse_semgrep(semgrep_raw).findings if "subnet-has-public" in f.rule_id]
    assert subnet and subnet[0].categories == [UNMAPPED]
    assert subnet[0].tool_owasp == ["A01:2025"]  # Se conserva lo que declara la regla.


def test_semgrep_flags_disagreement_with_the_table(semgrep_raw):
    curl = [f for f in parse_semgrep(semgrep_raw).findings if "gha-curl" in f.rule_id]
    assert curl and curl[0].owasp_disagrees and curl[0].categories == ["A05:2025"]


def test_semgrep_partial_files_become_a_warning(semgrep_raw):
    assert "parcial" in parse_semgrep(semgrep_raw).warnings[0]


def test_sonar_real_output_reconciles(sonar_raw):
    result = parse_sonar(sonar_raw)
    assert result.reconciled and not result.warnings


def test_sonar_former_hotspot_needs_review_and_secret_does_not(sonar_raw):
    by_rule = {f.rule_id: f for f in parse_sonar(sonar_raw).findings}
    assert by_rule["typescript:S5332"].review_required
    assert not by_rule["typescript:S6437"].review_required


def test_sonar_component_prefix_is_removed(sonar_raw):
    assert all(not f.file.startswith("lab-raw1:") for f in parse_sonar(sonar_raw).findings)


def test_sonar_severity_comes_from_security_impact(sonar_raw):
    item = sonar_raw["issues"][0]
    item["impacts"] = [{"softwareQuality": "MAINTAINABILITY", "severity": "LOW"}, {"softwareQuality": "SECURITY", "severity": "BLOCKER"}]
    finding = next(f for f in parse_sonar(sonar_raw).findings if item["key"] in str(f) or f.file in item["component"])
    assert finding.severity == "critical"


def test_sonar_warns_when_api_truncates(sonar_raw):
    sonar_raw["issues_total"] = len(sonar_raw["issues"]) + 5
    assert "solo devolvió" in parse_sonar(sonar_raw).warnings[0]


def test_sonar_rule_with_cwes_in_several_categories(sonar_raw):
    finding = next(f for f in parse_sonar(sonar_raw).findings if f.rule_id == "typescript:S5332")
    assert finding.categories == ["A01:2025", "A04:2025"]  # CWE-200 y CWE-319


def test_zap_real_output_reconciles(zap_raw):
    result = parse_zap(zap_raw)
    assert result.reconciled
    assert len(result.findings) == len(zap_raw["site"][0]["alerts"])


def test_zap_alert_without_cwe_stays_unmapped(zap_raw):
    modern = next(f for f in parse_zap(zap_raw).findings if f.title == "Modern Web Application")
    assert modern.categories == [UNMAPPED] and modern.cwes == [] and modern.severity == "info"


def test_zap_false_positive_is_discarded_with_reason(zap_raw):
    zap_raw["site"][0]["alerts"][0]["confidence"] = "0"
    result = parse_zap(zap_raw)
    assert result.reconciled and "falso positivo" in result.discarded[0]["reason"]


def test_zap_html_is_stripped_from_text(zap_raw):
    assert "<p>" not in parse_zap(zap_raw).findings[0].message


def test_zap_keeps_instance_count_when_truncating(zap_raw):
    alert = zap_raw["site"][0]["alerts"][0]
    alert["instances"] = [{"uri": f"http://x/{i}"} for i in range(30)]
    finding = parse_zap(zap_raw, max_instances=5).findings[0]
    assert len(finding.instances) == 5 and finding.instance_count == 30


def test_snippet_is_attached_but_never_for_secrets(tmp_path, semgrep_raw, sonar_raw):
    (tmp_path / "routes").mkdir()
    (tmp_path / "lib").mkdir()
    (tmp_path / "routes/login.ts").write_text("\n" * 33 + "  SELECT * FROM Users\n")
    (tmp_path / "lib/insecurity.ts").write_text("x\n" * 41 + "const privateKey = 'TOP-SECRET'\n")
    findings = parse_semgrep(semgrep_raw).findings
    attach_snippets(findings, tmp_path)
    login = next(f for f in findings if f.file == "routes/login.ts")
    assert login.snippet == "SELECT * FROM Users"
    assert not any("TOP-SECRET" in f.snippet for f in findings)
    assert any(f.snippet.startswith("(oculto") for f in findings if f.file == "lib/insecurity.ts")


def test_snippet_does_not_read_outside_the_source(tmp_path):
    from lab.models import Finding

    outside = tmp_path / "outside.txt"
    outside.write_text("confidencial\n")
    root = tmp_path / "src"
    root.mkdir()
    finding = Finding("x", "semgrep", "r", "t", "low", ["A01:2025"], file="../outside.txt", line=1)
    attach_snippets([finding], root)
    assert finding.snippet == ""


def test_zap_active_scan_finds_the_login_sqli(zap_raw):
    sqli = next(f for f in parse_zap(zap_raw).findings if f.title == "SQL Injection")
    assert sqli.severity == "high" and sqli.categories == ["A05:2025"] and 89 in sqli.cwes
    assert any(i.url.endswith("/rest/user/login") and i.method == "POST" for i in sqli.instances)


def test_zap_network_failures_become_a_warning(zap_raw):
    assert "no obtuvo respuesta" in parse_zap(zap_raw).warnings[0]


def test_zap_text_keeps_paragraph_breaks_and_decodes_entities(zap_raw):
    alert = zap_raw["site"][0]["alerts"][0]
    alert["solution"] = "<p>Uno.</p><p>Dos &amp; tres &lt;b&gt;.</p>"
    assert parse_zap(zap_raw).findings[0].solution == "Uno. Dos & tres <b>."


def test_trivy_reconciles_and_every_finding_is_unique(trivy_raw):
    from lab.normalize import parse_trivy

    result = parse_trivy(trivy_raw)
    assert result.reconciled and result.raw_count > 0
    assert len({f.fingerprint for f in result.findings}) == len(result.findings)


def test_trivy_vulnerable_dependency_is_a03_whatever_the_advisory_says(trivy_raw):
    from lab.normalize import parse_trivy

    vulns = [f for f in parse_trivy(trivy_raw).findings if f.cwes == [1395]]
    assert vulns and all(f.categories == ["A03:2025"] for f in vulns)
    with_advisory = next(f for f in vulns if f.advisory_cwes)
    assert 1395 not in with_advisory.advisory_cwes


def test_trivy_secret_is_a07_and_never_copies_its_value(trivy_raw):
    from lab.normalize import parse_trivy

    secret_value = "-----BEGIN PRIVATE KEY-----supersecreto"
    item = next(r for r in trivy_raw["scans"][0]["report"]["Results"] if r.get("Secrets"))
    item["Secrets"][0]["Match"] = secret_value
    item["Secrets"][0]["Code"] = {"Lines": [{"Content": secret_value}]}
    findings = parse_trivy(trivy_raw).findings
    secrets = [f for f in findings if f.cwes == [798]]
    assert secrets and all(f.categories == ["A07:2025"] for f in secrets)
    assert secret_value not in str([f.to_dict() for f in findings])


def test_trivy_same_vulnerability_in_two_paths_counts_once_with_a_reason():
    from lab.normalize import parse_trivy

    vuln = {"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1", "Severity": "HIGH"}
    data = {"scans": [{"kind": "fs", "report": {"Results": [
        {"Target": "x/package-lock.json", "Vulnerabilities": [vuln]},
        {"Target": "y/package-lock.json", "Vulnerabilities": [vuln]},
    ]}}]}
    result = parse_trivy(data)
    assert len(result.findings) == 1 and result.reconciled
    assert "otra ruta" in result.discarded[0]["reason"]


def test_trivy_unknown_severity_and_missing_fix_are_explained():
    from lab.normalize import parse_trivy

    data = {"scans": [{"kind": "fs", "report": {"Results": [{"Target": "l", "Vulnerabilities": [
        {"VulnerabilityID": "X-1", "PkgName": "a", "InstalledVersion": "1", "Severity": "UNKNOWN"},
    ]}]}}]}
    finding = parse_trivy(data).findings[0]
    assert finding.severity == "medium" and "no informa" in finding.message
    assert "no hay una versión corregida" in finding.solution


def test_trivy_malformed_item_is_discarded_not_lost():
    from lab.normalize import parse_trivy

    data = {"scans": [{"kind": "fs", "report": {"Results": [{"Target": "l", "Vulnerabilities": [{"x": 1}], "Secrets": [{"y": 2}]}]}}]}
    result = parse_trivy(data)
    assert result.reconciled and len(result.discarded) == 2


def test_trivy_image_findings_say_where_they_come_from(trivy_raw):
    from lab.normalize import parse_trivy

    files = {f.file for f in parse_trivy(trivy_raw).findings}
    assert any(f == "imagen: sistema operativo" for f in files)
    assert not any("/image.tar" in f for f in files)


def test_trivy_warnings_are_kept(trivy_raw):
    from lab.normalize import parse_trivy

    assert "no trae lockfile" in parse_trivy(trivy_raw).warnings[0]


def test_trivy_results_can_be_null():
    from lab.normalize import parse_trivy

    result = parse_trivy({"scans": [{"kind": "fs", "report": {"Results": None}}]})
    assert result.findings == [] and result.reconciled
