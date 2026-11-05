"""Convierte la salida cruda de cada herramienta al modelo común.

Los formatos se han sacado de ejecuciones reales (ver tests/fixtures).
Un elemento que no se entiende se descarta con motivo, nunca en silencio: la
regla "crudos = normalizados + descartados" se comprueba en cada ejecución.
"""
from __future__ import annotations

import hashlib
import html
import re
from pathlib import Path

from lab.models import Finding, Instance, ParseResult
from lab.owasp import UNMAPPED, categories_for, parse_cwe

SEMGREP_SEVERITY = {
    "CRITICAL": "critical", "ERROR": "high", "HIGH": "high",
    "WARNING": "medium", "MEDIUM": "medium", "LOW": "low", "INFO": "low",
}
SONAR_SEVERITY = {"BLOCKER": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
ZAP_CONFIDENCE = {"0": "falso positivo", "1": "baja", "2": "media", "3": "alta", "4": "confirmada"}
CONFIDENCE_LABELS = {"HIGH": "alta", "MEDIUM": "media", "LOW": "baja"}

# Reglas que detectan secretos: su evidencia no debe copiarse al informe.
SECRET_CWES = {259, 321, 522, 798}

_OWASP_2025 = re.compile(r"(A\d{2}:2025)")
_TAG = re.compile(r"<[^>]+>")
_BLOCK_END = re.compile(r"</(?:p|li|div)>|<br\s*/?>", re.IGNORECASE)


def fingerprint(*parts: object) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _cwe_numbers(raw: list | str | None) -> list[int]:
    items = [raw] if isinstance(raw, (str, int)) else (raw or [])
    numbers = {parse_cwe(item) for item in items}
    return sorted(n for n in numbers if n is not None)


def _strip_html(text: str) -> str:
    """Texto plano. La plantilla vuelve a escapar, así que decodificar aquí es seguro."""
    spaced = _BLOCK_END.sub(" ", text or "")
    return html.unescape(_TAG.sub("", spaced)).strip()


def _disagrees(categories: list[str], declared: list[str]) -> bool:
    return bool(declared) and categories != [UNMAPPED] and not set(categories) & set(declared)


def parse_semgrep(data: dict) -> ParseResult:
    results = data.get("results", [])
    findings, discarded = [], []
    seen: set[str] = set()
    for item in results:
        try:
            extra = item["extra"]
            metadata = extra.get("metadata", {})
            cwes = _cwe_numbers(metadata.get("cwe"))
            categories = categories_for(cwes)
            declared = sorted({
                match.group(1)
                for label in (metadata.get("owasp") or [])
                if (match := _OWASP_2025.match(str(label)))
            })
            rule_id = item["check_id"].removeprefix("rules.yaml.")
            line = item["start"]["line"]
            path = item["path"]
            key = fingerprint("semgrep", rule_id, path, item["start"].get("offset"), item["end"].get("offset"))
            if key in seen:
                discarded.append({"item": f"{rule_id} {path}:{line}", "reason": "Duplicado exacto en la salida de Semgrep"})
                continue
            seen.add(key)
            findings.append(Finding(
                fingerprint=key,
                tool="semgrep",
                rule_id=rule_id,
                title=rule_id.rsplit(".", 1)[-1].replace("-", " ").capitalize(),
                severity=SEMGREP_SEVERITY.get(str(extra.get("severity")).upper(), "medium"),
                categories=categories,
                cwes=cwes,
                confidence=CONFIDENCE_LABELS.get(str(metadata.get("confidence")).upper(), ""),
                message=extra.get("message", ""),
                file=path,
                line=line,
                tool_owasp=declared,
                owasp_disagrees=_disagrees(categories, declared),
            ))
        except (KeyError, TypeError) as exc:
            discarded.append({"item": str(item)[:200], "reason": f"Formato inesperado: {exc!r}"})

    errors = data.get("errors", [])
    warnings = []
    if errors:
        paths = {e.get("path") for e in errors if e.get("path")}
        warnings.append(f"{len(paths)} archivos analizados de forma parcial o con errores de sintaxis")
    return ParseResult("semgrep", findings, len(results), discarded, warnings)


def _strip_component(component: str, project_key: str) -> str:
    return component.removeprefix(f"{project_key}:")


def parse_sonar(data: dict) -> ParseResult:
    project_key = data.get("project_key", "")
    rules = data.get("rules", {})
    issues = data.get("issues", [])
    hotspots = data.get("hotspots", [])
    findings, discarded = [], []

    for item in issues:
        try:
            rule_key = item["rule"]
            rule = rules.get(rule_key, {})
            security = [i for i in item.get("impacts", []) if i.get("softwareQuality") == "SECURITY"]
            impact = security[0]["severity"] if security else ""
            cwes = _cwe_numbers(rule.get("cwes"))
            findings.append(Finding(
                fingerprint=fingerprint("sonar", rule_key, item["component"], item.get("line"), item["key"]),
                tool="sonar",
                rule_id=rule_key,
                title=rule.get("name") or rule_key,
                severity=SONAR_SEVERITY.get(impact, "medium"),
                categories=categories_for(cwes),
                cwes=cwes,
                message=item.get("message", ""),
                file=_strip_component(item["component"], project_key),
                line=item.get("line") or 0,
                # Sonar ya no separa los hotspots: son vulnerabilidades con esta etiqueta,
                # pero siguen dependiendo del contexto.
                review_required="former-hotspot" in rule.get("sysTags", []),
            ))
        except (KeyError, TypeError) as exc:
            discarded.append({"item": str(item)[:200], "reason": f"Formato inesperado: {exc!r}"})

    for item in hotspots:
        try:
            rule_key = item.get("ruleKey", "")
            rule = rules.get(rule_key, {})
            cwes = _cwe_numbers(rule.get("cwes"))
            findings.append(Finding(
                fingerprint=fingerprint("sonar", rule_key, item["component"], item.get("line"), item["key"]),
                tool="sonar",
                rule_id=rule_key,
                title=rule.get("name") or rule_key,
                severity="medium",
                categories=categories_for(cwes),
                cwes=cwes,
                message=item.get("message", ""),
                file=_strip_component(item["component"], project_key),
                line=item.get("line") or 0,
                review_required=True,
            ))
        except (KeyError, TypeError) as exc:
            discarded.append({"item": str(item)[:200], "reason": f"Formato inesperado: {exc!r}"})

    warnings = []
    missing = data.get("issues_total", len(issues)) - len(issues)
    if missing > 0:
        warnings.append(f"La API de Sonar solo devolvió {len(issues)} de {data['issues_total']} issues")
    return ParseResult("sonar", findings, len(issues) + len(hotspots), discarded, warnings)


def _zap_warnings(data: dict) -> list[str]:
    """Las señales de ZAP de que el análisis pudo quedarse corto."""
    for insight in data.get("insights", []):
        if insight.get("key") == "insight.network.failure" and insight.get("level") != "Info":
            return [
                f"ZAP no obtuvo respuesta en el {insight.get('statistic')} % de las peticiones: "
                "puede que la web se saturara o que fallaran recursos externos, y parte del análisis puede faltar"
            ]
    return []


def parse_zap(data: dict, max_instances: int = 20) -> ParseResult:
    findings, discarded = [], []
    raw_count = 0
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            raw_count += 1
            try:
                # ZAP marca con confianza 0 lo que un revisor ya descartó.
                if str(alert.get("confidence")) == "0":
                    discarded.append({"item": alert.get("name"), "reason": "ZAP lo marca como falso positivo"})
                    continue
                cwes = _cwe_numbers(alert.get("cweid"))
                instances = alert.get("instances", [])
                findings.append(Finding(
                    fingerprint=fingerprint("zap", site.get("@name"), alert["pluginid"], alert.get("alertRef")),
                    tool="zap",
                    rule_id=str(alert.get("alertRef") or alert["pluginid"]),
                    title=alert.get("name") or alert.get("alert", ""),
                    severity=ZAP_RISK.get(str(alert.get("riskcode")), "medium"),
                    categories=categories_for(cwes),
                    cwes=cwes,
                    confidence=ZAP_CONFIDENCE.get(str(alert.get("confidence")), ""),
                    message=_strip_html(alert.get("desc", "")),
                    solution=_strip_html(alert.get("solution", "")),
                    instances=[
                        Instance(
                            url=i.get("uri", ""), method=i.get("method", ""),
                            param=i.get("param", ""),
                            evidence=(i.get("attack") or i.get("evidence") or "")[:300],
                        )
                        for i in instances[:max_instances]
                    ],
                    instance_count=len(instances),
                ))
            except (KeyError, TypeError) as exc:
                discarded.append({"item": str(alert)[:200], "reason": f"Formato inesperado: {exc!r}"})
    return ParseResult("zap", findings, raw_count, discarded, _zap_warnings(data))


def attach_snippets(findings: list[Finding], src: Path, max_len: int = 240) -> None:
    """Añade la línea de código a los hallazgos SAST.

    Semgrep no la da sin iniciar sesión ("requires login"). Nunca se copia en los
    hallazgos de secretos: el informe se puede compartir. Las rutas vienen de una
    herramienta que analizó código no confiable, así que no se sale de `src`.
    """
    root = src.resolve()
    cache: dict[str, list[str]] = {}
    for finding in findings:
        if not finding.file or finding.line <= 0:
            continue
        if SECRET_CWES & set(finding.cwes) or "secret" in finding.rule_id.lower():
            finding.snippet = "(oculto: posible secreto)"
            continue
        path = (root / finding.file).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            continue
        if finding.file not in cache:
            try:
                cache[finding.file] = path.read_text(errors="replace").splitlines()
            except OSError:
                cache[finding.file] = []
        lines = cache[finding.file]
        if finding.line <= len(lines):
            finding.snippet = lines[finding.line - 1].strip()[:max_len]
