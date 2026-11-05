"""Deduplicación SAST y correlación SAST/DAST."""
from __future__ import annotations

from lab.models import SEVERITIES, Finding

LINE_TOLERANCE = 3


def _rank(finding: Finding) -> tuple:
    # Se conserva como principal el más grave; a igualdad, el de más información.
    return (SEVERITIES.index(finding.severity), finding.review_required, finding.tool)


def merge_sast(findings: list[Finding]) -> list[Finding]:
    """Fusiona hallazgos de herramientas SAST distintas.

    Solo si coinciden archivo, algún CWE y línea ±3. Sin CWE común no se fusiona: dos
    problemas distintos pueden estar en la misma línea. Una herramienta no se fusiona
    consigo misma: dos reglas suyas son dos avisos distintos.
    """
    sast = sorted((f for f in findings if f.is_sast), key=_rank)
    others = [f for f in findings if not f.is_sast]
    kept: list[Finding] = []
    for finding in sast:
        target = next(
            (
                k for k in kept
                if k.file == finding.file
                and finding.file
                and abs(k.line - finding.line) <= LINE_TOLERANCE
                and set(k.cwes) & set(finding.cwes)
                and finding.tool not in k.tools
            ),
            None,
        )
        if target is None:
            kept.append(finding)
            continue
        target.also_found_by.append({
            "tool": finding.tool, "rule_id": finding.rule_id, "title": finding.title,
            "line": finding.line, "severity": finding.severity,
        })
        target.categories = sorted(set(target.categories) | set(finding.categories))
        target.cwes = sorted(set(target.cwes) | set(finding.cwes))
    return kept + others


def correlate(findings: list[Finding]) -> int:
    """Marca como relacionados los hallazgos SAST y DAST con algún CWE común.

    No se fusionan: no hay un vínculo fiable entre una URL y una línea de código.
    Devuelve cuántos hallazgos dinámicos tienen alguna correlación.
    """
    correlated = 0
    sast = [f for f in findings if f.is_sast and f.cwes]
    for dast in (f for f in findings if not f.is_sast and f.cwes):
        matches = [s for s in sast if set(s.cwes) & set(dast.cwes)]
        if matches:
            correlated += 1
            dast.related = [s.fingerprint for s in matches]
            for source in matches:
                source.related.append(dast.fingerprint)
    return correlated
