"""Modelo común de hallazgos."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABELS = {
    "critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa",
}
TOOLS = ["semgrep", "sonar", "trivy", "zap"]
# Las que analizan código o artefactos, sin ejecutar la aplicación.
SAST_TOOLS = {"semgrep", "sonar", "trivy"}


@dataclass
class Instance:
    """Dónde aparece un hallazgo dinámico."""
    url: str
    method: str = ""
    param: str = ""
    evidence: str = ""


@dataclass
class Finding:
    fingerprint: str
    tool: str
    rule_id: str
    title: str
    severity: str
    categories: list[str]
    cwes: list[int] = field(default_factory=list)
    confidence: str = ""
    message: str = ""
    file: str = ""
    line: int = 0
    solution: str = ""
    snippet: str = ""
    # Enlace al aviso de seguridad y CWE que este declara (dependencias vulnerables).
    reference: str = ""
    advisory_cwes: list[int] = field(default_factory=list)
    # True: la herramienta pide que una persona confirme si es un problema real.
    review_required: bool = False
    instances: list[Instance] = field(default_factory=list)
    instance_count: int = 0
    # Categoría 2025 que declara la propia herramienta, si difiere de la de su CWE.
    tool_owasp: list[str] = field(default_factory=list)
    owasp_disagrees: bool = False
    # Se rellenan al deduplicar y correlacionar.
    also_found_by: list[dict] = field(default_factory=list)
    related: list[str] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({self.tool, *(item["tool"] for item in self.also_found_by)})

    @property
    def is_sast(self) -> bool:
        return self.tool in SAST_TOOLS

    def to_dict(self) -> dict:
        data = asdict(self)
        data["tools"] = self.tools
        return data


@dataclass
class ParseResult:
    tool: str
    findings: list[Finding]
    raw_count: int
    discarded: list[dict] = field(default_factory=list)  # {"item": ..., "reason": ...}
    warnings: list[str] = field(default_factory=list)

    @property
    def reconciled(self) -> bool:
        return self.raw_count == len(self.findings) + len(self.discarded)
