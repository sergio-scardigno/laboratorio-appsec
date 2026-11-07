"""Runner de SonarQube: analiza con el scanner efímero y recoge resultados por API."""
from __future__ import annotations

import base64
import json
import os
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from lab import images
from lab.runners.base import ToolResult, docker_run, tail

SCANNER_NETWORK = "lab-sonar-front"
INTERNAL_URL = "http://sonarqube:9000"
PAGE_SIZE = 500
MAX_RESULTS = 10000  # Límite de paginación de la API de Sonar.
# Dependencias y artefactos: no son código de la aplicación.
EXCLUSIONS = "**/node_modules/**,**/dist/**,**/build/**,**/vendor/**,**/*.min.js"


class SonarApi:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{token}:".encode()).decode()

    def get(self, path: str, **params) -> dict:
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        req = urllib.request.Request(f"{self.base_url}{path}?{query}", headers={"Authorization": self.auth})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)

    def post(self, path: str, **params) -> None:
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, method="POST",
                                     headers={"Authorization": self.auth})
        with urllib.request.urlopen(req, timeout=60):
            pass

    def paged(self, path: str, key: str, **params) -> tuple[list[dict], int]:
        """Devuelve (elementos, total declarado por la API)."""
        items: list[dict] = []
        page = 1
        total = 0
        while True:
            data = self.get(path, p=page, ps=PAGE_SIZE, **params)
            batch = data.get(key, [])
            items += batch
            total = data.get("paging", {}).get("total", data.get("total", len(items)))
            if not batch or len(items) >= min(total, MAX_RESULTS):
                return items, total
            page += 1


def wait_for_task(api: SonarApi, task_id: str, timeout_s: int) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        task = api.get("/api/ce/task", id=task_id)["task"]
        if task["status"] in ("SUCCESS", "FAILED", "CANCELED"):
            return task
        time.sleep(5)
    raise TimeoutError(f"Sonar no procesó el análisis en {timeout_s}s")


def rule_info(api: SonarApi, key: str) -> dict:
    """Nombre, etiquetas y CWE de una regla.

    api/rules/show no trae los CWE; el facet de api/rules/search sí, y es dato
    estructurado. La descripción de la regla no se guarda: no hace falta.
    """
    rule = api.get("/api/rules/show", key=key)["rule"]
    search = api.get("/api/rules/search", rule_key=key, facets="cwe,owaspTop10-2021", ps=1)
    facets = {
        facet["property"]: [v["val"] for v in facet["values"] if v["count"]]
        for facet in search.get("facets", [])
    }
    return {
        "name": rule.get("name"),
        "sysTags": rule.get("sysTags", []),
        "cwes": facets.get("cwe", []),
        "owasp2021": facets.get("owaspTop10-2021", []),
    }


def collect(api: SonarApi, project_key: str) -> dict:
    # Solo seguridad: los problemas de mantenibilidad no son hallazgos de este informe.
    issues, issues_total = api.paged(
        "/api/issues/search", "issues",
        componentKeys=project_key, impactSoftwareQualities="SECURITY",
        issueStatuses="OPEN,CONFIRMED",
    )
    hotspots, hotspots_total = api.paged("/api/hotspots/search", "hotspots", project=project_key)
    rules = {}
    for key in sorted({i["rule"] for i in issues} | {h.get("ruleKey") for h in hotspots if h.get("ruleKey")}):
        rules[key] = rule_info(api, key)
    return {
        "project_key": project_key,
        "issues": issues,
        "issues_total": issues_total,
        "hotspots": hotspots,
        "hotspots_total": hotspots_total,
        "rules": rules,
    }


def project_key(run_id: str) -> str:
    return f"lab-{run_id}"


def delete_project(sonar_url: str, token: str, key: str) -> None:
    """Borra el proyecto de un análisis; la puerta lo hace para no acumular uno por push."""
    SonarApi(sonar_url, token).post("/api/projects/delete", project=key)


def run(
    src: Path, out_dir: Path, run_id: str, sonar_url: str, token: str, timeout_s: int = 2400
) -> ToolResult:
    key = project_key(run_id)
    work = out_dir / "scannerwork"
    work.mkdir(parents=True, exist_ok=True)
    log = out_dir / "sonar-scanner.log"
    started = time.monotonic()
    outcome = docker_run(
        f"lab-{run_id}-sonar",
        images.SONAR_SCANNER,
        [
            "--network", SCANNER_NETWORK,
            "--memory", "4g",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-e", f"SONAR_HOST_URL={INTERNAL_URL}",
            "-e", "SONAR_USER_HOME=/work/.sonar",
            "-e", "SONAR_SCANNER_OPTS=-Xmx2g",
            "-v", f"{src.resolve()}:/usr/src:ro",
            "-v", f"{work.resolve()}:/work",
        ],
        [
            f"-Dsonar.projectKey={key}",
            f"-Dsonar.projectName={run_id}",
            "-Dsonar.sources=.",
            "-Dsonar.working.directory=/work/scanner",
            "-Dsonar.scm.disabled=true",
            f"-Dsonar.exclusions={EXCLUSIONS}",
            "-Dsonar.javascript.node.maxspace=3072",
        ],
        timeout_s=timeout_s,
        stdout_path=log,
        stderr_path=out_dir / "sonar-scanner.err",
        env={"SONAR_TOKEN": token},
    )
    if outcome.timed_out:
        return ToolResult("sonar", "error", outcome.duration_s, message=f"Superó el límite de {timeout_s}s")
    report = work / "scanner" / "report-task.txt"
    if outcome.returncode != 0 or not report.exists():
        return ToolResult(
            "sonar", "error", outcome.duration_s,
            message=f"El scanner falló (exit {outcome.returncode}): {tail(log)}",
        )
    props = dict(
        line.split("=", 1) for line in report.read_text().splitlines() if "=" in line
    )
    shutil.rmtree(work, ignore_errors=True)  # Caché y artefactos del scanner.

    api = SonarApi(sonar_url, token)
    try:
        task = wait_for_task(api, props["ceTaskId"], timeout_s=900)
        if task["status"] != "SUCCESS":
            return ToolResult(
                "sonar", "error", time.monotonic() - started,
                message=f"Sonar rechazó el análisis: {task['status']} {task.get('errorMessage', '')}",
            )
        data = collect(api, key)
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as exc:
        return ToolResult("sonar", "error", time.monotonic() - started, message=f"Error con la API: {exc}")

    raw = out_dir / "sonar.json"
    raw.write_text(json.dumps(data))
    return ToolResult(
        "sonar", "ok", time.monotonic() - started, [raw.name],
        details={
            "issues": len(data["issues"]),
            "issues_total": data["issues_total"],
            "hotspots": len(data["hotspots"]),
            "hotspots_total": data["hotspots_total"],
            "rules": len(data["rules"]),
            "project_key": key,
        },
    )
