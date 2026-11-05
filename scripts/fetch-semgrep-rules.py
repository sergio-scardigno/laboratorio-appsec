#!/usr/bin/env python3
"""Descarga los rulesets de Semgrep a rules/ para analizar sin red.

No se versionan en git: tienen su propia licencia (Semgrep Rules License).
El manifiesto guarda el hash y la fecha, para saber con qué reglas se hizo un análisis.
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

RULESETS = ["default", "owasp-top-ten", "security-audit", "secrets"]
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def main() -> int:
    RULES_DIR.mkdir(exist_ok=True)
    manifest = {"fetched": date.today().isoformat(), "rulesets": {}}
    for name in RULESETS:
        req = urllib.request.Request(
            f"https://semgrep.dev/c/p/{name}", headers={"User-Agent": "appsec-lab"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
        if not body.lstrip().startswith(b"rules:") and b"rules:" not in body[:200]:
            print(f"ERROR: {name}: la respuesta no parece un ruleset", file=sys.stderr)
            return 1
        (RULES_DIR / f"{name}.yaml").write_bytes(body)
        manifest["rulesets"][name] = {
            "sha256": hashlib.sha256(body).hexdigest(),
            "rules": body.count(b"\n- id:") + body.count(b"\n  - id:"),
        }
        print(f"{name}: {len(body) // 1024} KB, {manifest['rulesets'][name]['rules']} reglas")
    (RULES_DIR / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
