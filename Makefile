.PHONY: setup venv env up down sonar images rules trivy-db test test-client web web-url owasp-map

setup: venv env up sonar images rules trivy-db

venv:
	python3 -m venv .venv
	.venv/bin/pip install --quiet -e ".[dev]"

env:
	python3 scripts/bootstrap-sonar.py init-env

up:
	docker compose up -d

down:
	docker compose down

sonar:
	python3 scripts/bootstrap-sonar.py configure

test:
	.venv/bin/pytest

test-client:
	bash client/tests/test-policy.sh

owasp-map:
	python3 scripts/gen_owasp_map.py

images:
	python3 -c "from lab import images; print(images.SEMGREP); print(images.SONAR_SCANNER); print(images.ZAP); print(images.TRIVY)" | xargs -n1 docker pull -q

rules:
	python3 scripts/fetch-semgrep-rules.py

trivy-db:
	.venv/bin/python -c "from lab.runners import trivy; print(trivy.update_db())"

web:
	.venv/bin/lab web

web-url:
	.venv/bin/lab web-url
