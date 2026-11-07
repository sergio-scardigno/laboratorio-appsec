"""Interfaz web. Pensada para escuchar solo en localhost y usarse por túnel SSH."""
from __future__ import annotations

import hmac
import queue
import re
import secrets
import threading
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import ChoiceLoader, Environment, FileSystemLoader, select_autoescape

from lab.pipeline import PRESET_JUICE_SHOP, ScanBusy, ScanRefused, ScanRequest, execute, new_run_id, validate
from lab.settings import Settings, load_settings
from lab.store import Store

HERE = Path(__file__).resolve().parent
COOKIE = "lab_session"
RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4}$")
PUBLIC_PATHS = {"/healthz"}
STAGES = [
    ("source", "Obtener el código"),
    ("semgrep", "Semgrep"),
    ("sonar", "SonarQube"),
    ("trivy", "Trivy"),
    ("zap", "ZAP"),
    ("report", "Mapear y generar el informe"),
]
STATUS_LABELS = {
    "queued": "En cola", "running": "En curso", "ok": "Completo", "partial": "Parcial", "error": "Con error",
}
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

POLL_JS = """
(function () {
  var root = document.getElementById('run');
  if (!root || root.dataset.finished === '1') return;
  function tick() {
    fetch(root.dataset.events, {credentials: 'same-origin'}).then(function (r) { return r.json(); }).then(function (d) {
      if (d.finished) { location.reload(); return; }
      d.stages.forEach(function (s) {
        var li = document.querySelector('[data-stage="' + s.id + '"]');
        if (!li) return;
        li.dataset.state = s.state;
        li.querySelector('.state').textContent = s.label;
        li.querySelector('.detail').textContent = s.message;
      });
      setTimeout(tick, 3000);
    }).catch(function () { setTimeout(tick, 6000); });
  }
  setTimeout(tick, 2000);
})();
"""
STATE_LABELS = {"pending": "Pendiente", "running": "En curso", "ok": "Correcto", "error": "Falló", "skipped": "No aplica"}


class Worker:
    """Una sola cola: los escáneres corren en serie por memoria."""

    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings, self.store = settings, store
        self.jobs: queue.Queue = queue.Queue()
        self.thread = threading.Thread(target=self._loop, daemon=True, name="lab-worker")
        self.thread.start()

    def submit(self, run_id: str, request: ScanRequest) -> None:
        self.jobs.put((run_id, request))

    def _loop(self) -> None:
        while True:
            run_id, request = self.jobs.get()
            try:
                execute(request, self.settings, self.store, run_id=run_id)
            except ScanBusy as exc:
                self.store.add_event(run_id, "done", "error", str(exc))
                self.store.finish_run(run_id, "error", {"message": str(exc)})
            except Exception as exc:  # noqa: BLE001 - el trabajador no debe morir
                self.store.add_event(run_id, "done", "error", f"{type(exc).__name__}: {exc}")
                self.store.finish_run(run_id, "error", {"message": f"{type(exc).__name__}: {exc}"})
            finally:
                self.jobs.task_done()


def stage_view(run: dict, events: list[dict]) -> list[dict]:
    request = run["request"]
    sast = bool(request.get("preset") or request.get("repo") or request.get("local_path"))
    dast = bool(request.get("preset") or request.get("url"))
    applies = {"source": sast, "semgrep": sast, "sonar": sast, "trivy": sast, "zap": dast, "report": True}
    latest = {event["stage"]: event for event in events}
    view = []
    for stage, name in STAGES:
        event = latest.get(stage)
        if not applies[stage]:
            state = "skipped"
        elif not event:
            state = "pending"
        else:
            state = {"ok": "ok", "error": "error", "running": "running", "skipped": "skipped"}.get(event["status"], "pending")
        view.append({
            "id": stage, "name": name, "state": state, "label": STATE_LABELS[state],
            "message": event["message"] if event else "",
        })
    return view


def create_app(settings: Settings | None = None, start_worker: bool = True) -> FastAPI:
    settings = settings or load_settings()
    if not settings.web_token:
        raise RuntimeError("Falta LAB_WEB_TOKEN: ejecuta make env")
    store = Store(settings.db_path)
    store.mark_interrupted()
    worker = Worker(settings, store) if start_worker else None

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings, app.state.store, app.state.worker = settings, store, worker
    # La sesión se deriva del token: no hay que guardar estado y caduca si cambia el token.
    session_value = hmac.new(settings.web_token.encode(), b"lab-session", "sha256").hexdigest()

    env = Environment(
        loader=ChoiceLoader([FileSystemLoader(HERE / "templates"), FileSystemLoader(HERE.parent / "templates")]),
        autoescape=select_autoescape(["html"], default_for_string=True, default=True),
    )
    templates = Jinja2Templates(env=env)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # DNS rebinding: otra web no puede hablar con este servicio cambiando su DNS.
        host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in ALLOWED_HOSTS and host != "testserver":
            return Response("Host no permitido", status_code=403)
        # CSRF: una página ajena no debe poder lanzar escaneos desde tu navegador.
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            if origin and (urlparse(origin).netloc != request.headers.get("host")):
                return Response("Origen no permitido", status_code=403)

        if request.url.path not in PUBLIC_PATHS:
            token = request.query_params.get("token")
            if token and hmac.compare_digest(token, settings.web_token):
                # El token no debe quedarse en la URL ni en el historial.
                response = RedirectResponse(request.url.path, status_code=303)
                response.set_cookie(COOKIE, session_value, httponly=True, samesite="strict", max_age=60 * 60 * 24 * 30)
                return response
            cookie = request.cookies.get(COOKIE, "")
            if not hmac.compare_digest(cookie, session_value):
                return HTMLResponse(
                    "<!doctype html><html lang=es><meta charset=utf-8><title>Acceso</title>"
                    "<p>Falta el token de acceso. Abre el enlace que muestra <code>lab web</code> al arrancar.</p>",
                    status_code=401,
                )
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", HTML_CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def render_home(request: Request, error: str = "", form: dict | None = None, status_code: int = 200):
        return templates.TemplateResponse(
            request, "index.html",
            {
                "runs": store.list_runs(30), "status_labels": STATUS_LABELS, "error": error,
                "form": form or {}, "sonar_ready": bool(settings.sonar_token),
            },
            status_code=status_code,
        )

    def get_run_or_none(run_id: str) -> dict | None:
        return store.get_run(run_id) if RUN_ID.match(run_id) else None

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        return render_home(request)

    @app.get("/app.js")
    def app_js():
        return Response(POLL_JS, media_type="text/javascript")

    @app.post("/scans")
    def create_scan(
        request: Request,
        preset: str = Form(""), repo: str = Form(""), ref: str = Form(""), url: str = Form(""),
        mode: str = Form("passive"), authorized: str = Form(""), active_confirmed: str = Form(""),
    ):
        scan = ScanRequest(
            repo=repo.strip(), ref=ref.strip(), url=url.strip(),
            preset=PRESET_JUICE_SHOP if preset == PRESET_JUICE_SHOP else "",
            active=mode == "active", authorized=authorized == "on", active_confirmed=active_confirmed == "on",
        )
        form = {"repo": scan.repo, "ref": scan.ref, "url": scan.url, "mode": mode}
        if preset and not scan.preset:
            return render_home(request, "Preset desconocido", form, 400)
        if scan.ref and not re.fullmatch(r"[\w./-]{1,200}", scan.ref) or scan.ref.startswith("-"):
            return render_home(request, "La rama o etiqueta no es válida", form, 400)
        try:
            validate(scan)
        except ScanRefused as exc:
            return render_home(request, str(exc), form, 400)
        run_id = new_run_id()
        store.create_run(run_id, scan.target, asdict(scan))
        if worker:
            worker.submit(run_id, scan)
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def show_run(request: Request, run_id: str):
        run = get_run_or_none(run_id)
        if not run:
            return HTMLResponse("No existe ese análisis", status_code=404)
        finished = run["status"] not in ("queued", "running")
        report_ready = (settings.runs_dir / run_id / "report.html").exists()
        return templates.TemplateResponse(
            request, "run.html",
            {
                "run": run, "stages": stage_view(run, store.events(run_id)), "finished": finished,
                "report_ready": report_ready, "status_labels": STATUS_LABELS,
            },
        )

    @app.get("/runs/{run_id}/events.json")
    def run_events(run_id: str):
        run = get_run_or_none(run_id)
        if not run:
            return JSONResponse({"error": "No existe"}, status_code=404)
        return {
            "status": run["status"],
            "finished": run["status"] not in ("queued", "running"),
            "stages": stage_view(run, store.events(run_id)),
        }

    @app.get("/runs/{run_id}/report")
    def run_report(run_id: str):
        path = settings.runs_dir / run_id / "report.html"
        if not get_run_or_none(run_id) or not path.exists():
            return HTMLResponse("Este análisis no tiene informe", status_code=404)
        # El informe trae su propia CSP con nonce; aquí se sirve tal cual.
        return FileResponse(path, media_type="text/html", headers={"Content-Security-Policy": "frame-ancestors 'none'"})

    @app.get("/runs/{run_id}/findings.json")
    def run_findings(run_id: str):
        path = settings.runs_dir / run_id / "findings.json"
        if not get_run_or_none(run_id) or not path.exists():
            return JSONResponse({"error": "No existe"}, status_code=404)
        return FileResponse(path, media_type="application/json")

    return app
