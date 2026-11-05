import pytest
from fastapi.testclient import TestClient

from lab.settings import Settings
from lab.web.app import create_app

TOKEN = "test-token-123"


@pytest.fixture
def client(tmp_path):
    settings = Settings(tmp_path, tmp_path / "runs", tmp_path / "rules", "http://x", "tok", TOKEN)
    settings.runs_dir.mkdir()
    app = create_app(settings, start_worker=False)
    test_client = TestClient(app, base_url="http://localhost:8000", follow_redirects=False)
    test_client.settings = settings
    return test_client


@pytest.fixture
def logged(client):
    assert client.get(f"/?token={TOKEN}").status_code == 303
    return client


def test_without_token_there_is_no_access(client):
    assert client.get("/").status_code == 401
    assert client.post("/scans", data={"preset": "juice-shop"}).status_code == 401


def test_wrong_token_is_rejected(client):
    assert client.get("/?token=mal").status_code == 401


def test_token_becomes_an_httponly_strict_cookie_and_leaves_the_url(client):
    response = client.get(f"/?token={TOKEN}")
    assert response.headers["location"] == "/"
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert TOKEN not in response.headers["set-cookie"]


def test_foreign_host_is_rejected_dns_rebinding(logged):
    assert logged.get("/", headers={"host": "evil.example"}).status_code == 403


def test_foreign_origin_cannot_launch_scans_csrf(logged):
    response = logged.post("/scans", data={"preset": "juice-shop"}, headers={"origin": "https://evil.example"})
    assert response.status_code == 403


def test_preset_launches_and_redirects(logged):
    response = logged.post("/scans", data={"preset": "juice-shop"}, headers={"origin": "http://localhost:8000"})
    assert response.status_code == 303 and response.headers["location"].startswith("/runs/")
    page = logged.get(response.headers["location"])
    assert page.status_code == 200 and "Juice Shop" in page.text


def test_external_url_without_authorization_is_refused(logged):
    response = logged.post("/scans", data={"url": "https://example.com"})
    assert response.status_code == 400 and "autorización" in response.text
    assert "https://example.com" in response.text  # El formulario conserva lo escrito.


def test_active_without_second_confirmation_is_refused(logged):
    response = logged.post("/scans", data={"url": "https://example.com", "mode": "active", "authorized": "on"})
    assert response.status_code == 400 and "activo" in response.text


def test_authorized_scan_is_accepted_and_recorded(logged):
    response = logged.post("/scans", data={"url": "https://example.com", "authorized": "on"})
    assert response.status_code == 303
    run_id = response.headers["location"].rsplit("/", 1)[-1]
    assert logged.app.state.store.get_run(run_id)["request"]["authorized"] is True


def test_web_cannot_scan_local_paths(logged):
    response = logged.post("/scans", data={"local_path": "/etc", "repo": ""})
    assert response.status_code == 400


def test_bad_ref_is_refused(logged):
    response = logged.post("/scans", data={"repo": "https://github.com/a/b", "ref": "--upload-pack=x"})
    assert response.status_code == 400


@pytest.mark.parametrize("run_id", ["..%2f..%2fetc", "20260101", "x" * 40, "20260101-000000-zzzz"])
def test_invalid_run_ids_are_not_found(logged, run_id):
    assert logged.get(f"/runs/{run_id}").status_code == 404
    assert logged.get(f"/runs/{run_id}/report").status_code == 404


def test_target_is_escaped_in_history(logged):
    logged.app.state.store.create_run("20260101-000000-abcd", "<script>x</script>", {})
    assert "<script>x</script>" not in logged.get("/").text


def test_pages_have_security_headers(logged):
    headers = logged.get("/").headers
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"


def test_events_endpoint_reports_stages(logged):
    response = logged.post("/scans", data={"preset": "juice-shop"})
    run_id = response.headers["location"].rsplit("/", 1)[-1]
    data = logged.get(f"/runs/{run_id}/events.json").json()
    assert data["finished"] is False
    assert [s["id"] for s in data["stages"]] == ["source", "semgrep", "sonar", "zap", "report"]


def test_interrupted_runs_are_marked_on_start(tmp_path):
    from lab.store import Store

    settings = Settings(tmp_path, tmp_path / "runs", tmp_path / "rules", "http://x", "tok", TOKEN)
    settings.runs_dir.mkdir()
    Store(settings.db_path).create_run("20260101-000000-abcd", "x", {}, status="running")
    create_app(settings, start_worker=False)
    run = Store(settings.db_path).get_run("20260101-000000-abcd")
    assert run["status"] == "error" and "Interrumpido" in run["summary"]["message"]
