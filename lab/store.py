"""Historial de ejecuciones en SQLite."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  target TEXT NOT NULL,
  request TEXT NOT NULL,
  summary TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES runs(id),
  at TEXT NOT NULL,
  stage TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_run ON events(run_id, id);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        with self._connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def create_run(self, run_id: str, target: str, request: dict, status: str = "queued") -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO runs (id, created_at, status, target, request) VALUES (?, ?, ?, ?, ?)",
                (run_id, now(), status, target, json.dumps(request)),
            )

    def set_status(self, run_id: str, status: str) -> None:
        with self._connect() as db:
            db.execute("UPDATE runs SET status = ? WHERE id = ?", (status, run_id))

    def finish_run(self, run_id: str, status: str, summary: dict | None) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE runs SET status = ?, finished_at = ?, summary = ? WHERE id = ?",
                (status, now(), json.dumps(summary) if summary else None, run_id),
            )

    def add_event(self, run_id: str, stage: str, status: str, message: str = "") -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO events (run_id, at, stage, status, message) VALUES (?, ?, ?, ?, ?)",
                (run_id, now(), stage, status, message),
            )

    def get_run(self, run_id: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._row(row) if row else None

    def list_runs(self, limit: int = 50) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM runs ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(row) for row in rows]

    def events(self, run_id: str) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT at, stage, status, message FROM events WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
        return [dict(row) for row in rows]

    def mark_interrupted(self) -> int:
        """Lo que estaba en curso al arrancar ya no sigue vivo."""
        with self._connect() as db:
            cursor = db.execute(
                "UPDATE runs SET status = 'error', finished_at = ?, "
                "summary = '{\"message\": \"Interrumpido: el servicio se reinició\"}' "
                "WHERE status IN ('queued', 'running')",
                (now(),),
            )
            return cursor.rowcount

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["request"] = json.loads(data["request"])
        data["summary"] = json.loads(data["summary"]) if data.get("summary") else None
        return data
