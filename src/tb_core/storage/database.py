"""SQLite storage for incident history.

Persists incident metadata, analysis timestamps, severity, event summaries
and report locations. Raw log files are not duplicated; only event summaries
are stored.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _json_serial(obj: Any) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def _event_to_dict(event: Any) -> Dict[str, Any]:
    if hasattr(event, "model_dump"):
        return event.model_dump()
    if hasattr(event, "dict"):
        return event.dict()
    return dict(event)


class IncidentDatabase:
    def __init__(self, db_path: str = "traceback_history.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    severity TEXT,
                    summary TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    primary_error TEXT,
                    affected_services TEXT,
                    confidence TEXT,
                    report_path TEXT,
                    created_at TEXT,
                    raw_json TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT,
                    event_id TEXT,
                    timestamp TEXT,
                    level TEXT,
                    message TEXT,
                    service TEXT,
                    request_id TEXT,
                    trace_id TEXT,
                    source_file TEXT,
                    line_number INTEGER,
                    exception_type TEXT,
                    stack_trace TEXT,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                )
                """
            )
            conn.commit()

    def save_incident(
        self,
        incident_id: str,
        title: str,
        severity: str,
        summary: str,
        events: List[Any],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        primary_error: Optional[str] = None,
        affected_services: Optional[List[str]] = None,
        confidence: str = "MEDIUM",
        report_path: Optional[str] = None,
    ) -> None:
        affected_services_json = json.dumps(affected_services or [])
        events_json = json.dumps(
            [_event_to_dict(e) for e in events], default=_json_serial
        )
        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents
                (id, title, severity, summary, start_time, end_time,
                 primary_error, affected_services, confidence, report_path,
                 created_at, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    title,
                    severity,
                    summary,
                    start_time.isoformat() if start_time else None,
                    end_time.isoformat() if end_time else None,
                    primary_error,
                    affected_services_json,
                    confidence,
                    report_path,
                    now,
                    events_json,
                ),
            )
            # Store individual events for timeline lookup
            conn.execute(
                "DELETE FROM incident_events WHERE incident_id = ?", (incident_id,)
            )
            for ev in events:
                ev_dict = _event_to_dict(ev)
                conn.execute(
                    """
                    INSERT INTO incident_events
                    (incident_id, event_id, timestamp, level, message, service,
                     request_id, trace_id, source_file, line_number,
                     exception_type, stack_trace)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident_id,
                        ev_dict.get("event_id"),
                        ev_dict.get("timestamp").isoformat()
                        if hasattr(ev_dict.get("timestamp"), "isoformat")
                        else ev_dict.get("timestamp"),
                        ev_dict.get("level"),
                        ev_dict.get("message"),
                        ev_dict.get("service"),
                        ev_dict.get("request_id"),
                        ev_dict.get("trace_id"),
                        ev_dict.get("source_file"),
                        ev_dict.get("line_number"),
                        ev_dict.get("exception_type"),
                        ev_dict.get("stack_trace"),
                    ),
                )
            conn.commit()

    def get_all_incidents(self) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT id, title, severity, summary, start_time, end_time,
                       primary_error, affected_services, confidence, report_path,
                       created_at
                FROM incidents ORDER BY created_at DESC
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT id, title, severity, summary, start_time, end_time,
                       primary_error, affected_services, confidence, report_path,
                       created_at, raw_json
                FROM incidents WHERE id = ?
                """,
                (incident_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_events_for_incident(self, incident_id: str) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT event_id, timestamp, level, message, service,
                       request_id, trace_id, source_file, line_number,
                       exception_type, stack_trace
                FROM incident_events WHERE incident_id = ?
                ORDER BY timestamp
                """,
                (incident_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def search_incidents(self, query: str) -> List[Dict[str, Any]]:
        like = f"%{query}%"
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT id, title, severity, summary, start_time, end_time,
                       primary_error, affected_services, confidence, report_path,
                       created_at
                FROM incidents
                WHERE title LIKE ? OR summary LIKE ? OR primary_error LIKE ?
                   OR affected_services LIKE ?
                ORDER BY created_at DESC
                """,
                (like, like, like, like),
            )
            return [dict(row) for row in cursor.fetchall()]

    def delete_incident(self, incident_id: str, confirm: bool = False) -> bool:
        if not confirm:
            return False
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM incident_events WHERE incident_id = ?", (incident_id,)
            )
            cursor = conn.execute(
                "DELETE FROM incidents WHERE id = ?", (incident_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
