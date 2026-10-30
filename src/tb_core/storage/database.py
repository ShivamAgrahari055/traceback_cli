import sqlite3
import json
from datetime import datetime

class IncidentDatabase:
    def __init__(self, db_path="traceback_history.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    timestamp DATETIME,
                    severity TEXT,
                    summary TEXT,
                    raw_json TEXT
                )
            """)
            conn.commit()

    def save_incident(self, incident_id, severity, summary, events_list):
        with sqlite3.connect(self.db_path) as conn:
            # Store events as JSON string
            events_json = json.dumps([e.dict() if hasattr(e, 'dict') else e for e in events_list])
            conn.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?)",
                (incident_id, datetime.now(), severity, summary, events_json)
            )
            conn.commit()

    def get_all_incidents(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM incidents")
            return cursor.fetchall()
