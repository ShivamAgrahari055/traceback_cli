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
            # Custom JSON encoder to handle datetime
            def json_serial(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                raise TypeError(f"Type {type(obj)} not serializable")
            
            # Convert Events to dicts and serialize
            event_dicts = [e.dict() if hasattr(e, 'dict') else e.__dict__ for e in events_list]
            events_json = json.dumps(event_dicts, default=json_serial)
            
            conn.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?)",
                (incident_id, datetime.now(), severity, summary, events_json)
            )
            conn.commit()

    def get_all_incidents(self):
        with sqlite3.connect(self.db_//db_path) as conn:
            cursor = conn.execute("SELECT * FROM incidents")
            return cursor.fetchall()
