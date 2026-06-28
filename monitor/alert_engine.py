"""
AlertEngine Module
--------------------
Responsible for persisting alert records when TrafficClassifier
flags a packet as INSECURE, and for retrieving the alert log for
display on the Dashboard.

Uses SQLite for lightweight, file-based storage with no external
database server required (Chapter 3, Section 3.4: Tools).

Schema matches Chapter 4, Section 4.4.4 (Database Schema):
    alert_id          INTEGER PRIMARY KEY AUTOINCREMENT
    source_ip         TEXT NOT NULL
    destination_ip    TEXT NOT NULL
    protocol          TEXT NOT NULL
    destination_port  INTEGER NOT NULL
    timestamp         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    classification    TEXT NOT NULL DEFAULT 'INSECURE'
"""

import sqlite3
import os


class AlertEngine:
    """
    Manages alert persistence and retrieval using SQLite.

    Attributes:
        db_path (str): Filesystem path to the SQLite database file.
    """

    def __init__(self, db_path: str = "data/alerts.db"):
        self.db_path = db_path
        self._ensure_data_dir_exists()
        self._create_table_if_not_exists()

    def _ensure_data_dir_exists(self):
        """Creates the data/ directory if it doesn't already exist."""
        directory = os.path.dirname(self.db_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)

    def _get_connection(self):
        """Returns a new SQLite connection. A fresh connection per
        operation keeps this safe to call from multiple threads
        (PacketCapture's sniff loop and Flask run on separate threads)."""
        return sqlite3.connect(self.db_path)

    def _create_table_if_not_exists(self):
        """Creates the alerts table if it doesn't already exist."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                destination_port INTEGER,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                classification TEXT NOT NULL DEFAULT 'INSECURE'
            )
        """)
        conn.commit()
        conn.close()

    def generate_alert(self, metadata: dict) -> int:
        """
        Inserts a new alert record into the database.

        Args:
            metadata (dict): Output of TrafficClassifier.extract_metadata(),
                expected to contain source_ip, destination_ip, protocol,
                destination_port, timestamp, and classification.

        Returns:
            int: The alert_id of the newly inserted row.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts
                (source_ip, destination_ip, protocol, destination_port, timestamp, classification)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            metadata.get("source_ip"),
            metadata.get("destination_ip"),
            metadata.get("protocol"),
            metadata.get("destination_port"),
            metadata.get("timestamp"),
            metadata.get("classification", "INSECURE"),
        ))
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()
        return new_id

    def get_alert_log(self, limit: int = 100) -> list:
        """
        Retrieves the most recent alert records, newest first.

        Args:
            limit (int): Maximum number of records to return.

        Returns:
            list[dict]: Alert records as dictionaries.
        """
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM alerts
            ORDER BY alert_id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def get_alert_count(self) -> int:
        """Returns the total number of alerts ever recorded."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def get_count_by_protocol(self, protocol: str) -> int:
        """Returns the count of alerts matching a specific protocol
        (e.g. 'HTTP', 'FTP', 'Telnet'). Used for the dashboard's
        per-protocol summary cards."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE protocol = ?", (protocol,))
        count = cursor.fetchone()[0]
        conn.close()
        return count
