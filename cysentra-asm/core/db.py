import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


DB_PATH = "data/cysentra_asm.db"


class DatabaseManager:
    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        Path("data").mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.create_tables()

    def create_tables(self) -> None:
        cursor = self.conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_domain TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            timestamp_utc TEXT NOT NULL
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            subdomain TEXT NOT NULL,
            resolves INTEGER NOT NULL,
            ip_addresses TEXT,
            http_status INTEGER,
            https_status INTEGER,
            http_title TEXT,
            https_title TEXT,
            http_server TEXT,
            https_server TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """)

        self.conn.commit()

    def insert_scan(self, target_domain: str, scan_type: str, timestamp_utc: str) -> int:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (target_domain, scan_type, timestamp_utc)
            VALUES (?, ?, ?)
            """,
            (target_domain, scan_type, timestamp_utc),
        )
        self.conn.commit()
        return cursor.lastrowid

    def insert_asset(self, scan_id: int, asset: Dict[str, Any]) -> None:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO assets (
                scan_id, subdomain, resolves, ip_addresses,
                http_status, https_status,
                http_title, https_title,
                http_server, https_server
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                asset["subdomain"],
                int(asset["resolves"]),
                ",".join(asset.get("ip_addresses", [])),
                asset.get("http_status"),
                asset.get("https_status"),
                asset.get("http_title"),
                asset.get("https_title"),
                asset.get("http_server"),
                asset.get("https_server"),
            ),
        )
        self.conn.commit()

    def get_previous_scan_id(self, target_domain: str, current_scan_id: int) -> Optional[int]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT id
            FROM scans
            WHERE target_domain = ?
              AND id < ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (target_domain, current_scan_id),
        )
        row = cursor.fetchone()
        return row["id"] if row else None

    def get_assets_by_scan_id(self, scan_id: int) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT *
            FROM assets
            WHERE scan_id = ?
            """,
            (scan_id,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        self.conn.close()
