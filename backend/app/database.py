import sqlite3
import os
from contextlib import contextmanager
from app.config import settings

def get_db_path() -> str:
    return os.environ.get("VULNSCAN_DB", settings.VULNSCAN_DB)

@contextmanager
def get_db_connection():
    db_path = get_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True) if os.path.dirname(db_path) else None
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                environment TEXT NOT NULL,
                criticality TEXT NOT NULL,
                open_ports TEXT NOT NULL,
                last_scanned TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                asset_ip TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                title TEXT NOT NULL,
                service TEXT NOT NULL,
                port INTEGER NOT NULL,
                cvss_vector TEXT NOT NULL,
                base_score REAL NOT NULL,
                severity TEXT NOT NULL,
                impact_score REAL NOT NULL,
                exploitability_score REAL NOT NULL,
                description TEXT NOT NULL,
                remediation TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'UNREMEDIATED',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
            );
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);")

        # Seed initial assets if empty
        cursor.execute("SELECT count(*) FROM assets")
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO assets (id, name, ip_address, environment, criticality, open_ports)
                VALUES 
                ('ast-gateway', 'prod-api-gateway-01', '10.0.1.15', 'PROD', 'CRITICAL', '80,443,8080'),
                ('ast-cache', 'staging-cache-cluster', '10.0.2.40', 'STAGING', 'HIGH', '6379,443'),
                ('ast-corp', 'internal-dc-auth', '192.168.1.10', 'INTERNAL', 'CRITICAL', '445')
            """)
        conn.commit()
