import sqlite3
import os
import json
import logging
from typing import Dict, List, Any, Tuple

logger = logging.getLogger("cspm.db")

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cspm.db")

def get_connection():
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables for scan runs and security findings."""
    logger.info(f"Initializing SQLite database at: {DB_FILE}")
    conn = get_connection()
    cursor = conn.cursor()
    
    # Enable foreign keys
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # Scans table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        score INTEGER NOT NULL,
        total_checks INTEGER NOT NULL,
        failed_checks INTEGER NOT NULL,
        critical_count INTEGER NOT NULL,
        high_count INTEGER NOT NULL,
        medium_count INTEGER NOT NULL,
        low_count INTEGER NOT NULL,
        is_mock INTEGER NOT NULL,
        regions TEXT NOT NULL
    );
    """)
    
    # Findings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        service TEXT NOT NULL,
        check_id TEXT NOT NULL,
        check_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        region TEXT NOT NULL,
        message TEXT NOT NULL,
        remediation TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    );
    """)

    # Settings table for Slack/Email integrations
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """)
    
    conn.commit()
    conn.close()

def save_scan(
    scan_id: str,
    timestamp: str,
    score: int,
    findings: List[Dict[str, Any]],
    is_mock: bool,
    regions: List[str]
) -> None:
    """Save a scan run and all its findings inside a database transaction."""
    conn = get_connection()
    cursor = conn.cursor()
    
    total_checks = len(findings)
    failed_checks = sum(1 for f in findings if f["status"] in ["FAIL", "WARNING"])
    
    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL" and f["status"] in ["FAIL", "WARNING"])
    high_count = sum(1 for f in findings if f["severity"] == "HIGH" and f["status"] in ["FAIL", "WARNING"])
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM" and f["status"] in ["FAIL", "WARNING"])
    low_count = sum(1 for f in findings if f["severity"] == "LOW" and f["status"] in ["FAIL", "WARNING"])
    
    try:
        # Insert scan summary
        cursor.execute("""
        INSERT INTO scans (id, timestamp, score, total_checks, failed_checks, critical_count, high_count, medium_count, low_count, is_mock, regions)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            scan_id,
            timestamp,
            score,
            total_checks,
            failed_checks,
            critical_count,
            high_count,
            medium_count,
            low_count,
            1 if is_mock else 0,
            ",".join(regions)
        ))
        
        # Insert findings
        for idx, f in enumerate(findings):
            finding_id = f"{scan_id}_{idx}"
            cursor.execute("""
            INSERT INTO findings (id, scan_id, service, check_id, check_name, severity, status, resource_id, region, message, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                finding_id,
                scan_id,
                f["service"],
                f["check_id"],
                f["check_name"],
                f["severity"],
                f["status"],
                f["resource_id"],
                f["region"],
                f["message"],
                f["remediation"]
            ))
            
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Error saving scan to database: {e}")
        raise e
    finally:
        conn.close()

def get_scan_history() -> List[Dict[str, Any]]:
    """Retrieve summaries of all past scans sorted by timestamp descending."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC;")
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for r in rows:
        history.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "score": r["score"],
            "total_checks": r["total_checks"],
            "failed_checks": r["failed_checks"],
            "critical_count": r["critical_count"],
            "high_count": r["high_count"],
            "medium_count": r["medium_count"],
            "low_count": r["low_count"],
            "is_mock": bool(r["is_mock"]),
            "regions": r["regions"].split(",") if r["regions"] else []
        })
    return history

def get_scan_details(scan_id: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Retrieve full details of a specific scan run, including all individual findings."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get scan summary
    cursor.execute("SELECT * FROM scans WHERE id = ?;", (scan_id,))
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        raise ValueError(f"Scan ID '{scan_id}' not found.")
        
    scan_summary = {
        "id": scan_row["id"],
        "timestamp": scan_row["timestamp"],
        "score": scan_row["score"],
        "total_checks": scan_row["total_checks"],
        "failed_checks": scan_row["failed_checks"],
        "critical_count": scan_row["critical_count"],
        "high_count": scan_row["high_count"],
        "medium_count": scan_row["medium_count"],
        "low_count": scan_row["low_count"],
        "is_mock": bool(scan_row["is_mock"]),
        "regions": scan_row["regions"].split(",") if scan_row["regions"] else []
    }
    
    # Get findings
    cursor.execute("SELECT * FROM findings WHERE scan_id = ?;", (scan_id,))
    finding_rows = cursor.fetchall()
    conn.close()
    
    findings = []
    for r in finding_rows:
        findings.append({
            "service": r["service"],
            "check_id": r["check_id"],
            "check_name": r["check_name"],
            "severity": r["severity"],
            "status": r["status"],
            "resource_id": r["resource_id"],
            "region": r["region"],
            "message": r["message"],
            "remediation": r["remediation"]
        })
        
    return scan_summary, findings

def delete_scan(scan_id: str) -> None:
    """Delete a scan run and all cascading findings from the database."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM scans WHERE id = ?;", (scan_id,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Error deleting scan {scan_id}: {e}")
        raise e
    finally:
        conn.close()

def get_previous_scan(current_scan_id: str) -> Dict[str, Any]:
    """Get the scan immediately before the given scan_id (by timestamp) for delta comparison."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get current scan's timestamp
    cursor.execute("SELECT timestamp FROM scans WHERE id = ?;", (current_scan_id,))
    current_row = cursor.fetchone()
    if not current_row:
        conn.close()
        return None
    
    current_ts = current_row["timestamp"]
    
    # Find the most recent scan before this one
    cursor.execute(
        "SELECT * FROM scans WHERE timestamp < ? ORDER BY timestamp DESC LIMIT 1;",
        (current_ts,)
    )
    prev_row = cursor.fetchone()
    
    if not prev_row:
        conn.close()
        return None
    
    prev_scan = {
        "id": prev_row["id"],
        "timestamp": prev_row["timestamp"],
        "score": prev_row["score"],
        "total_checks": prev_row["total_checks"],
        "failed_checks": prev_row["failed_checks"],
        "critical_count": prev_row["critical_count"],
        "high_count": prev_row["high_count"],
        "medium_count": prev_row["medium_count"],
        "low_count": prev_row["low_count"],
        "is_mock": bool(prev_row["is_mock"]),
        "regions": prev_row["regions"].split(",") if prev_row["regions"] else []
    }
    
    # Get previous scan's findings for delta comparison
    cursor.execute("SELECT check_id, status FROM findings WHERE scan_id = ?;", (prev_row["id"],))
    prev_findings = cursor.fetchall()
    prev_scan["finding_statuses"] = {r["check_id"]: r["status"] for r in prev_findings}
    
    conn.close()
    return prev_scan

def get_resource_view(scan_id: str) -> List[Dict[str, Any]]:
    """Group all findings by resource_id for a resource-centric risk view."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM findings WHERE scan_id = ?;", (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    
    resource_map = {}
    for r in rows:
        rid = r["resource_id"]
        if rid not in resource_map:
            resource_map[rid] = {
                "resource_id": rid,
                "region": r["region"],
                "services": set(),
                "findings": [],
                "total_checks": 0,
                "failed_checks": 0,
                "risk_score": 0,
                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            }
        
        resource_map[rid]["services"].add(r["service"])
        resource_map[rid]["total_checks"] += 1
        
        finding_entry = {
            "check_id": r["check_id"],
            "check_name": r["check_name"],
            "severity": r["severity"],
            "status": r["status"],
            "message": r["message"],
            "service": r["service"]
        }
        resource_map[rid]["findings"].append(finding_entry)
        
        if r["status"] in ("FAIL", "WARNING"):
            resource_map[rid]["failed_checks"] += 1
            sev = r["severity"]
            if sev in resource_map[rid]["severity_counts"]:
                resource_map[rid]["severity_counts"][sev] += 1
            # Compute weighted risk score
            weight = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 8, "LOW": 3}.get(sev, 1)
            resource_map[rid]["risk_score"] += weight
    
    # Convert sets to lists for JSON serialization, then sort by risk_score descending
    result = []
    for rid, data in resource_map.items():
        data["services"] = list(data["services"])
        result.append(data)
    
    result.sort(key=lambda x: x["risk_score"], reverse=True)
    return result


def get_setting(key: str, default: str = "") -> str:
    """Retrieve a setting value by key."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?;", (key,))
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else default


def save_setting(key: str, value: str) -> None:
    """Insert or update a setting value."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO settings (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value;
    """, (key, value))
    conn.commit()
    conn.close()
