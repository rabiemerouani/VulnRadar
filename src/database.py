import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

# Retrieve database path from .env (or use default value)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulnradar.db")
DB_PATH = DATABASE_URL.replace("sqlite:///./", "")

def get_db_connection():
    """Establishes a connection and explicitly enables foreign key support."""
    conn = sqlite3.connect(DB_PATH)
    # Allows accessing columns by name like a dictionary
    conn.row_factory = sqlite3.Row  
    # CRITICAL: SQLite disables foreign key constraints by default
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    """Creates the tables in the correct order respecting dependencies."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Table 1: Scans
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL, -- pending, running, completed, failed
                hosts_found INTEGER DEFAULT 0
            );
        """)

        # Table 2: Hosts (Depends on Scans)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                status TEXT NOT NULL, -- up, down
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # Table 3: Ports (Depends on Hosts)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port_number INTEGER NOT NULL,
                protocol TEXT NOT NULL, -- tcp, udp
                service_name TEXT,
                service_version TEXT,
                state TEXT NOT NULL, -- open, closed, filtered
                FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
            );
        """)

        # Table 4: CVE Findings (Depends on Ports)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL, -- e.g., CVE-2023-12345
                description TEXT,
                cvss_score REAL, -- Decimal value (e.g., 7.5)
                severity TEXT, -- LOW, MEDIUM, HIGH, CRITICAL
                FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
            );
        """)

        conn.commit()
        print("[+] VulnRadar database initialized successfully.")
    except Exception as e:
        conn.rollback()
        print(f"[-] Error during database initialization: {e}")
        raise e
    finally:
        conn.close()

# ==========================================
# INSERTION FUNCTIONS (WRITES)
# ==========================================

def create_scan(target: str) -> int:
    """Inserts a new scan with 'pending' status and returns its generated ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO scans (target, status) VALUES (?, ?);",
            (target, "pending")
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        conn.rollback()
        print(f"[-] Error in create_scan: {e}")
        return None
    finally:
        conn.close()

def update_scan_status(scan_id: int, status: str, hosts_found: int = 0):
    """Updates the status and the number of discovered hosts for a scan."""
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE scans SET status = ?, hosts_found = ? WHERE id = ?;",
            (status, hosts_found, scan_id)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[-] Error in update_scan_status: {e}")
    finally:
        conn.close()

def save_host(scan_id: int, ip: str, hostname: str, status: str) -> int:
    """Saves a discovered host and returns its generated ID (cursor.lastrowid)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO hosts (scan_id, ip, hostname, status) VALUES (?, ?, ?, ?);",
            (scan_id, ip, hostname, status)
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        conn.rollback()
        print(f"[-] Error in save_host: {e}")
        return None
    finally:
        conn.close()

def save_port(host_id: int, port_number: int, protocol: str, service_name: str, service_version: str, state: str) -> int:
    """Saves an open port found on a host and returns its generated ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO ports (host_id, port_number, protocol, service_name, service_version, state) 
               VALUES (?, ?, ?, ?, ?, ?);""",
            (host_id, port_number, protocol, service_name, service_version, state)
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        conn.rollback()
        print(f"[-] Error in save_port: {e}")
        return None
    finally:
        conn.close()

def save_cve(port_id: int, cve_id: str, description: str, cvss_score: float, severity: str) -> int:
    """Saves a CVE vulnerability vulnerability tied to a specific port."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO cve_findings (port_id, cve_id, description, cvss_score, severity) 
               VALUES (?, ?, ?, ?, ?);""",
            (port_id, cve_id, description, cvss_score, severity)
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        conn.rollback()
        print(f"[-] Error in save_cve: {e}")
        return None
    finally:
        conn.close()

# ==========================================
# RETRIEVAL FUNCTIONS (READS)
# ==========================================

def get_all_scans():
    """Retrieves the global history of all executed scans."""
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM scans ORDER BY start_time DESC;").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_scan_details(scan_id: int) -> dict:
    """
    Retrieves a complete scan tree structure (Scan -> Hosts -> Ports -> CVEs).
    Optimized hierarchical format for API payloads and Frontend usage.
    """
    conn = get_db_connection()
    try:
        # 1. Parent Scan Information
        scan_row = conn.execute("SELECT * FROM scans WHERE id = ?;", (scan_id,)).fetchone()
        if not scan_row:
            return None
        
        scan_dict = dict(scan_row)
        scan_dict["hosts"] = []

        # 2. Retrieve hosts tied to the scan
        hosts_rows = conn.execute("SELECT * FROM hosts WHERE scan_id = ?;", (scan_id,)).fetchall()
        for h_row in hosts_rows:
            host_dict = dict(h_row)
            host_dict["ports"] = []
            
            # 3. Retrieve open ports for each host
            ports_rows = conn.execute("SELECT * FROM ports WHERE host_id = ?;", (host_dict["id"],)).fetchall()
            for p_row in ports_rows:
                port_dict = dict(p_row)
                port_dict["cves"] = []
                
                # 4. Retrieve CVEs associated with this port
                cve_rows = conn.execute("SELECT * FROM cve_findings WHERE port_id = ?;", (port_dict["id"],)).fetchall()
                port_dict["cves"] = [dict(c) for c in cve_rows]
                
                host_dict["ports"].append(port_dict)
            
            scan_dict["hosts"].append(host_dict)
            
        return scan_dict
    finally:
        conn.close()