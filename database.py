import sqlite3
from werkzeug.security import generate_password_hash
from datetime import datetime

DATABASE = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # ===== Create users table =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            office TEXT,
            status TEXT DEFAULT 'Active',
            role TEXT NOT NULL
        )
    """)

    # ===== Create default admin =====
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if cursor.fetchone() is None:
        cursor.execute("""
            INSERT INTO users (name, username, password, office, status, role)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            'Administrator',
            'admin',
            generate_password_hash('admin123'),
            'Head Office',
            'Active',
            'admin'
        ))

    # ===== Create audit_trail table =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            office TEXT,
            action TEXT NOT NULL,
            date_time TEXT NOT NULL
        )
    """)

    # ===== Create signatories table =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS signatories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            office_department TEXT NOT NULL,
            designation TEXT NOT NULL,
            date_added TEXT NOT NULL,
            added_by TEXT NOT NULL,
            edited_by TEXT,
            date_edited TEXT,
            remarks TEXT
        )
    """)

    # ===== Create issued_control_no table =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS issued_control_no (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_no TEXT NOT NULL,
            amount REAL NOT NULL,
            office TEXT NOT NULL,
            program TEXT NOT NULL,
            code TEXT NOT NULL,
            source_of_fund TEXT NOT NULL,
            issued_date TEXT NOT NULL,
            issued_by TEXT NOT NULL,
            received INTEGER NOT NULL DEFAULT 0,
            received_date TEXT,
            received_by TEXT,
            -- ✅ newly added columns
            date_edited TEXT,
            edited_by TEXT,
            reason_for_editing TEXT
        )
    """)

    # ===== Create transmitting_documents table =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transmitting_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_no TEXT NOT NULL,
            code TEXT NOT NULL,
            project_title TEXT,
            document_type TEXT NOT NULL,
            amount REAL,
            source_of_fund TEXT,
            send_to TEXT NOT NULL,
            file_path TEXT,
            signatories TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            send_by TEXT NOT NULL,
            office TEXT,                  -- ✅ NEW COLUMN (after send_by)
            received INTEGER NOT NULL DEFAULT 0,
            received_date TEXT,
            received_by TEXT,
            obr_no TEXT
        )
    """)

    # ===== Create obligated_documents table =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS obligated_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            transmitting_id INTEGER,         -- original transmitting_documents.id (for reference)
            control_no TEXT NOT NULL,
            code TEXT NOT NULL,
            document_type TEXT NOT NULL,
            program TEXT NOT NULL,
            amount REAL,
            source_of_fund TEXT,
            obr_no TEXT NOT NULL,
            status TEXT NOT NULL,

            obligated_by TEXT NOT NULL,
            obligated_office TEXT NOT NULL,
            obligated_date TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_obligated_unique
        ON obligated_documents(control_no, code, obr_no)
    """)


    # ===== Create returned_documents table (FOR SIGNATURE RETURNS) =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS returned_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_no TEXT NOT NULL,
            code TEXT NOT NULL,
            document_type TEXT NOT NULL,
            program TEXT NOT NULL,
            amount REAL NOT NULL,
            source_of_fund TEXT NOT NULL,
            returned_by TEXT NOT NULL,
            office TEXT,                  -- office of the user who returned (MBO)
            returned_to TEXT NOT NULL,    -- sender office (OME, etc.)
            returned_date TEXT NOT NULL,
            returned_reason TEXT NOT NULL,
            status TEXT NOT NULL,
            received INTEGER NOT NULL DEFAULT 0,
            received_date TEXT,
            received_by TEXT
        )
    """)

    # ===== Create returned_documents_obligation table (FOR OBLIGATION RETURNS) =====
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS returned_documents_obligation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_no TEXT NOT NULL,
            code TEXT NOT NULL,
            document_type TEXT NOT NULL,
            program TEXT NOT NULL,
            amount REAL NOT NULL,
            source_of_fund TEXT NOT NULL,

            returned_by TEXT NOT NULL,
            office TEXT,                  -- office of the user who returned (MBO)
            returned_to TEXT NOT NULL,    -- sender office (OME, etc.)
            returned_date TEXT NOT NULL,

            received INTEGER NOT NULL DEFAULT 0,
            received_date TEXT,
            received_by TEXT,

            returned_reason TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    # =========================================================
    # ✅ NEW: saved_documents_backup table
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS saved_documents_backup (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_no TEXT NOT NULL,
            code TEXT NOT NULL,
            document_type TEXT NOT NULL,
            program TEXT NOT NULL,
            amount REAL NOT NULL,
            file_path TEXT,
            office TEXT NOT NULL,
            saved_date TEXT NOT NULL,
            saved_by TEXT NOT NULL
        )
    """)

    # ✅ unique constraint (prevents saving same doc twice)
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_saved_doc
        ON saved_documents_backup (control_no, code, document_type)
    """)

    # =========================================================
    # ✅ NEW: signed_documents table
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS signed_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_no TEXT NOT NULL,
            code TEXT NOT NULL,
            document_type TEXT NOT NULL,
            program TEXT NOT NULL,
            amount REAL NOT NULL,
            source_of_fund TEXT NOT NULL,
            file_path TEXT,
            office TEXT NOT NULL,
            signed_date TEXT NOT NULL,
            signed_by TEXT NOT NULL,
            action_office TEXT NOT NULL,
            remarks TEXT,
            status TEXT NOT NULL
        )
    """)

    # ✅ prevent signing the same doc twice (optional but recommended)
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_signed_doc
        ON signed_documents (control_no, code, document_type)
    """)




    conn.commit()
    conn.close()
