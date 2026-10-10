"""
Database manager for SQLite (with optional MySQL fallback).
Handles database initialization, schema execution, and connection helpers.
"""

import sqlite3
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "threat_correlation.db"
SCHEMA_PATH = BASE_DIR / "data" / "schema.sql"


def get_db_connection():
    """Returns a SQLite connection with row_factory set to sqlite3.Row."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Initializes the database using schema.sql."""
    os.makedirs(DB_PATH.parent, exist_ok=True)
    with get_db_connection() as conn:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()
    print(f"[DB] Initialized database at {DB_PATH}")


def dict_from_row(row):
    """Converts a sqlite3.Row or dict to a regular dictionary."""
    if row is None:
        return None
    return dict(row)


def dict_list(rows):
    """Converts a list of sqlite3.Row objects to a list of dicts."""
    return [dict(r) for r in rows]
