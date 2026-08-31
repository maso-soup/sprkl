"""SQLite access layer.

`params=None` runs a statement exactly as given, which is how callers that build
SQL by concatenation reach the driver. Every statement — parameterised or not —
goes through the same tap, so the instrumentation is not a tell.
"""
import os, sqlite3, time, threading
from . import config, tap

_local = threading.local()


def _connect():
    os.makedirs(config.DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.create_function("sleep", 1, lambda s: (time.sleep(min(float(s or 0), 5)) or 0))
    return conn


def get_db():
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _local.conn = _connect()
    return conn


def query(sql, params=(), one=False):
    """Run a statement. `params=None` executes it as-is, with no binding."""
    t0, err, rows = time.perf_counter(), None, []
    try:
        rows = get_db().execute(sql, params if params is not None else ()).fetchall()
        return (rows[0] if rows else None) if one else rows
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        raise
    finally:
        tap.emit("sql.exec", sql=sql, parameterised=params is not None, error=err,
                 rows=len(rows), ms=round((time.perf_counter() - t0) * 1000, 2))


def execute(sql, params=()):
    t0, err = time.perf_counter(), None
    conn = get_db()
    try:
        cur = conn.execute(sql, params if params is not None else ())
        conn.commit()
        return cur.lastrowid
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        raise
    finally:
        tap.emit("sql.exec", sql=sql, parameterised=params is not None, error=err,
                 rows=0, ms=round((time.perf_counter() - t0) * 1000, 2))


def raw_query(sql):
    return query(sql, None)


def init_schema():
    conn = _connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, email TEXT, password TEXT, pw_md5 TEXT,
            name TEXT, role TEXT DEFAULT 'customer', org_id INTEGER,
            address TEXT, loyalty INTEGER DEFAULT 0, secret TEXT
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY, slug TEXT, name TEXT, flavor TEXT,
            price REAL, in_stock INTEGER DEFAULT 1, listed INTEGER DEFAULT 1,
            spec_xml TEXT, secret TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY, user_id INTEGER, total REAL,
            status TEXT, ref TEXT, secret TEXT
        );
        CREATE TABLE IF NOT EXISTS coupons (
            code TEXT PRIMARY KEY, kind TEXT, value TEXT, used INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS coupon_redemptions (
            id INTEGER PRIMARY KEY, code TEXT, actor TEXT
        );
        CREATE TABLE IF NOT EXISTS solves (
            id INTEGER PRIMARY KEY, finding_id TEXT, actor TEXT,
            evidence TEXT, ts REAL,
            UNIQUE(finding_id, actor)
        );
        CREATE TABLE IF NOT EXISTS canaries (
            token TEXT PRIMARY KEY, owner TEXT, kind TEXT
        );
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY, product_id INTEGER, author TEXT, body TEXT
        );
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY, email TEXT, subject TEXT, message TEXT, actor TEXT
        );
        CREATE TABLE IF NOT EXISTS giftcards (
            id INTEGER PRIMARY KEY, owner_id INTEGER, code TEXT, balance REAL, secret TEXT
        );
        CREATE TABLE IF NOT EXISTS wallet (
            user_id INTEGER PRIMARY KEY, balance REAL
        );
        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY, code TEXT, owner_id INTEGER, redeemed_by TEXT
        );
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, action TEXT, actor TEXT, ts REAL
        );
        CREATE TABLE IF NOT EXISTS flags (
            name TEXT PRIMARY KEY, value TEXT
        );
        CREATE TABLE IF NOT EXISTS wishlists (
            id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, secret TEXT
        );
        """
    )
    conn.commit()
    conn.close()
