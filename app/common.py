"""Shared configuration and the SQLite state plane.

Three processes (web console / resolver / authoritative endpoint) share one
SQLite database in WAL mode:

  control   -- desired behaviour of the authoritative endpoint, written by the
               web console, read by the authoritative endpoint per query.
  cache     -- the resolver's cache.  Absolute epoch deadlines are stored, so a
               resolver restart can never extend the validity of an old A
               record; the stale window simply keeps counting down.
  query_log -- every client query the resolver answered, with its source.
  auth_log  -- every query the authoritative endpoint saw, with the action it
               took (answered / nxdomain / dropped / delayed).

The stale-answer ledger is kept here as well, so it survives resolver
restarts and process crashes:

  stale_impact  -- one row per cache-stale answer the resolver is about to
                   send: client IP/port, stale A address, time and a unique
                   query id.  The row is written *before* the datagram is
                   sent; a missing post-send confirmation leaves it
                   `unverified` (待核实) instead of `sent`.
  notify_batch  -- an immutable snapshot ("notification roster") generated for
                   a fault start time.  notify_entry rows copy the evidence of
                   every affected client at generation time; later queries or
                   late confirmations may change stale_impact but never the
                   snapshot.
  notify_ack    -- the operator's registration that a client has been
                   notified.  Kept separate so acknowledging never rewrites
                   the roster evidence.
"""
from __future__ import annotations

import os
import sqlite3
import time
import uuid

# --------------------------------------------------------------------------
# Configuration (environment overridable; defaults are the spec values).
# --------------------------------------------------------------------------
FIXED_DOMAIN = os.environ.get("FIXED_DOMAIN", "service.example").strip().rstrip(".")
FQDN = FIXED_DOMAIN + "."

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

FRESH_TTL = float(os.environ.get("FRESH_TTL", "5"))        # successful answers are fresh for 5s
STALE_WINDOW = float(os.environ.get("STALE_WINDOW", "20"))  # stale A usable <=20s after expiry
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "2.0"))

AUTH_HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("AUTH_PORT", "5354"))
RESOLVER_HOST = os.environ.get("RESOLVER_HOST", "127.0.0.1")
RESOLVER_PORT = int(os.environ.get("RESOLVER_PORT", "5353"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))

DEFAULT_IP = os.environ.get("DEFAULT_IP", "192.0.2.10")
DEFAULT_DELAY = float(os.environ.get("DEFAULT_DELAY", "3.0"))

# Drill-only fault injection for the stale-answer ledger.  Empty in normal
# operation.  "fail-prewrite" makes the pre-send insert fail (the resolver
# must answer SERVFAIL, never a stale A without evidence); "skip-confirm"
# simulates a crash between sendto() and the post-send confirmation (the
# record must stay 待核实/pending, including across a restart).
STALE_LEDGER_FAULT = os.environ.get("STALE_LEDGER_FAULT", "").strip().lower()

SCHEMA = """
CREATE TABLE IF NOT EXISTS control (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,              -- a | nxdomain | delay | timeout
  ip TEXT NOT NULL,
  delay_seconds REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  qname TEXT NOT NULL,
  rcode TEXT NOT NULL,             -- NOERROR | NXDOMAIN
  a_record TEXT,                   -- NULL once NXDOMAIN is confirmed (old A purged)
  fetched_at REAL NOT NULL,        -- last successful upstream answer (epoch)
  fresh_until REAL NOT NULL,       -- serve-fresh deadline (epoch)
  stale_until REAL,                -- A only: last moment a stale A may be served
  nx_confirmed_at REAL
);
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, source TEXT, rcode TEXT, answers TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, mode TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS stale_impact (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  query_uid TEXT NOT NULL UNIQUE,  -- unique query id minted before sending
  ts REAL NOT NULL,                -- answer time (epoch)
  client_ip TEXT NOT NULL,
  client_port INTEGER NOT NULL,
  qname TEXT NOT NULL,
  qtype TEXT NOT NULL,
  stale_a TEXT NOT NULL,           -- the old A address in the stale answer
  ttl INTEGER NOT NULL,
  detail TEXT,
  state TEXT NOT NULL CHECK (state IN ('pending', 'sent')),
  confirmed_at REAL               -- set when the post-send confirmation arrives
);
CREATE INDEX IF NOT EXISTS stale_impact_ts ON stale_impact(ts);
CREATE TABLE IF NOT EXISTS notify_batch (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fault_start REAL NOT NULL,
  window_end REAL NOT NULL,        -- generated_at: roster covers [fault_start, this]
  generated_at REAL NOT NULL,
  note TEXT
);
CREATE TABLE IF NOT EXISTS notify_entry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id INTEGER NOT NULL REFERENCES notify_batch(id),
  impact_id INTEGER NOT NULL,
  query_uid TEXT NOT NULL,         -- evidence copied at generation time
  ts REAL NOT NULL,
  client_ip TEXT NOT NULL,
  client_port INTEGER NOT NULL,
  stale_a TEXT NOT NULL,
  ttl INTEGER NOT NULL,
  state_at_snapshot TEXT NOT NULL, -- sent | unverified at generation time
  confirmed_at_at_snapshot REAL,
  detail TEXT,
  UNIQUE(batch_id, impact_id)
);
CREATE INDEX IF NOT EXISTS notify_entry_batch ON notify_entry(batch_id);
CREATE TABLE IF NOT EXISTS notify_ack (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id INTEGER NOT NULL REFERENCES notify_batch(id),
  impact_id INTEGER NOT NULL REFERENCES stale_impact(id),
  client_ip TEXT NOT NULL,
  acknowledged_at REAL NOT NULL,
  note TEXT,
  UNIQUE(batch_id, impact_id)
);
"""

_LOG_TABLES = ("query_log", "auth_log")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def init_db() -> None:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with _connect() as c:
        c.executescript(SCHEMA)
        c.execute(
            "INSERT OR IGNORE INTO control(id, mode, ip, delay_seconds, updated_at)"
            " VALUES (1, 'a', ?, ?, ?)",
            (DEFAULT_IP, DEFAULT_DELAY, time.time()),
        )


# --------------------------------------------------------------------------
# control table (web writes, authoritative endpoint reads)
# --------------------------------------------------------------------------
def get_control() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM control WHERE id = 1").fetchone()
        return dict(row) if row else None


def set_control(mode: str, ip: str, delay_seconds: float) -> None:
    with _connect() as c:
        c.execute(
            "UPDATE control SET mode = ?, ip = ?, delay_seconds = ?, updated_at = ?"
            " WHERE id = 1",
            (mode, ip, float(delay_seconds), time.time()),
        )


# --------------------------------------------------------------------------
# cache table (resolver only)
# --------------------------------------------------------------------------
def get_cache() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM cache WHERE id = 1").fetchone()
        return dict(row) if row else None


def put_cache_a(ip: str, now: float) -> None:
    """Store a freshly fetched A record: fresh for FRESH_TTL, then stale-usable
    for STALE_WINDOW more seconds.  Absolute epochs are persisted, so a restart
    does not extend either deadline."""
    with _connect() as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NOERROR', ?, ?, ?, ?, NULL)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NOERROR',"
            "   a_record = excluded.a_record, fetched_at = excluded.fetched_at,"
            "   fresh_until = excluded.fresh_until, stale_until = excluded.stale_until,"
            "   nx_confirmed_at = NULL",
            (FQDN, ip, now, now + FRESH_TTL, now + FRESH_TTL + STALE_WINDOW),
        )


def put_cache_nxdomain(now: float) -> None:
    """Confirm NXDOMAIN.  Any old A record is purged immediately and durably:
    from this moment no answer may contain the old A again, and NXDOMAIN itself
    is only cached fresh (never used as stale backup)."""
    with _connect() as c:
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at)"
            " VALUES (1, ?, 'NXDOMAIN', NULL, ?, ?, NULL, ?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NXDOMAIN', a_record = NULL,"
            "   fetched_at = excluded.fetched_at, fresh_until = excluded.fresh_until,"
            "   stale_until = NULL, nx_confirmed_at = excluded.nx_confirmed_at",
            (FQDN, now, now + FRESH_TTL, now),
        )


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------
def _log(table: str, columns: tuple[str, ...], values: tuple) -> None:
    assert table in _LOG_TABLES
    cols = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    with _connect() as c:
        c.execute(f"INSERT INTO {table}({cols}) VALUES ({marks})", values)
        c.execute(
            f"DELETE FROM {table} WHERE id NOT IN"
            f" (SELECT id FROM {table} ORDER BY id DESC LIMIT 300)"
        )


def log_query(qname, qtype, source, rcode, answers, detail) -> None:
    _log(
        "query_log",
        ("ts", "qname", "qtype", "source", "rcode", "answers", "detail"),
        (time.time(), qname, qtype, source, rcode, answers, detail),
    )


def log_auth(qname, qtype, mode, action, detail) -> None:
    _log(
        "auth_log",
        ("ts", "qname", "qtype", "mode", "action", "detail"),
        (time.time(), qname, qtype, mode, action, detail),
    )


def recent(table: str, limit: int = 15) -> list[dict]:
    assert table in _LOG_TABLES
    with _connect() as c:
        rows = c.execute(
            f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# stale-answer impact ledger (resolver writes, web reads)
# --------------------------------------------------------------------------
def new_query_uid() -> str:
    return f"q-{uuid.uuid4().hex}"


def put_stale_impact(query_uid: str, addr, qname: str, qtype: str,
                     stale_a: str, ttl: int, detail: str,
                     ts: float | None = None) -> int | None:
    """Persist the pre-send record of a cache-stale answer.

    Must be committed BEFORE the datagram is sent.  If it raises, the caller
    falls back to SERVFAIL and the client is never handed a stale A.  The row
    starts as `pending`; only a post-send confirmation moves it to `sent`,
    otherwise it stays visible as `pending` (待核实) across restarts.
    """
    with _connect() as c:
        cur = c.execute(
            "INSERT INTO stale_impact(query_uid, ts, client_ip, client_port,"
            " qname, qtype, stale_a, ttl, detail, state, confirmed_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL)",
            (query_uid, time.time() if ts is None else ts,
             str(addr[0]), int(addr[1]), qname, qtype, stale_a, int(ttl), detail),
        )
        return cur.lastrowid


def confirm_stale_impact(query_uid: str) -> bool:
    """Post-send confirmation: the datagram reached the socket.  Only then is
    the record marked `sent`.  Absence of this call leaves `pending`, which
    the console shows as 待核实 and which is still there after a restart."""
    with _connect() as c:
        cur = c.execute(
            "UPDATE stale_impact SET state = 'sent', confirmed_at = ?"
            " WHERE query_uid = ? AND state = 'pending'",
            (time.time(), query_uid),
        )
        return cur.rowcount > 0


def stale_impacts(since: float = 0.0, until: float | None = None) -> list[dict]:
    with _connect() as c:
        rows = c.execute(
            "SELECT * FROM stale_impact WHERE ts >= ? AND ts <= ? ORDER BY ts, id",
            (since, time.time() if until is None else until),
        ).fetchall()
        return [dict(r) for r in rows]


def stale_impact(query_uid: str) -> dict | None:
    with _connect() as c:
        row = c.execute(
            "SELECT * FROM stale_impact WHERE query_uid = ?", (query_uid,)
        ).fetchone()
        return dict(row) if row else None


def stale_impact_by_id(impact_id: int) -> dict | None:
    with _connect() as c:
        row = c.execute(
            "SELECT * FROM stale_impact WHERE id = ?", (impact_id,)
        ).fetchone()
        return dict(row) if row else None


# --------------------------------------------------------------------------
# notification roster: immutable snapshot + separate acknowledgements
# --------------------------------------------------------------------------
def create_notify_batch(fault_start: float, note: str | None = None) -> int:
    """Snapshot every affected client since `fault_start` into a new batch.

    notify_entry copies the evidence (query id, time, client, stale A, state at
    that moment) and is never updated afterwards.  Later cache-stale queries or
    late confirmations change stale_impact only; the console diffs both to show
    what is new and what changed since this roster was generated.
    """
    end = time.time()
    with _connect() as c:
        cur = c.execute(
            "INSERT INTO notify_batch(fault_start, window_end, generated_at, note)"
            " VALUES (?, ?, ?, ?)",
            (float(fault_start), end, end, note),
        )
        batch_id = cur.lastrowid
        c.execute(
            "INSERT OR IGNORE INTO notify_entry(batch_id, impact_id, query_uid,"
            " ts, client_ip, client_port, stale_a, ttl, state_at_snapshot,"
            " confirmed_at_at_snapshot, detail)"
            " SELECT ?, id, query_uid, ts, client_ip, client_port, stale_a, ttl,"
            "        state, confirmed_at, detail"
            " FROM stale_impact WHERE ts >= ?"
            " ORDER BY ts, id",
            (batch_id, float(fault_start)),
        )
        return batch_id


def notify_batches() -> list[dict]:
    with _connect() as c:
        rows = c.execute(
            "SELECT * FROM notify_batch ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def notify_batch(batch_id: int) -> dict | None:
    with _connect() as c:
        row = c.execute(
            "SELECT * FROM notify_batch WHERE id = ?", (batch_id,)
        ).fetchone()
        return dict(row) if row else None


def notify_entries(batch_id: int) -> list[dict]:
    with _connect() as c:
        rows = c.execute(
            "SELECT * FROM notify_entry WHERE batch_id = ? ORDER BY ts, id",
            (batch_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def notify_acks(batch_id: int) -> list[dict]:
    with _connect() as c:
        rows = c.execute(
            "SELECT * FROM notify_ack WHERE batch_id = ? ORDER BY id",
            (batch_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def ack_notify_entry(batch_id: int, impact_id: int,
                     note: str | None = None) -> bool:
    """Register that a client on the roster has been notified.

    Keyed by the impact row (not by a snapshot entry), so it stays attached to
    the same evidence the roster listed.  Acknowledgements live apart from
    notify_entry: the evidence captured at generation is never rewritten.
    """
    with _connect() as c:
        entry = c.execute(
            "SELECT client_ip FROM notify_entry WHERE batch_id = ? AND impact_id = ?",
            (batch_id, impact_id),
        ).fetchone()
        if entry is None:
            return False
        c.execute(
            "INSERT INTO notify_ack(batch_id, impact_id, client_ip,"
            " acknowledged_at, note) VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(batch_id, impact_id) DO UPDATE SET"
            "   acknowledged_at = excluded.acknowledged_at,"
            "   note = excluded.note",
            (batch_id, impact_id, str(entry["client_ip"]), time.time(), note),
        )
        return True


def unack_notify_entry(batch_id: int, impact_id: int) -> bool:
    with _connect() as c:
        cur = c.execute(
            "DELETE FROM notify_ack WHERE batch_id = ? AND impact_id = ?",
            (batch_id, impact_id),
        )
        return cur.rowcount > 0
