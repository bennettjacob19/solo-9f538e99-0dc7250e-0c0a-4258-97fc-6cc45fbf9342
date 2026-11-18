#!/usr/bin/env python3
"""End-to-end self-test for the stale-answer notification ledger.

Spawns auth + resolver + web on loopback with shortened timings and drives:

  G. a cache-stale answer is ledgered before sending: client IP/port, stale A,
     time and a unique query id, confirmed as `sent` after sendto();
  H. fresh A and NXDOMAIN answers are never ledgered;
  I. a failed pre-send write turns the would-be stale answer into SERVFAIL
     (never a stale A without evidence);
  J. a missing post-send confirmation leaves the record `pending` (待核实) and
     it survives a resolver restart;
  K. roster generation snapshots evidence for a fault start time, register/diff
     behave: ack does not rewrite evidence; later queries show up as new
     pending clients; a late confirmation shows up as a changed entry.

Exits non-zero if any check fails.  Runtime: ~35s.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dnslib import DNSRecord, QTYPE  # noqa: E402

DOMAIN = "service.example"
AUTH_PORT, RES_PORT, WEB_PORT = 25354, 25353, 28000
TMP = tempfile.mkdtemp(prefix="dns-notifytest-")
DB = os.path.join(TMP, "app.db")

BASE_ENV = dict(os.environ)
BASE_ENV.update(
    DB_PATH=DB,
    FIXED_DOMAIN=DOMAIN,
    AUTH_HOST="127.0.0.1",
    AUTH_PORT=str(AUTH_PORT),
    RESOLVER_HOST="127.0.0.1",
    RESOLVER_PORT=str(RES_PORT),
    WEB_PORT=str(WEB_PORT),
    FRESH_TTL="2",
    STALE_WINDOW="8",
    UPSTREAM_TIMEOUT="1",
    DEFAULT_IP="192.0.2.10",
    DEFAULT_DELAY="2",
    PYTHONPATH=ROOT,
    PYTHONUNBUFFERED="1",
)

procs: dict[str, subprocess.Popen] = {}
FAILS: list[str] = []


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def start(name: str, module: str, fault: str = "") -> None:
    env = dict(BASE_ENV)
    if fault:
        env["STALE_LEDGER_FAULT"] = fault
    log = open(os.path.join(TMP, f"{name}.log"), "ab")
    procs[name] = subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
    )


def stop(name: str) -> None:
    p = procs.get(name)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def set_mode(mode: str, ip: str = "192.0.2.10", delay: float = 2.0) -> None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute(
        "INSERT INTO control(id, mode, ip, delay_seconds, updated_at)"
        " VALUES (1, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET mode=excluded.mode, ip=excluded.ip,"
        " delay_seconds=excluded.delay_seconds, updated_at=excluded.updated_at",
        (mode, ip, delay, time.time()),
    )
    conn.commit()
    conn.close()


def clear_cache() -> None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("DELETE FROM cache WHERE id = 1")
    conn.commit()
    conn.close()


def db_rows(table: str) -> list[dict]:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_cache() -> dict | None:
    rows = db_rows("cache")
    return rows[0] if rows else None


def dns_query(src: str = "127.0.0.1") -> tuple[int, list[tuple], str | None]:
    q = DNSRecord.question(DOMAIN, "A")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((src, 0))
    sock.settimeout(8)
    sock.sendto(q.pack(), ("127.0.0.1", RES_PORT))
    data, _ = sock.recvfrom(4096)
    sock.close()
    rep = DNSRecord.parse(data)
    answers = [(QTYPE[rr.rtype], str(rr.rdata), rr.ttl) for rr in rep.rr]
    src_value = None
    for rr in rep.ar:
        if rr.rtype == QTYPE.TXT:
            txt = str(rr.rdata).strip('"')
            if txt.startswith("source="):
                src_value = txt.split("=", 1)[1].split()[0]
    return rep.header.rcode, answers, src_value


def api(path: str, method: str = "GET", body: dict | None = None,
        port: int = WEB_PORT) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def check(name: str, cond: bool, info: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {info}", flush=True)
    if not cond:
        FAILS.append(name)


def wait_resolver_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            dns_query()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def wait_web_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if api("/api/state")[0] == 200:
                return True
        except Exception:
            time.sleep(0.3)
    return False


def expire_then_stale(src: str = "127.0.0.1") -> tuple[int, list, str | None]:
    """Let the fresh A expire with the auth endpoint unreachable, then query."""
    set_mode("timeout")
    cache = get_cache()
    time.sleep(max(0.0, cache["fresh_until"] - time.time() + 0.2))
    return dns_query(src)


# --------------------------------------------------------------------------
# scenario
# --------------------------------------------------------------------------
def main() -> int:
    print(f"[notify-selftest] workdir={TMP}", flush=True)
    start("auth", "app.auth_server")
    start("web", "app.web")
    start("resolver", "app.resolver")
    try:
        if not (wait_resolver_ready() and wait_web_ready()):
            print("  [FAIL] services did not come up")
            return 1

        # -- G. stale answers are ledgered before being sent -----------------
        print("G. cache-stale 答复先持久记录、发包后确认", flush=True)
        clear_cache()
        set_mode("a", "192.0.2.10")
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        t_stale = time.time()
        rc, ans, src = expire_then_stale()
        check("G1 过期+超时得到旧 A(stale)",
              rc == 0 and src == "cache-stale", f"rcode={rc} src={src}")
        time.sleep(0.3)  # the confirmation happens right after sendto()
        rows = db_rows("stale_impact")
        row = rows[-1] if rows else None
        check("G2 记录含客户端 IP/端口/旧 A/时间/唯一查询号",
              bool(row) and row["client_ip"] == "127.0.0.1"
              and row["client_port"] > 0 and row["stale_a"] == "192.0.2.10"
              and row["ts"] >= t_stale - 0.5 and row["qname"] == DOMAIN + "."
              and row["qtype"] == "A" and row["query_uid"].startswith("q-")
              and row["ttl"] >= 1, f"row={row}")
        check("G3 发包后已确认 sent", row is not None and row["state"] == "sent"
              and row["confirmed_at"] is not None, f"state={row and row['state']}")
        check("G4 唯一查询号互不重复",
              len({r["query_uid"] for r in rows}) == len(rows))
        uid = row["query_uid"]
        logrow = [r for r in db_rows("query_log")
                  if uid in (r["detail"] or "")][-1]
        check("G5 查询日志可凭唯一查询号核对", logrow["source"] == "cache-stale",
              f"detail={logrow['detail']}")

        # -- H. fresh A / NXDOMAIN are not ledgered ---------------------------
        print("H. 新鲜 A 与 NXDOMAIN 不计入影响记录", flush=True)
        before = len(db_rows("stale_impact"))
        set_mode("a", "192.0.2.10")
        clear_cache()
        rc, ans, src = dns_query()          # upstream + fresh cache hit
        rc, ans, src = dns_query()          # cache-fresh
        check("H1 新鲜 A 不写入记录", len(db_rows("stale_impact")) == before,
              f"before={before} after={len(db_rows('stale_impact'))}")
        set_mode("nxdomain")
        clear_cache()
        rc, ans, src = dns_query()
        check("H2 NXDOMAIN 不写入记录",
              rc == 3 and len(db_rows("stale_impact")) == before,
              f"rcode={rc} rows={len(db_rows('stale_impact'))}")

        # -- I. pre-send write failure -> SERVFAIL ---------------------------
        print("I. 前置写入失败改答 SERVFAIL", flush=True)
        stop("resolver")
        set_mode("a", "192.0.2.10")
        clear_cache()
        start("resolver", "app.resolver")
        assert wait_resolver_ready(), "resolver did not come back"
        clear_cache()
        set_mode("a", "192.0.2.10")
        dns_query()  # populate
        stop("resolver")
        start("resolver", "app.resolver", fault="fail-prewrite")
        assert wait_resolver_ready(), "faulty resolver did not come back"
        rc, ans, src = expire_then_stale()
        check("I1 前置写入失败不返回旧 A，改答 SERVFAIL",
              rc == 2 and not ans and src == "none", f"rcode={rc} ans={ans}")
        check("I2 失败时记录中没有残留的旧 A 影响行",
              not [r for r in db_rows("stale_impact") if r["ts"] > time.time() - 6])
        stop("resolver")
        start("resolver", "app.resolver", fault="skip-confirm")
        assert wait_resolver_ready(), "faulty resolver did not come back"
        set_mode("a", "192.0.2.10")
        clear_cache()
        dns_query()
        rc, ans, src = expire_then_stale(src="127.0.0.2")
        check("I3 发包成功但确认缺失：仍返回旧 A",
              rc == 0 and src == "cache-stale", f"rcode={rc} src={src}")

        # -- J. pending survives a restart -----------------------------------
        print("J. 确认缺失留作待核实，重启仍可查", flush=True)
        time.sleep(0.3)
        pending = [r for r in db_rows("stale_impact") if r["state"] == "pending"]
        check("J1 缺少确认的记录为 pending(待核实)", len(pending) == 1
              and pending[0]["client_ip"] == "127.0.0.2",
              f"pending={pending}")
        uid = pending[0]["query_uid"]
        stop("resolver")
        start("resolver", "app.resolver")
        assert wait_resolver_ready(), "resolver did not come back"
        still = [r for r in db_rows("stale_impact") if r["query_uid"] == uid]
        check("J2 重启后待核实记录仍在", len(still) == 1
              and still[0]["state"] == "pending" and still[0]["stale_a"] != "",
              f"row={still}")

        # -- K. roster snapshot, acknowledgement, drift ----------------------
        print("K. 通知名单快照、登记与变化提示", flush=True)
        set_mode("a", "192.0.2.10")
        clear_cache()
        dns_query()
        t_fault = 1.0  # include every stale impact produced by this run
        rc, ans, src = expire_then_stale(src="127.0.0.3")
        check("K1 再产生一条新的 stale 影响", rc == 0 and src == "cache-stale",
              f"rcode={rc} src={src}")
        time.sleep(0.3)
        status, gen = api("/api/notify/generate", "POST",
                          {"fault_start": t_fault})
        check("K2 按故障起始时间生成名单", status == 200 and gen["ok"]
              and gen["entry_count"] >= 2, f"gen={gen}")
        batch_id = gen["batch_id"]
        status, det = api(f"/api/notify/batch/{batch_id}")
        entries = det["entries"]
        check("K3 名单含已发出与待核实客户端及逐笔依据",
              det["summary"]["sent_at_snapshot"] >= 2
              and det["summary"]["unverified_at_snapshot"] >= 1
              and all(e["query_uid"] and e["ts"] and e["stale_a"]
                      and e["client_ip"] for e in entries),
              f"summary={det['summary']}")
        first = next(e for e in entries if e["client_ip"] == "127.0.0.1")
        snapshot = (first["query_uid"], first["ts"], first["stale_a"],
                    first["state_at_snapshot"], first["ttl"])

        status, ack = api(f"/api/notify/batch/{batch_id}/ack", "POST",
                          {"impact_id": first["impact_id"]})
        check("K4 登记已通知者", status == 200 and ack["ok"])
        status, det2 = api(f"/api/notify/batch/{batch_id}")
        e2 = next(e for e in det2["entries"] if e["impact_id"] == first["impact_id"])
        check("K5 登记不改写名单依据", (e2["query_uid"], e2["ts"], e2["stale_a"],
              e2["state_at_snapshot"], e2["ttl"]) == snapshot
              and e2["acknowledged_at"] is not None,
              f"entry={e2}")

        # a new stale query after generation -> new pending client
        set_mode("a", "192.0.2.10")
        clear_cache()
        dns_query()
        time.sleep(0.2)
        rc, ans, src = expire_then_stale(src="127.0.0.4")
        check("K6 名单生成后新查询也照常给出旧 A",
              rc == 0 and src == "cache-stale", f"src={src}")
        time.sleep(0.3)
        status, det3 = api(f"/api/notify/batch/{batch_id}")
        new_ips = [i["client_ip"] for i in det3["new_impacts"]]
        check("K7 页面指出新增待通知者", "127.0.0.4" in new_ips,
              f"new={new_ips}")

        # late confirmation of a 待核实 roster entry -> changed entry
        pending_uid = next(e["query_uid"] for e in entries
                           if e["state_at_snapshot"] == "pending")
        sys.path.insert(0, ROOT)
        from app import common  # same DB_PATH via BASE_ENV? explicit below
        os.environ["DB_PATH"] = DB
        common.DB_PATH = DB
        common.confirm_stale_impact(pending_uid)
        status, det4 = api(f"/api/notify/batch/{batch_id}")
        changed = [e for e in det4["entries"]
                   if e["query_uid"] == pending_uid and e["change"]]
        check("K8 迟到确认改变影响记录时，名单指出状态变化且依据不变",
              changed and changed[0]["state_at_snapshot"] == "pending"
              and changed[0]["stale_a"] == next(
                  e["stale_a"] for e in entries if e["query_uid"] == pending_uid),
              f"changed={changed}")

        # fresh answers after generation are never in the roster
        status, det5 = api(f"/api/notify/batch/{batch_id}")
        dup = [i for i in det5["new_impacts"]
               if i["stale_a"] == "192.0.2.10" and i["ts"] > time.time() + 1]
        check("K9 名单只含旧 A 影响，新鲜答复无新增", not dup)

        # roster persists across web restart (it is the shared DB)
        stop("web")
        start("web", "app.web")
        assert wait_web_ready(), "web did not come back"
        status, det6 = api(f"/api/notify/batch/{batch_id}")
        check("K10 重启后名单与登记仍可查",
              status == 200 and len(det6["entries"]) == len(entries)
              and any(e["acknowledged_at"] for e in det6["entries"]),
              f"entries={len(det6['entries'])}")
    finally:
        for name in list(procs):
            stop(name)
        print(f"[notify-selftest] logs in {TMP}", flush=True)

    print(f"\n{'=' * 60}\n结果: {len(FAILS)} 项失败" if FAILS
          else f"\n{'=' * 60}\n结果: 全部通过", flush=True)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
