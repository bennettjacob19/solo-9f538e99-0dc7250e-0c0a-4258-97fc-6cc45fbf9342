"""Caching UDP DNS resolver for one fixed internal domain.

Behaviour (all timings from app.common, defaults are the spec values):

  * a successful A answer is cached fresh for FRESH_TTL (5s) and served from
    cache with the remaining TTL;
  * after expiry the resolver re-fetches.  If the upstream times out (or its
    reply is unusable) the old A record may be served stale for at most
    STALE_WINDOW (20s) past expiry; beyond that the answer is SERVFAIL;
  * NXDOMAIN is cached fresh only -- it is never used as stale backup;
  * confirming NXDOMAIN purges the old A record durably (SQLite), so no later
    answer contains the old A again;
  * every upstream attempt uses a dedicated socket with a random transaction
    ID and matches the question section, so a late answer to an already
    timed-out query is never read and can never resurrect the old A;
  * cache deadlines are absolute epochs persisted in SQLite, so a restart does
    not extend the validity of an old A record.

The resolver reports where each answer came from in an additional-section TXT
record (_src.<domain> TXT "source=upstream|cache-fresh|cache-stale|none ...")
and logs every query to the query_log table for the web console.

Every cache-stale answer is also recorded in the stale_impact ledger *before*
it is sent (client IP/port, stale A address, time, unique query id).  Only
after sendto() succeeds is the record confirmed as `sent`; if the pre-send
write fails the client gets SERVFAIL instead of a stale A, and a missing
confirmation leaves the record `pending` (待核实) durably in SQLite, so a
restart still shows it.  Fresh A answers and NXDOMAIN are not ledgered.
"""
from __future__ import annotations

import random
import socket
import threading
import time
import traceback

from dnslib import A, CLASS, QTYPE, RCODE, RR, TXT, DNSHeader, DNSRecord

from . import common


def _same_name(a, b) -> bool:
    return str(a).rstrip(".").lower() == str(b).rstrip(".").lower()


def upstream_query() -> DNSRecord | None:
    """One-shot upstream A query for the fixed domain.

    A dedicated UDP socket per attempt plus a random transaction ID means a
    late answer to an earlier, already timed-out query can never be read back
    (the socket is closed) and can never be mistaken for the answer to a later
    query (ID + question must match).
    """
    query = DNSRecord.question(common.FQDN, "A")
    query.header.id = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query.pack(), (common.AUTH_HOST, common.AUTH_PORT))
        deadline = time.monotonic() + common.UPSTREAM_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                return None
            try:
                resp = DNSRecord.parse(data)
            except Exception:
                continue  # unparsable stray datagram: keep waiting
            if resp.header.id != query.header.id:
                continue  # stray/late packet for someone else: ignore
            if not _same_name(resp.q.qname, query.q.qname):
                continue
            return resp
    except OSError:
        return None
    finally:
        sock.close()


def _a_rr(ip: str, ttl: int) -> RR:
    return RR(common.FQDN, QTYPE.A, CLASS.IN, ttl, A(ip))


def _reply(query: DNSRecord, rcode: int, answers=(), source="none", detail="") -> DNSRecord:
    rep = DNSRecord(
        DNSHeader(
            id=query.header.id, qr=1, aa=0, ra=1, rd=query.header.rd, rcode=rcode
        ),
        q=query.q,
    )
    for rr in answers:
        rep.add_answer(rr)
    meta = f"source={source}" + (f" {detail}" if detail else "")
    rep.add_ar(RR(f"_src.{common.FQDN}", QTYPE.TXT, CLASS.IN, 0, TXT(meta)))
    return rep



def resolve_a(query: DNSRecord) -> tuple[DNSRecord, str, str, dict | None]:
    """Resolve the fixed domain's A record.

    Returns (reply, source, detail, impact).  `impact` is non-None only for a
    cache-stale answer; it carries the (stale A, TTL) that must be written to
    the notification ledger before the reply is sent.
    """
    now = time.time()
    row = common.get_cache()

    # 1) fresh cache hits
    if row and row["rcode"] == "NOERROR" and row["a_record"] and now < row["fresh_until"]:
        ttl = max(1, int(row["fresh_until"] - now + 0.999))
        return (
            _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)], "cache-fresh",
                   f"fresh_left={row['fresh_until'] - now:.1f}"),
            "cache-fresh",
            "fresh A from cache",
            None,
        )
    if row and row["rcode"] == "NXDOMAIN" and now < row["fresh_until"]:
        return (
            _reply(query, RCODE.NXDOMAIN, [], "cache-fresh",
                   f"fresh_left={row['fresh_until'] - now:.1f}"),
            "cache-fresh",
            "fresh NXDOMAIN from cache",
            None,
        )

    # 2) expired: ask the authoritative endpoint
    resp = upstream_query()
    now2 = time.time()

    if resp is not None and resp.header.rcode == RCODE.NOERROR:
        ips = [str(rr.rdata) for rr in resp.rr if rr.rtype == QTYPE.A]
        if ips:
            common.put_cache_a(ips[0], now2)
            return (
                _reply(query, RCODE.NOERROR, [_a_rr(ips[0], int(common.FRESH_TTL))],
                       "upstream"),
                "upstream",
                f"fetched A={ips[0]}",
                None,
            )

    if resp is not None and resp.header.rcode == RCODE.NXDOMAIN:
        # Confirming NXDOMAIN purges the old A record (durably, in SQLite).
        common.put_cache_nxdomain(now2)
        return (
            _reply(query, RCODE.NXDOMAIN, [], "upstream", "nxdomain-confirmed"),
            "upstream",
            "NXDOMAIN confirmed; old A purged",
            None,
        )

    # 3) upstream timeout / unusable reply: maybe serve the stale A record
    #    (NXDOMAIN is never served stale).  Stale answers are ledgered by the
    #    caller before they are sent.
    row = common.get_cache()
    if (
        row
        and row["rcode"] == "NOERROR"
        and row["a_record"]
        and row["stale_until"]
        and now2 < row["stale_until"]
    ):
        ttl = max(1, int(row["stale_until"] - now2 + 0.999))
        return (
            _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)], "cache-stale",
                   f"stale_left={row['stale_until'] - now2:.1f}"),
            "cache-stale",
            "upstream timeout; serving stale A",
            {
                "stale_a": row["a_record"],
                "ttl": ttl,
                "detail": f"upstream-timeout; stale_left={row['stale_until'] - now2:.1f}",
            },
        )

    return (
        _reply(query, RCODE.SERVFAIL, [], "none", "upstream-timeout"),
        "none",
        "upstream timeout; no usable cache",
        None,
    )


def _ledger_fault(which: str) -> None:
    """Drill-only fault injection, enabled via STALE_LEDGER_FAULT."""
    if common.STALE_LEDGER_FAULT == which:
        raise RuntimeError(f"injected ledger fault: {which}")


def handle_packet(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        uid = None
        impact = None
        if not _same_name(query.q.qname, common.FQDN):
            rep = _reply(query, RCODE.REFUSED, [], "none", "out-of-scope")
            source, detail = "none", "out-of-scope"
        elif query.q.qtype == QTYPE.A:
            rep, source, detail, impact = resolve_a(query)
        else:
            rep = _reply(query, RCODE.NOERROR, [], "none", "nodata")
            source, detail = "none", "nodata"

        if impact is not None:
            # Pre-send evidence: durable before the client can possibly see the
            # stale A.  If this write fails, answer SERVFAIL instead -- never
            # hand out a stale A that the notification roster cannot explain.
            uid = common.new_query_uid()
            try:
                _ledger_fault("fail-prewrite")
                common.put_stale_impact(uid, addr, qname, qtype,
                                        impact["stale_a"], impact["ttl"],
                                        impact["detail"])
            except Exception:
                rep = _reply(query, RCODE.SERVFAIL, [], "none",
                             "ledger-prewrite-failed")
                source, detail = "none", "stale answer withheld: pre-send write failed"
                uid = None
            else:
                detail = f"{detail}; query_uid={uid}"

        sock.sendto(rep.pack(), addr)

        if uid is not None:
            # Post-send confirmation.  If it is lost (crash, injected fault)
            # the record stays pending -> 待核实, still visible after restart.
            try:
                _ledger_fault("skip-confirm")
                common.confirm_stale_impact(uid)
            except Exception:
                pass

        answers = ";".join(
            f"{QTYPE[rr.rtype]}={rr.rdata}(ttl={rr.ttl})" for rr in rep.rr
        ) or "-"
        common.log_query(qname, qtype, source, RCODE[rep.header.rcode], answers, detail)
    except Exception:
        common.log_query(qname, qtype, "error", "SERVFAIL", "-",
                         traceback.format_exc(limit=3))


def main() -> None:
    common.init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.RESOLVER_PORT))
    print(
        f"[resolver] {common.FQDN} on udp/{common.RESOLVER_PORT}, "
        f"upstream {common.AUTH_HOST}:{common.AUTH_PORT}, "
        f"fresh={common.FRESH_TTL}s stale={common.STALE_WINDOW}s "
        f"timeout={common.UPSTREAM_TIMEOUT}s",
        flush=True,
    )
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_packet, args=(data, addr, sock),
                         daemon=True).start()


if __name__ == "__main__":
    main()
