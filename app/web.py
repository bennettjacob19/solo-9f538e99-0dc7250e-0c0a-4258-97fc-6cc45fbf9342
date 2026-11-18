"""FastAPI operations console.

Serves a single-page console that can
  * switch the authoritative endpoint's behaviour for the fixed domain
    (A record / NXDOMAIN / delayed A / timeout),
  * fire a real DNS query at the resolver and show the actual reply together
    with where it came from (upstream / cache-fresh / cache-stale / none),
  * show the resolver cache state (with live countdowns) and the query logs
    of both the resolver and the authoritative endpoint,
  * generate an immutable notification roster for the clients that may have
    received an old A since a fault start time (sent + 待核实), register which
    clients have been notified, and diff the roster against the live ledger so
    newly affected clients and changed entries are visible for follow-up.
"""
from __future__ import annotations

import ipaddress
import time

import uvicorn
from dnslib import QTYPE, RCODE, DNSRecord
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import common

app = FastAPI(title="DNS duty console")

PAGE = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>DNS 值班控制台</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; background:#f6f7f9; color:#222; }
  h1 { font-size: 1.3rem; }
  section { background:#fff; border:1px solid #ddd; border-radius:8px;
            padding:1rem 1.2rem; margin-bottom:1rem; }
  h2 { font-size:1rem; margin-top:0; }
  label { margin-right:1rem; cursor:pointer; }
  input[type=text] { width:9rem; }
  input[type=number] { width:5rem; }
  button { padding:.35rem 1rem; cursor:pointer; }
  table { border-collapse:collapse; width:100%; font-size:.82rem; }
  th, td { border:1px solid #e2e2e2; padding:.25rem .5rem; text-align:left; }
  th { background:#f0f1f4; }
  pre { background:#0d1420; color:#cfe3ff; padding:.7rem; border-radius:6px;
        overflow:auto; font-size:.78rem; }
  .pill { display:inline-block; padding:.1rem .55rem; border-radius:1rem;
          background:#e8ecf3; font-size:.8rem; margin-right:.4rem; }
  .ok { color:#0a7a2f; } .bad { color:#b00020; } .muted { color:#777; }
  #qresult b { font-size:1.05rem; }
</style>
</head>
<body>
<h1>DNS 值班控制台 — <code id="dom">…</code></h1>
<p class="muted" id="params"></p>

<section>
  <h2>1. 权威端行为切换</h2>
  <label><input type="radio" name="mode" value="a"> A 记录</label>
  <label><input type="radio" name="mode" value="nxdomain"> NXDOMAIN</label>
  <label><input type="radio" name="mode" value="delay"> 延迟应答</label>
  <label><input type="radio" name="mode" value="timeout"> 超时（不应答）</label>
  <p>
    A 记录 IP：<input type="text" id="ip" value="192.0.2.10">
    &nbsp; 延迟秒数：<input type="number" id="delay" value="3" min="0" step="0.5">
    &nbsp; <button onclick="applyMode()">应用</button>
    <span id="modemsg"></span>
  </p>
  <p class="muted">当前权威端模式：<b id="curmode">…</b>（每 2 秒自动刷新）</p>
</section>

<section>
  <h2>2. 发起查询（经解析器）</h2>
  <button onclick="doQuery()">查询 A 记录</button>
  <span id="qmsg"></span>
  <div id="qresult"></div>
  <pre id="qraw" style="display:none"></pre>
</section>

<section>
  <h2>3. 解析器缓存状态</h2>
  <div id="cache">…</div>
</section>

<section>
  <h2>4. 故障影响与通知名单</h2>
  <p class="muted">
    解析器每发出一条 cache-stale 答复，都会先在 SQLite 记下客户端 IP、地址、时间和唯一查询号，
    发包后才确认“已发出”；前置写入失败则改答 SERVFAIL，确认缺失（如崩溃）则留作
    <b>待核实</b>，重启后仍可查。新鲜 A 与 NXDOMAIN 不计入。
  </p>
  <p>
    故障起始时间：<input type="datetime-local" id="faultStart" step="1">
    &nbsp; <button onclick="genRoster()">按此时间生成通知名单</button>
    <span id="genmsg"></span>
  </p>
  <p class="muted">已有名单：<select id="batchSel" onchange="loadRoster()"></select>
     &nbsp; <button onclick="loadRoster()">查看</button>
     <span id="ackmsg"></span></p>
  <div id="roster"></div>
</section>

<section>
  <h2>5. 解析器查询日志（最近 15 条）</h2>
  <table id="rlog"><thead><tr>
    <th>时间</th><th>名称</th><th>类型</th><th>来源</th><th>RCODE</th><th>答复</th><th>说明</th>
  </tr></thead><tbody></tbody></table>
</section>

<section>
  <h2>6. 权威端接收日志（最近 15 条）</h2>
  <table id="alog"><thead><tr>
    <th>时间</th><th>名称</th><th>类型</th><th>模式</th><th>动作</th><th>说明</th>
  </tr></thead><tbody></tbody></table>
</section>

<script>
let serverOffset = 0;  // server_now - client_now

function fmtTs(ts) {
  return new Date((ts) * 1000).toLocaleTimeString();
}
function countdown(ts) {
  const left = ts - (Date.now() / 1000 + serverOffset);
  if (left <= 0) return '<span class="bad">已过期</span>';
  return '<span class="ok">剩 ' + left.toFixed(1) + 's</span>';
}

async function refresh() {
  try {
    const s = await (await fetch('/api/state')).json();
    serverOffset = s.now - Date.now() / 1000;
    document.getElementById('dom').textContent = s.domain;
    document.getElementById('params').textContent =
      `成功答复 TTL=${s.params.fresh_ttl}s · 过期后旧 A 最多沿用 ${s.params.stale_window}s` +
      ` · 上游超时 ${s.params.upstream_timeout}s`;
    const c = s.control;
    if (c) {
      document.getElementById('curmode').textContent =
        `${c.mode}（A=${c.ip}，延迟=${c.delay_seconds}s，更新于 ${fmtTs(c.updated_at)}）`;
      document.querySelector(`input[name=mode][value=${c.mode}]`).checked = true;
      if (document.activeElement.id !== 'ip') document.getElementById('ip').value = c.ip;
      if (document.activeElement.id !== 'delay')
        document.getElementById('delay').value = c.delay_seconds;
    }
    const k = s.cache;
    document.getElementById('cache').innerHTML = k ?
      `<span class="pill">rcode=${k.rcode}</span>` +
      (k.a_record ? `<span class="pill">A=${k.a_record}</span>` : '<span class="pill">无 A 记录</span>') +
      `<span class="pill">fresh: ${countdown(k.fresh_until)}</span>` +
      (k.stale_until ? `<span class="pill">stale: ${countdown(k.stale_until)}</span>`
                     : '<span class="pill">无 stale 备用</span>') +
      (k.nx_confirmed_at ? `<span class="pill">NXDOMAIN 确认于 ${fmtTs(k.nx_confirmed_at)}</span>` : '')
      : '<span class="muted">（缓存为空）</span>';
    fillLog('rlog', s.resolver_log, r =>
      [fmtTs(r.ts), r.qname, r.qtype, r.source, r.rcode, r.answers, r.detail]);
    fillLog('alog', s.auth_log, r =>
      [fmtTs(r.ts), r.qname, r.qtype, r.mode, r.action, r.detail]);
  } catch (e) { console.log(e); }
}

function fillLog(id, rows, cols) {
  const tb = document.querySelector('#' + id + ' tbody');
  tb.innerHTML = rows.map(r =>
    '<tr>' + cols(r).map(x => `<td>${x ?? ''}</td>`).join('') + '</tr>').join('');
}

// ---- notification roster --------------------------------------------------
let currentBatch = null;

function fmtFull(ts) {
  if (ts == null) return '—';
  return new Date(ts * 1000).toLocaleString('sv-SE');  // YYYY-MM-DD HH:MM:SS
}
function fmtLocalInput(ts) {
  const d = new Date(ts * 1000 - new Date().getTimezoneOffset() * 60000);
  return d.toISOString().slice(0, 19);
}
function stateLabel(st) {
  return st === 'pending'
    ? '<span class="bad">待核实</span>'
    : '<span class="ok">已发出</span>';
}

async function refreshBatches(selectId) {
  const r = await (await fetch('/api/notify/batches')).json();
  const sel = document.getElementById('batchSel');
  const keep = selectId ?? currentBatch;
  sel.innerHTML = r.batches.map(b =>
    `<option value="${b.id}">#${b.id} 起始 ${fmtFull(b.fault_start)}` +
    ` · 生成 ${fmtFull(b.generated_at)} · ${b.entry_count} 人` +
    `${b.unacked_count ? ' · 未登记 ' + b.unacked_count : ''}</option>`).join('');
  if (keep && r.batches.some(b => b.id === keep)) sel.value = keep;
  return r.batches;
}

async function genRoster() {
  const raw = document.getElementById('faultStart').value;
  if (!raw) { document.getElementById('genmsg').textContent = ' ✘ 请填写故障起始时间'; return; }
  const ts = new Date(raw).getTime() / 1000;
  const r = await (await fetch('/api/notify/generate', { method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ fault_start: ts }) })).json();
  if (!r.ok) { document.getElementById('genmsg').textContent = ' ✘ ' + r.error; return; }
  document.getElementById('genmsg').textContent =
    ` ✔ 已生成名单 #${r.batch_id}（${r.entry_count} 人：已发出 ${r.sent_count}，` +
    `待核实 ${r.unverified_count}）`;
  currentBatch = r.batch_id;
  await refreshBatches(r.batch_id);
  await loadRoster();
}

async function loadRoster() {
  const sel = document.getElementById('batchSel');
  if (!sel.value) { document.getElementById('roster').innerHTML = ''; return; }
  currentBatch = parseInt(sel.value);
  const r = await (await fetch(`/api/notify/batch/${currentBatch}`)).json();
  if (!r.ok) {
    document.getElementById('roster').innerHTML = '<b class="bad">' + r.error + '</b>';
    return;
  }
  if (!document.getElementById('faultStart').value)
    document.getElementById('faultStart').value = fmtLocalInput(r.batch.fault_start);

  const rows = r.entries.map(e => {
    const ack = e.acknowledged_at
      ? `<span class="ok">已登记 ${fmtFull(e.acknowledged_at)}</span>`
      : `<button onclick="ack(${e.impact_id})">登记已通知</button>`;
    const drift = e.change
      ? `<span class="bad">${e.change}</span>` : '<span class="muted">—</span>';
    return '<tr>' +
      `<td>${fmtFull(e.ts)}</td>` +
      `<td>${e.client_ip}:${e.client_port}</td>` +
      `<td>${e.stale_a} <span class="muted">ttl=${e.ttl}s</span></td>` +
      `<td>${stateLabel(e.state_at_snapshot)}</td>` +
      `<td><code>${e.query_uid}</code></td>` +
      `<td>${drift}</td>` +
      '<td>' + ack + '</td></tr>';
  }).join('');

  const newRows = r.new_impacts.map(i =>
    '<tr>' +
    `<td>${fmtFull(i.ts)}</td>` +
    `<td>${i.client_ip}:${i.client_port}</td>` +
    `<td>${i.stale_a} <span class="muted">ttl=${i.ttl}s</span></td>` +
    `<td><code>${i.query_uid}</code></td>` +
    `<td>${stateLabel(i.state)}</td></tr>`).join('');

  document.getElementById('roster').innerHTML = `
    <p class="muted">名单 #${r.batch.id} 于 ${fmtFull(r.batch.generated_at)} 生成，
       覆盖 ${fmtFull(r.batch.fault_start)} 之后至生成时刻的 cache-stale 答复。
       依据在生成时固化，之后的查询或迟到确认不会改写它。</p>
    <p class="pill">名单内 ${r.summary.total} 人</p>
    <p class="pill">已发出 ${r.summary.sent_at_snapshot}</p>
    <p class="pill">待核实 ${r.summary.unverified_at_snapshot}</p>
    <p class="pill">已登记通知 ${r.summary.acknowledged}</p>
    <p class="pill">新增待通知 ${r.summary.new_impacts}</p>
    <p class="pill">名单内状态变化 ${r.summary.changed}</p>
    <h3 style="font-size:.92rem">名单（依据为生成时快照）</h3>
    <table><thead><tr>
      <th>答复时间</th><th>客户端</th><th>旧 A / TTL</th><th>生成时状态</th>
      <th>唯一查询号</th><th>之后的变化</th><th>通知登记</th>
    </tr></thead><tbody>${rows || '<tr><td colspan="7" class="muted">（无）</td></tr>'}</tbody></table>
    <h3 style="font-size:.92rem">生成名单之后新增的待通知客户端</h3>
    <table><thead><tr>
      <th>答复时间</th><th>客户端</th><th>旧 A / TTL</th><th>唯一查询号</th><th>当前状态</th>
    </tr></thead><tbody>${newRows || '<tr><td colspan="5" class="muted">（无）</td></tr>'}</tbody></table>`;
}

async function ack(impactId) {
  const r = await (await fetch(`/api/notify/batch/${currentBatch}/ack`,
    { method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ impact_id: impactId }) })).json();
  document.getElementById('ackmsg').textContent = r.ok ? ' ✔ 已登记' : ' ✘ ' + r.error;
  await refreshBatches(currentBatch);
  await loadRoster();
}

async function applyMode() {
  const mode = document.querySelector('input[name=mode]:checked').value;
  const body = { mode, ip: document.getElementById('ip').value,
                 delay_seconds: parseFloat(document.getElementById('delay').value) };
  const r = await (await fetch('/api/mode', { method: 'POST',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) })).json();
  document.getElementById('modemsg').textContent = r.ok ? ' ✔ 已切换' : ' ✘ ' + r.error;
  refresh();
}

async function doQuery() {
  document.getElementById('qmsg').textContent = ' 查询中…';
  const r = await (await fetch('/api/query', {method: 'POST'})).json();
  document.getElementById('qmsg').textContent = '';
  const el = document.getElementById('qresult');
  if (!r.ok) { el.innerHTML = '<b class="bad">查询失败：' + r.error + '</b>'; return; }
  const ans = r.answers.length
    ? r.answers.map(a => `${a.type} ${a.data} <span class="muted">TTL=${a.ttl}s</span>`).join('，')
    : '（无应答记录）';
  el.innerHTML = `<p><b>${r.rcode}</b> &nbsp; ${ans} &nbsp; ` +
    `<span class="pill">来源：${r.source}</span> ` +
    `<span class="muted">${r.elapsed_ms}ms · ${r.meta.join(' ')}</span></p>`;
  const raw = document.getElementById('qraw');
  raw.style.display = 'block';
  raw.textContent = r.raw;
  refresh();
}

setInterval(refresh, 2000);
refresh();
if (!document.getElementById('faultStart').value)
  document.getElementById('faultStart').value = fmtLocalInput(Date.now() / 1000);
refreshBatches().then(() => { if (document.getElementById('batchSel').value) loadRoster(); });
</script>
</body>
</html>
"""


class ModeIn(BaseModel):
    mode: str
    ip: str | None = None
    delay_seconds: float | None = None


class GenerateIn(BaseModel):
    fault_start: float
    note: str | None = None


class AckIn(BaseModel):
    impact_id: int
    note: str | None = None


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return PAGE


@app.get("/api/state")
def state() -> dict:
    return {
        "now": time.time(),
        "domain": common.FQDN,
        "params": {
            "fresh_ttl": common.FRESH_TTL,
            "stale_window": common.STALE_WINDOW,
            "upstream_timeout": common.UPSTREAM_TIMEOUT,
        },
        "control": common.get_control(),
        "cache": common.get_cache(),
        "resolver_log": common.recent("query_log"),
        "auth_log": common.recent("auth_log"),
    }


@app.post("/api/mode")
def set_mode(m: ModeIn):
    if m.mode not in ("a", "nxdomain", "delay", "timeout"):
        return JSONResponse({"ok": False, "error": f"unknown mode {m.mode!r}"}, 400)
    cur = common.get_control() or {"ip": common.DEFAULT_IP,
                                   "delay_seconds": common.DEFAULT_DELAY}
    ip = m.ip if m.ip is not None else cur["ip"]
    delay = m.delay_seconds if m.delay_seconds is not None else cur["delay_seconds"]
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return JSONResponse({"ok": False, "error": f"bad IPv4 address {ip!r}"}, 400)
    if not (0 <= float(delay) <= 60):
        return JSONResponse({"ok": False, "error": "delay must be 0..60s"}, 400)
    common.set_control(m.mode, ip, float(delay))
    return {"ok": True, "control": common.get_control()}


@app.post("/api/query")
def do_query() -> dict:
    """Fire a real A query at the resolver and report the actual reply."""
    query = DNSRecord.question(common.FQDN, "A")
    t0 = time.time()
    try:
        data = query.send(common.RESOLVER_HOST, common.RESOLVER_PORT,
                          timeout=common.UPSTREAM_TIMEOUT + 6)
        rep = DNSRecord.parse(data)
    except Exception as exc:  # noqa: BLE001 - report any transport failure
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    answers = [
        {"name": str(rr.rname), "type": QTYPE[rr.rtype], "data": str(rr.rdata),
         "ttl": rr.ttl}
        for rr in rep.rr
    ]
    txts = [str(rr.rdata).strip('"') for rr in rep.ar if rr.rtype == QTYPE.TXT]
    source = next(
        (t.split("=", 1)[1].split()[0] for t in txts if t.startswith("source=")),
        "unknown",
    )
    return {
        "ok": True,
        "rcode": RCODE[rep.header.rcode],
        "answers": answers,
        "source": source,
        "meta": txts,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "raw": str(rep),
    }


def _entry_change(snapshot: dict, live: dict | None) -> str | None:
    """Describe how a snapshot entry differs from the live ledger row."""
    if live is None:
        return "影响记录缺失"
    if snapshot["state_at_snapshot"] == "pending" and live["state"] == "sent":
        return "迟到确认：已由待核实转为已发出"
    if live["state"] != snapshot["state_at_snapshot"]:
        return f"状态 {snapshot['state_at_snapshot']} → {live['state']}"
    return None


@app.get("/api/notify/batches")
def notify_batches() -> dict:
    batches = common.notify_batches()
    for b in batches:
        entries = common.notify_entries(b["id"])
        acks = {a["impact_id"] for a in common.notify_acks(b["id"])}
        b["entry_count"] = len(entries)
        b["unacked_count"] = sum(
            1 for e in entries if e["impact_id"] not in acks
        )
    return {"ok": True, "batches": batches}


@app.post("/api/notify/generate")
def notify_generate(g: GenerateIn):
    now = time.time()
    if not (g.fault_start > 0):
        return JSONResponse({"ok": False, "error": "fault_start must be an epoch"},
                            400)
    if g.fault_start > now + 1:
        return JSONResponse({"ok": False, "error": "fault_start is in the future"},
                            400)
    batch_id = common.create_notify_batch(g.fault_start, g.note)
    entries = common.notify_entries(batch_id)
    return {
        "ok": True,
        "batch_id": batch_id,
        "entry_count": len(entries),
        "sent_count": sum(1 for e in entries if e["state_at_snapshot"] == "sent"),
        "unverified_count": sum(
            1 for e in entries if e["state_at_snapshot"] == "pending"
        ),
    }


@app.get("/api/notify/batch/{batch_id}")
def notify_batch_detail(batch_id: int):
    batch = common.notify_batch(batch_id)
    if batch is None:
        return JSONResponse({"ok": False, "error": "no such batch"}, 404)
    entries = common.notify_entries(batch_id)
    ack_map = {a["impact_id"]: a for a in common.notify_acks(batch_id)}

    out = []
    for e in entries:
        live = common.stale_impact_by_id(e["impact_id"])
        out.append({
            **e,
            "change": _entry_change(e, live),
            "acknowledged_at": (ack_map[e["impact_id"]]["acknowledged_at"]
                                if e["impact_id"] in ack_map else None),
            "ack_note": (ack_map[e["impact_id"]]["note"]
                         if e["impact_id"] in ack_map else None),
        })

    seen = {e["impact_id"] for e in entries}
    new_impacts = [
        i for i in common.stale_impacts(since=batch["fault_start"])
        if i["id"] not in seen
    ]
    return {
        "ok": True,
        "batch": batch,
        "entries": out,
        "new_impacts": new_impacts,
        "summary": {
            "total": len(entries),
            "sent_at_snapshot": sum(
                1 for e in entries if e["state_at_snapshot"] == "sent"),
            "unverified_at_snapshot": sum(
                1 for e in entries if e["state_at_snapshot"] == "pending"),
            "acknowledged": sum(1 for e in entries if e["impact_id"] in ack_map),
            "new_impacts": len(new_impacts),
            "changed": sum(1 for e in out if e["change"]),
        },
    }


@app.post("/api/notify/batch/{batch_id}/ack")
def notify_ack(batch_id: int, a: AckIn):
    if common.notify_batch(batch_id) is None:
        return JSONResponse({"ok": False, "error": "no such batch"}, 404)
    ok = common.ack_notify_entry(batch_id, a.impact_id, a.note)
    if not ok:
        return JSONResponse(
            {"ok": False, "error": "impact is not on this roster"}, 400)
    return {"ok": True}


@app.post("/api/notify/batch/{batch_id}/unack")
def notify_unack(batch_id: int, a: AckIn):
    if not common.unack_notify_entry(batch_id, a.impact_id):
        return JSONResponse({"ok": False, "error": "not acknowledged"}, 400)
    return {"ok": True}


def main() -> None:
    common.init_db()
    uvicorn.run(app, host="0.0.0.0", port=common.WEB_PORT, log_level="warning")


if __name__ == "__main__":
    main()
