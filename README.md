# DNS 值班解析系统（serve-stale 演练）

平台值班场景：内部服务的权威 DNS 失联时，解析器继续为已确认的地址提供解析，
但记录被删除（NXDOMAIN）后绝不把旧地址交给调用方。

## 组成

| 服务 | 模块 | 端口 | 说明 |
|---|---|---|---|
| `auth` | `app.auth_server` | UDP 5354 | 本地权威端，行为可由网页实时切换 |
| `resolver` | `app.resolver` | UDP 5353 | 缓存/serve-stale UDP 解析器 |
| `web` | `app.web` | HTTP 8000 | FastAPI 操作网页 |

三者通过共享卷上的 SQLite（WAL 模式）协作：`control` 表存权威端行为，
`cache` 表存解析器缓存（**绝对时间戳**），`query_log`/`auth_log` 表供网页展示，
`stale_impact`/`notify_batch`/`notify_entry`/`notify_ack` 表构成通知依据与名单。

## 运行

```bash
docker compose up --build
# 网页:  http://localhost:8000
# 查询:  dig @127.0.0.1 -p 5353 service.example A
```

无 Docker 的本地运行（等价三进程）：

```bash
pip install -r requirements.txt
DB_PATH=/tmp/dns/app.db AUTH_PORT=15354 python -m app.auth_server &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 AUTH_PORT=15354 python -m app.resolver &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 WEB_PORT=8000 python -m app.web &
```

自测（自动拉起三进程，跑全部关键交错，约 95 秒）：

```bash
python tests/selftest.py
```

通知名单自测（失败注入、待核实跨重启、快照/登记/差异，约 40 秒）：

```bash
python tests/notify_selftest.py
```

## 语义（默认值，可用环境变量调整）

- 成功答复 TTL = **5 秒**（`FRESH_TTL`），缓存命中时 TTL 倒数。
- 过期后重新回源；上游超时（`UPSTREAM_TIMEOUT`=2s）时旧 A 最多沿用 **20 秒**
  （`STALE_WINDOW`），应答 TTL 为剩余可用时长；超过即 **SERVFAIL**。
- **NXDOMAIN 只作 5 秒新鲜缓存，绝不作过期备用**：过期+上游超时 → SERVFAIL。
- 解析器确认 NXDOMAIN 时**立即持久清除旧 A**：此后任何答复都不再含旧 A。
- 每次回源用**独立 socket + 随机事务 ID + 问题匹配**，超时后迟到的旧答复
  无人接收、也不会被错配给后续查询，因此无法复活旧记录。
- 缓存期限以绝对 epoch 存于 SQLite，**重启不延长旧 A 的有效期**
  （窗口继续倒数，不会重新计时）。

网页可切换权威端行为：`a`（可改 IP）/ `nxdomain` / `delay`（延迟应答，默认 3s，
大于上游超时，用于演练迟到应答）/ `timeout`（不应答，模拟权威端失联）。
网页"发起查询"经解析器发真实 DNS 查询，展示实际答复（rcode、应答、TTL）
与来源（`upstream` / `cache-fresh` / `cache-stale` / `none`，由解析器在
additional 段 TXT `_src.<域名>` 中带回），并展示双方日志。

固定域名默认 `service.example`（`FIXED_DOMAIN` 可改）。解析器只服务该域名，
其余名称 REFUSED，非 A 查询返回 NODATA。

## 旧 A 影响记录与通知名单

解析器准备发出 **cache-stale**（旧 A）答复时：

1. **先持久记录**：写入 `stale_impact`（客户端 IP/端口、旧 A 地址、时间、唯一查询号
   `query_uid`），提交成功后才发包；
2. 发包成功才**确认“已发出”**（`state=sent`，`confirmed_at`）；
3. **前置写入失败** → 不返回旧 A，改答 **SERVFAIL**（绝不发出无依据的旧 A）；
4. **确认缺失**（如确认前崩溃）→ 记录留作 **待核实**（`state=pending`），
   持久在 SQLite 中，**重启仍可查**。

新鲜 A 与 NXDOMAIN 答复**不**写入影响记录，原解析语义不变。

网页第 4 节按**故障起始时间**生成通知名单：把该时刻之后的全部影响记录
（已发出 + 待核实）**快照**进 `notify_entry`，含逐笔依据（查询号、时间、客户端、
旧 A、TTL、生成时状态）。依据一经快照**不再改写**；值班员可逐笔“登记已通知”
（存于独立的 `notify_ack` 表，不触碰快照）。名单生成后：

- 新的 cache-stale 查询 → 页面列出**新增待通知者**；
- 待核实记录后来补上确认 → 页面在“之后的变化”列指出**状态变化**（原依据不变）。

演练用环境变量 `STALE_LEDGER_FAULT`（`fail-prewrite` / `skip-confirm`）仅用于自测，
正常运行时留空。

## 文件

```
app/common.py       配置 + SQLite 状态面
app/auth_server.py  可控权威端（dnslib 编解码，线程并发）
app/resolver.py     缓存/serve-stale 解析器
app/web.py          FastAPI 操作网页（含通知名单）
tests/selftest.py   端到端自测（A–F 六组场景）
tests/notify_selftest.py 通知名单自测（G–K 五组场景）
Dockerfile / docker-compose.yml / requirements.txt
```
