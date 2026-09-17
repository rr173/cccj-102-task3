# Whub 离线可核验防篡改凭证册

本文档说明新增的证据链、封存锚点、原子恢复、导出、隐私清除与离线核验协议。

## 1. 一键复现

```bash
cd webhook-hub

# 7 个凭证专项检查：空白 SQLite、真实 store/worker-a/worker-b/sink、真实 HTTP、SIGKILL、离线核验器
./run-evidence.sh

# 等价命令
python3 -m whub evidence --ttl 2 --report evidence-report.json

# 单独离线核验导出包
python3 -m whub verify /path/to/export.whubpak --json

# 同时验证导出包中不包含某个敏感值
python3 -m whub verify /path/to/export.whubpak --scan-secret 'SECRET_...'
```

检查覆盖：

1. 两个 worker 高频争用、多次所有权换手，链连续且终态凭证与接收方实际动作逐项对应；
2. 副作用前、副作用后、锚点封存途中 `SIGKILL`，对账器区分安全再试 / 结局待查 / 已收敛；
3. 改写中间条目、删除条目、交换相邻条目、替换锚点，离线核验全部失败并给出首个失信序号；
4. 持续压力写入期间导出，冻结点以前稳定可验，以后条目不混入，增量包紧接 `cutoff+1`；
5. Ed25519 封存密钥换代，前后包均可验；模拟旧私钥泄漏后伪造新锚点失败；
6. 留存到期抹除正文后动作数量和次序仍可证，司法留置阻止清除，解除后续办；
7. 共享账库短暂拒写时业务不能记成功，恢复后链头与主账终态一致。

## 2. 数据模型与不写入的秘密

每个客户账户（`tenant_id`）一条链，表在共享 SQLite 中：

* `evidence_entries(tenant_id, seq, event_type, action_id, anchor_id, prev_digest, digest, body_json, created_at)`；
* `evidence_anchors`：锚点签名、锚点代次和上一锚点；
* `sealing_keys / sealing_rotations`：只保存公钥、换代时间和旧私钥签署的分界证明；
* `delivery_intents`：出站动作的可恢复状态；
* `evidence_exports`：冻结导出作业；
* `retention_policies / legal_holds / privacy_batches`：留存、留置和清除进度。

封存私钥是独立 0600 文件：

```text
<db-dir>/sealing-keys/sealing-key-generation-0000.seed
```

私钥永不进入 SQLite、导出包、审计日志、API 响应。正文、HMAC secret、API key、Authorization、Cookie 等也不进入凭证。正文仅保存：

* `payload_digest = SHA256(canonical payload)`；
* `payload_bytes`；
* 业务对象和事件的非秘密标识。

请求仅记录 `request_digest`、host、path、签名代次和 kid，不记录请求头或鉴权材料。响应只记录 HTTP code 与 `response_digest`。

## 3. 规范编码与摘要域隔离

统一使用 JCS 风格的最小 JSON 编码：

* UTF-8；
* 键名按 Unicode 码位排序；
* 无多余空白：分隔符为 `,` 和 `:`；
* `ensure_ascii=False`；
* 禁止 `NaN/Infinity`。

实现见 `Engine.canonical_json()` 与 `evidence_pack.canonical()`。

摘要采用显式域隔离，避免把一类对象的字节解释成另一类对象：

```text
SHA256(canonical({"domain": "whub/evidence-entry/v1", "body": entry_body}))
SHA256(canonical({"domain": "whub/evidence-anchor/v1", "body": anchor_statement}))
SHA256(canonical({"domain": "whub/sealing-key-rotation/v1", "body": rotation_statement}))
SHA256(canonical({"domain": "whub/evidence-export/v1", "body": export_statement}))
```

普通条目包含：版本、客户账户、序号、事件类型、动作编号、前条摘要、时间和仅含非秘密字段的 `attributes`。第 1 条的 `prev_digest` 固定为 `GENESIS`。

事件类型：

* `message_enqueued`：消息入账；
* `ownership_handover`：lane 所有权交接；
* `outbound_attempt`：出站尝试，先于网络副作用落库；
* `peer_response`：收到对方应答；
* `delivery_result`：成功、可重试失败、永久失败或跳过的终态；
* `operator_replayed`：操作员再次执行；
* `anchor_sealed`：周期/手动封存；
* `sealing_key_rotated`：封存密钥换代分界；
* `export_cutoff`（内部导出元数据，不进入冻结包）；
* `privacy_erased`：隐私清除批次。

## 4. 连续编号、防分叉和两节点争用

凭证追加与主账变更在同一个 SQLite `BEGIN IMMEDIATE` 事务中：

* 入账：事件、job、lane 序号与 `message_enqueued` 同事务；
* 所有权：lane owner/epoch/fence 变化与 `ownership_handover` 同事务；
* 出站：lease/fence 校验、`delivery_intents` 与 `outbound_attempt` 同事务；
* 终态：job 状态、`peer_response`（如有）和 `delivery_result` 同事务。

两进程争用时，SQLite 写事务和 `(tenant_id, seq)` 主键保证只有一个追加者赢；事务回滚则业务状态和凭证都不存在。链校验要求 `seq = 上一序号 + 1` 且 `prev_digest = 上一条 digest`，所以分叉、缺号、插入、删除、调序都会被定位。

成功终态严格在真实 HTTP 应答之后。没有应答时只能形成可重试/结局待查，不允许出现成功凭证。终态条目对 `(tenant_id, action_id)` 建唯一索引，同一动作不会产生两个终态凭证。

## 5. 原子分界和恢复判定

一次出站动作的持久状态机：

```text
prepared ──副作用前提交 outbound_attempt/intent
          │
          ├─ 崩溃：未发生副作用，lease 失效后 safe_to_retry
          ▼
dispatched ──已调用网络，尚未得到/落库应答
          │
          ├─ 崩溃且无外部观察：outcome_unknown，禁止伪成功
          ├─ 接收方观察到动作：converged，按原 action_id 补 peer_response+唯一终态
          ▼
response_seen / settled ──应答与终态同事务落库
```

`POST /admin/intents/recover` 返回三类计数：

* `safe_to_retry`：只有副作用前的 prepared 意图；job 回到 pending，可由 worker 安全再试；
* `outcome_unknown`：dispatched 后崩溃，对账器无法证明对端是否处理，保持待查；
* `converged`：已经有终态，或通过接收方观察列表确认动作真实发生。幂等补录终态后再次对账仍为 0 个新增收敛，不会产生双份终态。

出站前仍保留 fence `touch` 写探针。共享账库拒写时，claim/touch/attempt/settle 均不能成功，worker 不制造无法记账的副作用。

## 6. 封存锚点与密钥换代

周期调度由 `AnchorScheduler` 完成，也可手动：

```bash
curl -X POST "$STORE/admin/evidence/anchor" \
  -d '{"tenant_id":"tnt_...","reason":"manual"}'
```

锚点语句包含链头摘要、序号、锚点编号、上一锚点编号和当前封存代次，并用纯标准库 Ed25519（`anchor_crypto.py`）签名。

换代：

```bash
curl -X POST "$STORE/admin/sealing-keys/rotate"
```

换代流程：

1. 生成新 Ed25519 私钥/公钥，新私钥持久化到新 0600 文件；
2. 对每条已有链写入 `sealing_key_rotated` 条目；
3. 用旧代次私钥签署“旧公钥 → 新公钥、边界序号、边界摘要”的分界声明；
4. 立即用新代次私钥签署换代后锚点。

因此：

* 旧包只依赖旧公钥与旧锚点，永久可验；
* 新锚点只接受当前代次公钥；
* 即使旧私钥泄漏，也不能验证新代次伪造锚点；
* 合法包内含旧私钥签署的换代声明，足以证明分界。

## 7. 一致性导出和增量包

导出在一个短事务中冻结：

1. 读取 `MAX(seq)` 作为 `cutoff_seq`；
2. 创建 `evidence_exports`，递增 `export_cutoff` 监控；
3. 提交后主账可继续写；
4. 导出只读查询严格限制 `start_seq <= seq <= cutoff_seq`，之后内容绝不混入。

包格式是自定义长度前缀容器 `.whubpak`（不压缩），包含：

```text
entries.json     起点至 cutoff 的条目
anchors.json     cutoff 以前的锚点及签名
rotations.json   cutoff 以前的密钥换代声明
keys.json        所需公钥沿革
manifest.json    每个文件的 64 KiB 分块 SHA256
proof.json       当前公钥可验证的导出证明
```

导出证明签署：客户、起止序号、起始前摘要、cutoff 链头摘要、上一锚点、manifest 摘要和密钥代次。增量包设置 `start_seq = 上一包 cutoff + 1`，其证明携带 `start_prev_digest`，离线可紧密衔接。

离线核验：

* 先逐帧校验 64 KiB 分块摘要，得到确定字节偏移；
* 再重放条目链，得到首个失信序号；
* 校验换代声明、锚点链和导出证明；
* 无损包通过；改写、删除、插入、调序、替换锚点均失败。

## 8. 留存与司法留置

```bash
# 保留到指定 store 时间戳之后可清除
curl -X POST "$STORE/admin/retention" \
  -d '{"tenant_id":"tnt_...","retain_until_after":1780000000}'

# 增加司法留置
curl -X POST "$STORE/admin/legal-holds" \
  -d '{"tenant_id":"tnt_...","reason":"litigation-123"}'

# 执行到期检查
curl -X POST "$STORE/admin/privacy/sweep" -d '{}'

# 解除留置后再次 sweep
curl -X POST "$STORE/admin/legal-holds/hold_.../release" -d '{}'
```

清除只把可识别 `events.payload` 替换为 `[REDACTED]`，并写 `privacy_erased`：批次编号、抹除数量和留存截止点。不修改凭证条目，不改变摘要链、动作计数和次序证明。原有正文仍由入账时的 `payload_digest` 间接指代，但无法从链中还原。

司法留置有效时 sweep 只产生 `blocked_legal_hold` 批次，不抹任何正文；解除后再执行同一作业即继续清除。

## 9. 运维面、审计与监控

`GET /admin/evidence` 汇总：链头、最近锚点、待查意图、导出作业、清除进度、本地核验结论和公钥沿革。

其他接口：

* `GET /admin/evidence/{tenant}`：条目；
* `GET /admin/evidence/verify`：链完整性；
* `GET /admin/intents`：悬挂意图；
* `POST /admin/intents/recover`：对账恢复；
* `POST /admin/evidence/export`：导出；
* `GET /admin/exports` / `/admin/exports/{id}/download`；
* `POST /admin/evidence/anchor`：手动封存；
* `POST /admin/sealing-keys/rotate`：换代；
* `GET /admin/sealing-keys`：公钥沿革；
* retention / legal-holds / privacy sweep 接口。

审计日志字段包含：客户账户、序号、动作编号、事件类型、本条摘要、前条摘要、锚点编号。私钥、正文、secret、API key、Authorization 永不打印。

Prometheus 指标：

```text
whub_lease_ops{kind="credential_append"}
whub_lease_ops{kind="intent_recovery"}
whub_lease_ops{kind="tamper_detected"}
whub_lease_ops{kind="anchor_seal"}
whub_lease_ops{kind="export_cutoff"}
whub_lease_ops{kind="privacy_erase"}
```

## 10. 机器报告

`evidence-report.json` 汇总每个场景的检查、凭证总数、链头摘要、分叉/缺号、意图归类、导出截止序号、篡改定位、密钥代次和隐私泄漏扫描。专项验收不是搜索日志：它同时读取共享库、真实 sink 收据和离线核验器结果。
