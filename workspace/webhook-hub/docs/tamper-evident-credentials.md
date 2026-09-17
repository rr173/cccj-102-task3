# 防篡改凭证册（Tamper-Evident Credential Book）

为 Whub 增设的一套**离线可核验**凭证册子系统。每个客户账户拥有一条
连续摘要链，记录消息入账、所有权交接、出站尝试、对方应答、操作员再执行
与跳过；链头由周期锚点用 Ed25519 封存；封存私钥可换代、换代分界可离线
证明；支持一致性导出（冻结截止序号、增量接续）、留存到期隐私抹除与
司法留置。核验者**只凭导出包 + 包内公开材料 + 约定规范编码**就能发现
改写、删除、插入、调序、伪造锚点，并指出**首个失信序号**。

本文档解释：规范编码、摘要域隔离、原子分界、恢复判定、私钥换代。
运维 API、监控指标见文末。

---

## 1. 规范编码（canonical encoding）

所有进入摘要的对象都用唯一的字节序列化（`cred_crypto.canonical`）：

```
UTF-8，ensure_ascii=false，sort_keys=true，separators=(",",":")，allow_nan=false
```

键顺序、空白、Unicode 转义的任何差异都会改变摘要——因此协议双方都只
认这一种字节序列。

## 2. 摘要域隔离（domain separation）

不同类型的字节不得互相碰撞。每个域都带长度前缀：

```
H = sha256( len(domain) ‖ domain ‖ len(canonical(obj)) ‖ canonical(obj) )
```

域标签：

| 域 | 标签 | 用途 |
|---|---|---|
| record | `whub-cred/record/v1` | 链式条目 |
| anchor | `whub-cred/anchor/v1` | 周期锚点签名 |
| rotation | `whub-cred/rotation/v1` | 换代证书签名 |
| manifest | `whub-cred/manifest/v1` | 导出包清单签名 |

### 2.1 链条目摘要

第 n 条记录的摘要为：

```
D_n = sha256( DOMAIN_RECORD ‖ D_{n-1} ‖ canonical(body_n) )
```

`body_n` 结构（白名单字段，正文/私钥/口令**永不**出现）：

```json
{"v":1,"type":"outbound_success","seq":42,"account":"tnt_…","at":1789.0,
 "data":{ …动作引用、对方应答码、哈希… }}
```

记录类型：

* `message_ingested` —— 只存 `payload_sha256`、字节数、lane/seq、kid，
  **不存正文**；
* `ownership_handoff` —— lane、新旧 owner/epoch、reason；
* `outbound_attempt` —— 副作用**前**登记（phase=pre_side_effect），
  不是成功；
* `peer_response` —— 对方应答码/类别；
* `outbound_success` / `outbound_failure` —— 唯一终态凭证；
* `operator_reexecuted` / `operator_skipped`；
* `anchor`、`key_rotation`、`privacy_scrubbed`。

### 2.2 编号连续、无分叉

`cred_records (account_id, seq)` 为主键。追加在写事务内：读当前链头 →
新记录 `prev_digest` 必须等于链头摘要 → 以 `head_seq=旧值` 为条件更新
链头。两个执行节点共用同一 SQLite，单写者 + `BEGIN IMMEDIATE` 保证
只有一个事务赢；输家重试。结果：seq 从 1 连续、无洞、无分叉。

---

## 3. 凭证追加与主账状态的原子约定

凭证账与主账是**同一个 SQLite 文件、同一条连接、同一把写锁**，因此凭证
追加可以放进主账状态变更的**同一个事务**，要么一起提交、要么一起回滚。

出站动作拆成两个事务：

```
tx1（副作用之前）                         tx2（副作用之后）
┌─────────────────────────────┐         ┌──────────────────────────────┐
│ jobs: pending → leased      │         │ jobs: leased → succeeded/... │
│ cred: outbound_attempt      │   HTTP  │ cred: peer_response          │
│ intent: recorded            │ ──────► │       outbound_success       │
│  （绝不记成功）              │  对方   │ intent: converged            │
└─────────────────────────────┘         └──────────────────────────────┘
```

终态凭证由 `cred_finalized (action_id, kind)` 唯一约束去重——
`action_id = "{delivery_id}:a{attempt_no}"`。重复对账、重复回写都不会
产生第二张成功凭证。

## 4. 恢复判定（崩溃三窗口）

进程被 kill -9 只可能落在三个窗口，对账器（`Engine.reconcile_intents`）
据此把悬挂意图归为三类：

| 崩溃窗口 | 主账状态 | 对方 | 判定 |
|---|---|---|---|
| tx1 之前 | 无意图凭证 | 未见 | **safe_retry**（可安全再试）|
| tx1 之后、副作用之前 | leased + recorded | 未见 | **safe_retry**（接收方按 event_id 幂等，重发不二次确认）|
| 副作用之后、tx2 之前 | leased + sent | **已见** | **in_doubt**（结局待查，禁止盲发第二条，需对对方权威确认）|
| tx2 已提交 | succeeded | 已见 | **converged**（已收敛，不补发、不补第二张凭证）|

判定绝不伪造成功：只有主账终态已落，或对对方明确确认后，才允许进入
converged；对方探针（sink `/admin/observed`）只回布尔，不回正文。

锚点封存也在一个事务里：append anchor 记录 + 写 `cred_anchors` +
更新链头，提交前崩溃则整体回滚——无半截锚点、锚点编号不跳变，重启后
可严格以“上一锚点号 +1”补封。

---

## 5. 周期锚点与私钥换代

### 5.1 锚点

每账户周期性封存（`AnchorService`，仅 store 进程持有私钥）。锚点 payload
含窗口内每条记录的 `(seq,type,digest)`、窗口边界、链头、nonce，用
**当前代次**私钥签 Ed25519（域 `DOMAIN_ANCHOR`）。锚点本身也是链上一条
`anchor` 记录。

签名实现见 `cred_crypto.py`：纯标准库 Ed25519（RFC 8032 扩展坐标），
以 OpenSSL 3.0 生成的向量在模块导入时自检；签名约 2.7ms、验签约 4.3ms。

### 5.2 私钥保管

* 私钥只在 store 节点本地的 keystore 文件（`WHUB_CRED_KEY`，权限 0600，
  `fcntl` 加锁），**绝不**进入数据库、凭证、审计、导出包；
* worker 进程不持有私钥，无法签锚点。

### 5.3 换代与分界证明

`Sealer.rotate()`：

1. keystore 生成新代次（gen+1，新 Ed25519 密钥）；
2. **旧代次私钥**对一张证书签名（域 `DOMAIN_ROTATION`，含两代公钥、kid、
   nonce）；
3. 一个数据库事务：旧代次 active→0、新代次 active→1、写 rotation 行、
   链上追加 `key_rotation`。

离线性质：

* 旧包永远可用旧公钥核验；
* 换代后**新锚点只认当前代次**——拿到泄漏的旧私钥伪造“新锚点”，用新
  公钥验签必然失败；
* 导出包 `material.json` 含各代公钥与全部换代证书，核验器重放整条沿革：
  每个 `gen i → i+1` 分界都必须能用 gen i 的公钥验证证书签名。

---

## 6. 一致性导出

`Exporter.export(account, out_dir, seq_from, incremental_of)`：

* 单事务冻结 `seq_cutoff = 当前链头`，主账可同时继续写入——之后的条目
  **绝不混入**本包；
* 产物 `.whubpkg`（ZIP STORED 不压缩）：
  `records.jsonl`（seq_from..cutoff）、`anchors.jsonl`（窗口起点之后
  封存的锚点）、`material.json`（公开校验材料/沿革）、`manifest.json`
  （各文件 SHA256、起止序号、链头）、`manifest.sig`（当前代次签清单）；
* **增量包**：`seq_from = 上一包 cutoff + 1`，清单携带上一包链头，
  核验器用外部前链头验证首条记录的 prev 链接，做到紧密接续。

## 7. 离线核验器

`python3 -m whub verify <pkg.whubpkg>`（`cred_verify.verify_package`）：

不连任何服务、不读主账库、不需要私钥。依次检查：

1. 容错读取 ZIP（中央目录被破坏时按本地头顺序扫描）；
2. 逐文件 SHA256 与清单比对（物理损坏定位到文件/行/字节偏移）；
3. 清单签名必须由当前代次私钥签出；
4. 重算摘要链：编号连续、prev 链接、每条摘要——报出**第一个断裂序号**；
5. 每个锚点：签名用其声明代次公钥可验、锚点条目在链上、窗口末摘要一致；
6. 密钥沿革证书链完整且签名合法；
7. 增量包与前包链头/起点接续；
8. 隐私泄漏扫描（`whsec_`/`whk_`/`seed_b64`/`api_key`/Bearer… 不得出现）。

定位优先级：语义链断裂点（最精确）> 锚点断裂点 > 文件哈希粗定位。
返回 JSON 含 `ok`、`first_bad_seq`、`anchor_failure`、`tamper`、
`privacy_scan` 等。

---

## 8. 留存与司法留置

* 凭证链从不存正文，因此“抹除可识别内容”作用于**主账** `events.payload`
  （以及受保护附件），凭证链的计数、次序、摘要完全不动；
* `set_retention(tenant, retain_seconds=TTL)`；`scrub_privacy` 选中
  `now - created_at >= TTL` 的事件，把正文替换成固定墓碑
  `{"_redacted":true,...}`，并在**同一事务**追加一条 `privacy_scrubbed`
  凭证（只引用 event_id、正文哈希、入账链序号，**不含原值**）；
* `legal_hold=True` 期间 scrub 直接返回 `blocked=legal_hold`；解除留置后
  从游标续办；
* 抹除后动作数量与次序仍可证明，导出包依旧离线可验；接口与审计文字中
  检索不到原值（验收会做字面扫描）。

---

## 9. 运维面 / 监控 / 审计

* `GET /admin/cred/overview` —— 每账户链头、最近锚点、链核验结论、待查
  意图、导出作业、指标；
* `POST /admin/cred/anchor|rotate-keys|export|reconcile|retention|
  legal-hold|scrub`；
* `GET /admin/cred/intents|exports|audit|generations`；
* Prometheus（`/metrics`）：
  `whub_cred_appends_total`、`whub_cred_intent_recoveries_total`、
  `whub_cred_tamper_findings_total`、`whub_cred_anchor_seals_total`、
  `whub_cred_export_cutoffs_total`、`whub_cred_privacy_scrubs_total`；
* 结构化审计表 `cred_audit` 固定携带 **account、seq、本条摘要、前条摘要、
  action_id、anchor_no**，绝不打印秘密/正文/鉴权材料。

---

## 10. 一键复现

```bash
# 离线单元测试（链/锚点/换代/篡改定位/增量/留存/对账）
python3 -m unittest whub.test_cred whub.test_core -v

# 7 场景验收：空白账库 + 真实双进程 + 故障注入 + 离线核验器
python3 -m whub cred-acceptance            # 产出 cred-acceptance-report.json

# 单独核验一个导出包（不连服务）
python3 -m whub verify path/to/exp_xxx.whubpkg
```

七场景对应交付检查：①高频争用+换手 ②副作用前/后/封存途中强杀
③改写/删除/调序/替换锚点 ④并发导出+增量 ⑤私钥换代 ⑥留存/留置
⑦账库拒写。
