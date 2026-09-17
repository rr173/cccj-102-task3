"""防篡改凭证册核心：连续摘要链 + 意图两阶段 + 周期锚点 + 换代/留存。

设计要点
========
1. **每客户账户一条链**。``cred_records (account_id, seq)`` 唯一，
   追加时先在事务内读当前链头，新记录 ``prev_digest`` 必须等于链头摘要，
   再以 ``prev_seq`` 条件插入。两进程争用时只有一个事务赢，另一个
   ``retry``，因此**无分叉、无缺号**。

2. **摘要链**。第 n 条记录的摘要
   ``D_n = sha256(DOMAIN_RECORD | D_{n-1} | canonical(body_n))``；
   正文/私钥/口令从不出现在 body 内（见 :data:`RECORD_TYPES`）。

3. **意图与主账原子**。出站动作分两个事务：
   * tx1（副作用前）：主账置“意图已登记” + 凭证记 ``outbound_attempt``
     （pending，**不是成功**）；
   * tx2（副作用后）：主账置终态 + 凭证记 ``peer_response``（应答）+
     必要的 ``outbound_success``/``outbound_failure`` 终态凭证。
   崩溃窗口因此只有三种：tx1 前（安全再试）、tx1 后副作用前（安全再试，
   接收方幂等）、副作用后 tx2 前（结局待查，对账时向对方核实）。

4. **终态唯一**。意图行 ``finalized`` 唯一终态；终态凭证幂等键
   ``(action_id, kind)`` UNIQUE，重复对账只结算一次——绝无双份终态凭证。

5. **锚点**。每账户每周期封存一次，签名覆盖窗口内全部条目摘要。
6. **换代**。旧私钥签 rotation 证书，证书本身是链上一条记录。
7. **留存/留置**。到期抹除可识别正文与受保护附件，但链、计数、次序不动；
   抹除动作本身是链上记录；司法留置期间拒办。
"""
from __future__ import annotations

import json
import logging
import secrets
import sqlite3
import threading
import time
from typing import Any, Callable, Optional

from .cred_crypto import (
    DOMAIN_ANCHOR, DOMAIN_ROTATION, SigningKey, b64d, b64e, canonical,
    chain_digest, domain_hash,
)

log = logging.getLogger("whub.cred")

# 凭证记录类型（body 中严禁出现正文、私钥、访问口令、原始鉴权材料）
# 题目要求覆盖：消息入账、所有权交接、出站尝试、对方应答、
#               操作员再次执行、操作员跳过
RECORD_INGEST = "message_ingested"
RECORD_HANDOFF = "ownership_handoff"
RECORD_ATTEMPT = "outbound_attempt"
RECORD_RESPONSE = "peer_response"
RECORD_SUCCESS = "outbound_success"
RECORD_FAILURE = "outbound_failure"
RECORD_REPLAY = "operator_reexecuted"
RECORD_SKIP = "operator_skipped"
RECORD_ANCHOR = "anchor"
RECORD_ROTATION = "key_rotation"
RECORD_SCRUB = "privacy_scrubbed"

RECORD_TYPES = (
    RECORD_INGEST, RECORD_HANDOFF, RECORD_ATTEMPT, RECORD_RESPONSE,
    RECORD_SUCCESS, RECORD_FAILURE, RECORD_REPLAY, RECORD_SKIP,
    RECORD_ANCHOR, RECORD_ROTATION, RECORD_SCRUB,
)

# 意图生命周期
INTENT_RECORDED = "recorded"        # tx1 已落，副作用未确认发生
INTENT_SENT = "sent"                # 副作用已返回，终态事务进行中
INTENT_SAFE_RETRY = "safe_retry"    # 对账判定：可安全再试
INTENT_IN_DOUBT = "in_doubt"        # 对账判定：结局待查
INTENT_CONVERGED = "converged"      # 对账判定：已收敛（终态唯一）

SCHEMA = """
CREATE TABLE IF NOT EXISTS cred_accounts (
    account_id   TEXT PRIMARY KEY,
    head_seq     INTEGER NOT NULL DEFAULT 0,
    head_digest  TEXT,
    created_at   REAL NOT NULL
);

-- 连续摘要链：(account, seq) 唯一；prev_seq/prev_digest 由追加事务强校验
CREATE TABLE IF NOT EXISTS cred_records (
    account_id   TEXT NOT NULL REFERENCES cred_accounts(account_id),
    seq          INTEGER NOT NULL,
    type         TEXT NOT NULL,
    action_id    TEXT,
    anchor_no    INTEGER,
    body_json    TEXT NOT NULL,          -- 规范体（无秘密）
    digest       TEXT NOT NULL,          -- 本条摘要 b64
    prev_digest  TEXT,                   -- 前条摘要 b64
    at           REAL NOT NULL,
    PRIMARY KEY (account_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_cred_action ON cred_records(action_id);
CREATE INDEX IF NOT EXISTS idx_cred_type ON cred_records(account_id, type, seq);

-- 出站意图（每个动作一行；finalized 唯一终态）
CREATE TABLE IF NOT EXISTS cred_intents (
    action_id    TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL,
    lane_id      TEXT NOT NULL,
    job_id       TEXT NOT NULL,
    attempt_no   INTEGER NOT NULL DEFAULT 1,
    state        TEXT NOT NULL,
    recorded_seq INTEGER,                 -- outbound_attempt 的链序号
    response_code INTEGER,
    response_kind TEXT,                   -- ack | nack | transport
    at           REAL NOT NULL,
    updated_at   REAL NOT NULL,
    finalized    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_intent_state ON cred_intents(state, account_id);

-- 终态凭证幂等去重（一个动作每种终态只允许一条）
CREATE TABLE IF NOT EXISTS cred_finalized (
    action_id    TEXT NOT NULL,
    kind         TEXT NOT NULL,           -- success | failure
    seq          INTEGER NOT NULL,
    at           REAL NOT NULL,
    PRIMARY KEY (action_id, kind)
);

-- 锚点（每账户递增编号；sig 签 DOMAIN_ANCHOR|payload）
CREATE TABLE IF NOT EXISTS cred_anchors (
    account_id   TEXT NOT NULL,
    anchor_no    INTEGER NOT NULL,
    gen          INTEGER NOT NULL,        -- 签名代次
    seq_from     INTEGER NOT NULL,
    seq_upto     INTEGER NOT NULL,
    digest_upto  TEXT NOT NULL,           -- 窗口末条摘要
    payload_json TEXT NOT NULL,
    signature    TEXT NOT NULL,
    at           REAL NOT NULL,
    record_seq   INTEGER NOT NULL,       -- 锚点自身在链中的序号
    PRIMARY KEY (account_id, anchor_no)
);

-- 封存私钥沿革（公开材料；私钥在外部 keystore 文件，绝不在此）
CREATE TABLE IF NOT EXISTS cred_key_gens (
    gen          INTEGER PRIMARY KEY,
    kid          TEXT NOT NULL,
    public_b64   TEXT NOT NULL,
    active       INTEGER NOT NULL,        -- 1=当前代次（唯一一行）
    rotated_at   REAL
);

-- 换代证书（旧私钥签 DOMAIN_ROTATION|canonical(cert)）
CREATE TABLE IF NOT EXISTS cred_rotations (
    gen_from     INTEGER PRIMARY KEY,
    gen_to       INTEGER NOT NULL,
    kid_from     TEXT NOT NULL,
    kid_to       TEXT NOT NULL,
    pub_from     TEXT NOT NULL,
    pub_to       TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    at           REAL NOT NULL,
    record_seq   INTEGER NOT NULL,
    signature    TEXT NOT NULL
);

-- 留存策略与司法留置（按账户）
CREATE TABLE IF NOT EXISTS cred_retention (
    account_id   TEXT PRIMARY KEY,
    retain_until REAL NOT NULL DEFAULT 0,    -- 0=长期留存
    legal_hold   INTEGER NOT NULL DEFAULT 0,
    hold_reason  TEXT,
    updated_at   REAL NOT NULL
);

-- 导出作业（冻结截止序号，可续作）
CREATE TABLE IF NOT EXISTS cred_exports (
    export_id    TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL,
    seq_from     INTEGER NOT NULL,
    seq_cutoff   INTEGER NOT NULL,
    incremental_of TEXT,
    path         TEXT NOT NULL,
    status       TEXT NOT NULL,             -- running | complete
    created_at   REAL NOT NULL,
    finished_at  REAL
);

-- 清除进度（每账户一条游标 + 已抹条目计数）
CREATE TABLE IF NOT EXISTS cred_scrubs (
    account_id   TEXT PRIMARY KEY,
    cursor_seq   INTEGER NOT NULL DEFAULT 0,
    scrubbed     INTEGER NOT NULL DEFAULT 0,
    blocked_by_hold INTEGER NOT NULL DEFAULT 0,
    updated_at   REAL NOT NULL
);

-- 凭证侧监控指标（与 lease counters 分离）
CREATE TABLE IF NOT EXISTS cred_metrics (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

-- 结构化审计（字段固定，绝不含秘密/正文/鉴权材料）
CREATE TABLE IF NOT EXISTS cred_audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        REAL NOT NULL,
    account_id TEXT,
    seq       INTEGER,
    digest    TEXT,
    prev_digest TEXT,
    action_id TEXT,
    anchor_no INTEGER,
    event     TEXT NOT NULL
);
"""

METRIC_APPEND = "credential_appends"
METRIC_INTENT_RECOVERED = "intent_recoveries"
METRIC_TAMPER_FOUND = "tamper_findings"
METRIC_ANCHOR = "anchor_seals"
METRIC_EXPORT_CUTOFF = "export_cutoffs"
METRIC_SCRUB = "privacy_scrubs"
METRIC_NAMES = (METRIC_APPEND, METRIC_INTENT_RECOVERED, METRIC_TAMPER_FOUND,
                METRIC_ANCHOR, METRIC_EXPORT_CUTOFF, METRIC_SCRUB)


class LedgerError(Exception):
    code = "ledger_error"


class StoreRejecting(LedgerError):
    code = "store_unavailable"


class TamperDetected(LedgerError):
    """在线自检发现库内链已被改写。"""
    code = "tamper_detected"

    def __init__(self, account_id: str, seq: int, reason: str):
        super().__init__(f"{account_id} seq={seq}: {reason}")
        self.account_id = account_id
        self.seq = seq
        self.reason = reason


class Ledger:
    """凭证账。复用主账同一 SQLite 文件 => 追加可与主账状态同事务原子。"""

    # 故障注入：>0 时在锚点事务追加锚点记录之后、commit 之前硬退出，
    # 模拟“封存途中强杀”（整个锚点事务回滚，不留半截锚点/不跳号）。
    crash_in_anchor = 0

    def __init__(self, conn: sqlite3.Connection, *, reject_flag: Callable[[], bool],
                 clock: Callable[[sqlite3.Connection], float],
                 shared_lock: Optional[threading.RLock] = None):
        # 关键：复用主账 Engine 的同一把锁，保证凭证写事务与主账写事务
        # 在同一连接上严格互斥/串行（否则两个线程各持一把锁会交叉 BEGIN）。
        self._lock = shared_lock or threading.RLock()
        self.conn = conn
        self._reject = reject_flag
        self._clock = clock
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    # ------------------------------------------------------------------
    # 基础
    # ------------------------------------------------------------------

    def _bump(self, c, name: str, n: int = 1) -> None:
        c.execute(
            "INSERT INTO cred_metrics(name,value) VALUES(?,?) "
            "ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
            (name, n))

    def metric(self, name: str) -> int:
        with self._lock:
            r = self.conn.execute("SELECT value FROM cred_metrics WHERE name=?",
                                  (name,)).fetchone()
            return r["value"] if r else 0

    def metrics(self) -> dict:
        with self._lock:
            return {r["name"]: r["value"] for r in self.conn.execute(
                "SELECT name,value FROM cred_metrics")}

    def _audit(self, c, now, event: str, *, account_id=None, seq=None,
               digest=None, prev_digest=None, action_id=None,
               anchor_no=None) -> None:
        c.execute(
            "INSERT INTO cred_audit(at,account_id,seq,digest,prev_digest,"
            "action_id,anchor_no,event) VALUES(?,?,?,?,?,?,?,?)",
            (now, account_id, seq, digest, prev_digest, action_id,
             anchor_no, event))

    def audit_tail(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM cred_audit ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
            return [dict(r) for r in rows[::-1]]

    def ensure_account(self, c, account_id: str, now: float) -> None:
        c.execute(
            "INSERT INTO cred_accounts(account_id,created_at) VALUES(?,?) "
            "ON CONFLICT(account_id) DO NOTHING", (account_id, now))
        c.execute(
            "INSERT INTO cred_retention(account_id,updated_at) VALUES(?,?) "
            "ON CONFLICT(account_id) DO NOTHING", (account_id, now))

    def head(self, account_id: str) -> dict:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM cred_accounts WHERE account_id=?",
                (account_id,)).fetchone()
            if r is None:
                return {"account_id": account_id, "head_seq": 0,
                        "head_digest": None}
            return dict(r)

    # ------------------------------------------------------------------
    # 链式追加（核心）
    # ------------------------------------------------------------------

    def append_record(self, c, now: float, account_id: str, rtype: str,
                      body: dict, *, action_id: Optional[str] = None,
                      anchor_no: Optional[int] = None,
                      max_retries: int = 0) -> dict:
        """在**已打开的事务 c** 内追加一条凭证。

        必须由主账的 ``_write`` 串行化器调用（或任何持 ``BEGIN IMMEDIATE``
        的写事务）；这样它与主账状态变更天然原子。``max_retries`` 仅在
        本方法自行开启事务时（独立追加路径）生效。
        """
        if rtype not in RECORD_TYPES:
            raise LedgerError(f"unknown record type {rtype!r}")
        return self._append_locked(c, now, account_id, rtype, body,
                                   action_id=action_id, anchor_no=anchor_no)

    def _append_locked(self, c, now, account_id, rtype, body, *,
                       action_id=None, anchor_no=None) -> dict:
        self.ensure_account(c, account_id, now)
        head = c.execute(
            "SELECT head_seq, head_digest FROM cred_accounts "
            "WHERE account_id=?", (account_id,)).fetchone()
        prev_seq = head["head_seq"]
        prev_digest_b64 = head["head_digest"]
        prev_digest = b64d(prev_digest_b64) if prev_digest_b64 else None
        seq = prev_seq + 1
        # 规范体：固定字段顺序无关（canonical 排序），但显式只挑白名单
        full_body = {"v": 1, "type": rtype, "seq": seq,
                     "account": account_id, "at": round(now, 6),
                     "data": body}
        body_bytes = canonical(full_body)
        digest = chain_digest(prev_digest, json.loads(body_bytes))
        digest_b64 = b64e(digest)
        cur = c.execute(
            "INSERT INTO cred_records(account_id,seq,type,action_id,"
            "anchor_no,body_json,digest,prev_digest,at) "
            "VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(account_id,seq) DO NOTHING",
            (account_id, seq, rtype, action_id, anchor_no,
             body_bytes.decode("utf-8"), digest_b64, prev_digest_b64, now))
        if cur.rowcount == 0:
            # 并发赢家已插入同一序号：交由上层事务重试或报错（正常不会到这，
            # 因为主写串行化；独立追加路径才可能遇到）
            raise sqlite3.OperationalError("cred seq conflict")
        c.execute(
            "UPDATE cred_accounts SET head_seq=?, head_digest=? "
            "WHERE account_id=? AND head_seq=?",
            (seq, digest_b64, account_id, prev_seq))
        self._bump(c, METRIC_APPEND)
        self._audit(c, now, f"append:{rtype}", account_id=account_id, seq=seq,
                    digest=digest_b64, prev_digest=prev_digest_b64,
                    action_id=action_id, anchor_no=anchor_no)
        log.info("cred append account=%s seq=%d type=%s action=%s anchor=%s "
                 "digest=%s prev=%s", account_id, seq, rtype,
                 action_id, anchor_no, digest_b64[:12],
                 (prev_digest_b64 or "")[:12])
        return {"seq": seq, "digest": digest_b64,
                "prev_digest": prev_digest_b64, "body": full_body}

    def transact(self, fn: Callable[[sqlite3.Connection, float], Any],
                 retries: int = 8) -> Any:
        """凭证侧独立串行写事务（受同一写闸门约束）。

        fn 收到 (conn, now)，可在其中 append_record / 写 anchors 等。
        与主账 ``_write`` 共用 ``self._lock`` 与同一连接，因此和主账状态
        事务彼此串行、不会交叉。
        """
        attempt = 0
        while True:
            with self._lock:
                if self._reject():
                    raise StoreRejecting("store rejecting writes")
                try:
                    self.conn.execute("BEGIN IMMEDIATE")
                    now = self._clock(self.conn)
                    out = fn(self.conn, now)
                    if getattr(self, "_crash_after_anchor", False) and out:
                        self._crash_after_anchor = False
                        log.error("FAULT: crash DURING anchor sealing "
                                  "(before commit)")
                        import os
                        os._exit(1)
                    self.conn.commit()
                    return out
                except sqlite3.OperationalError as e:
                    self.conn.rollback()
                    if "locked" in str(e).lower() or "busy" in str(e).lower():
                        if attempt < retries:
                            attempt += 1
                            time.sleep(0.02 * attempt)
                            continue
                    raise
                except Exception:
                    self.conn.rollback()
                    raise

    def append_standalone(self, account_id: str, rtype: str, body: dict,
                          *, action_id=None, retries: int = 8) -> dict:
        """独立追加路径（不与主账状态耦合的记录，如锚点/换代/清除）。

        自开 IMMEDIATE 事务并在 seq 冲突时重试。受主写串行化器的写闸门约束。
        """
        return self.transact(
            lambda c, now: self.append_record(
                c, now, account_id, rtype, body, action_id=action_id),
            retries=retries)

    def get_record(self, account_id: str, seq: int) -> Optional[dict]:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM cred_records WHERE account_id=? AND seq=?",
                (account_id, seq)).fetchone()
            return dict(r) if r else None

    def records(self, account_id: str, seq_from: int = 1,
                seq_to: Optional[int] = None) -> list[dict]:
        q = ("SELECT * FROM cred_records WHERE account_id=? AND seq>=?")
        args: list[Any] = [account_id, seq_from]
        if seq_to is not None:
            q += " AND seq<=?"
            args.append(seq_to)
        q += " ORDER BY seq"
        with self._lock:
            return [dict(r) for r in self.conn.execute(q, args)]

    # ------------------------------------------------------------------
    # 出站意图两阶段（与主账作业状态同事务）
    # ------------------------------------------------------------------

    def begin_intent(self, c, now, *, account_id: str, action_id: str,
                     lane_id: str, job_id: str, attempt_no: int,
                     body: dict) -> dict:
        """tx1：登记意图 + 写 pending 的 outbound_attempt。

        返回意图记录。重复 action_id 时返回既有行（接收方/操作员幂等）。
        """
        rec = self._append_locked(
            c, now, account_id, RECORD_ATTEMPT, body, action_id=action_id)
        c.execute(
            "INSERT INTO cred_intents(action_id,account_id,lane_id,job_id,"
            "attempt_no,state,recorded_seq,at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(action_id) DO NOTHING",
            (action_id, account_id, lane_id, job_id, attempt_no,
             INTENT_RECORDED, rec["seq"], now, now))
        return {"state": INTENT_RECORDED, "seq": rec["seq"]}

    def mark_sent(self, c, now, action_id: str, code: int,
                  kind: str) -> None:
        """副作用已返回、终态事务开始（sent 窗口）。"""
        c.execute(
            "UPDATE cred_intents SET state=?, response_code=?, "
            "response_kind=?, updated_at=? WHERE action_id=? AND finalized=0",
            (INTENT_SENT, code, kind, now, action_id))

    def finalize_success(self, c, now, *, account_id: str, action_id: str,
                         code: int, peer_event: Optional[str],
                         response_body_meta: dict) -> dict:
        """tx2 成功终态：peer_response + outbound_success，意图置收敛。

        通过 cred_finalized 唯一约束保证“一次动作只有一个终态凭证”。
        """
        resp = self._append_locked(
            c, now, account_id, RECORD_RESPONSE,
            {"action_id": action_id, "code": code, "kind": "ack",
             "peer_event_id": peer_event, **response_body_meta},
            action_id=action_id)
        term = self._append_locked(
            c, now, account_id, RECORD_SUCCESS,
            {"action_id": action_id, "code": code,
             "peer_event_id": peer_event, "response_seq": resp["seq"]},
            action_id=action_id)
        c.execute(
            "INSERT INTO cred_finalized(action_id,kind,seq,at) "
            "VALUES(?,?,?,?) ON CONFLICT(action_id,kind) DO NOTHING",
            (action_id, "success", term["seq"], now))
        c.execute(
            "UPDATE cred_intents SET state=?, finalized=1, "
            "response_code=?, response_kind='ack', updated_at=? "
            "WHERE action_id=?",
            (INTENT_CONVERGED, code, now, action_id))
        return {"response_seq": resp["seq"], "success_seq": term["seq"]}

    def finalize_failure(self, c, now, *, account_id: str, action_id: str,
                         code: Optional[int], kind: str, reason_class: str,
                         terminal: bool) -> dict:
        """tx2 失败终态：peer_response(nack/transport) + outbound_failure。

        terminal=False（可重试）时意图退回 safe_retry，不写终态标记；
        terminal=True（dead）写 finalized failure 终态凭证。
        """
        resp = self._append_locked(
            c, now, account_id, RECORD_RESPONSE,
            {"action_id": action_id, "code": code, "kind": kind,
             "reason_class": reason_class}, action_id=action_id)
        if terminal:
            term = self._append_locked(
                c, now, account_id, RECORD_FAILURE,
                {"action_id": action_id, "code": code, "kind": kind,
                 "reason_class": reason_class, "response_seq": resp["seq"]},
                action_id=action_id)
            c.execute(
                "INSERT INTO cred_finalized(action_id,kind,seq,at) "
                "VALUES(?,?,?,?) ON CONFLICT(action_id,kind) DO NOTHING",
                (action_id, "failure", term["seq"], now))
            c.execute(
                "UPDATE cred_intents SET state=?, finalized=1, "
                "response_code=?, response_kind=?, updated_at=? "
                "WHERE action_id=?",
                (INTENT_CONVERGED, code, kind, now, action_id))
            return {"response_seq": resp["seq"], "failure_seq": term["seq"]}
        c.execute(
            "UPDATE cred_intents SET state=?, response_code=?, "
            "response_kind=?, updated_at=? WHERE action_id=?",
            (INTENT_SAFE_RETRY, code, kind, now, action_id))
        return {"response_seq": resp["seq"]}

    def pending_intents(self, account_id: Optional[str] = None,
                        states=(INTENT_RECORDED, INTENT_SENT)) -> list[dict]:
        states = tuple(states)
        placeholders = ",".join("?" * len(states))
        q = f"SELECT * FROM cred_intents WHERE state IN ({placeholders})"
        args: list[Any] = list(states)
        if account_id:
            q += " AND account_id=?"
            args.append(account_id)
        q += " ORDER BY at"
        with self._lock:
            return [dict(r) for r in self.conn.execute(q, args)]

    def intent(self, action_id: str) -> Optional[dict]:
        with self._lock:
            r = self.conn.execute("SELECT * FROM cred_intents WHERE action_id=?",
                                  (action_id,)).fetchone()
            return dict(r) if r else None

    def set_intent_state(self, c, now, action_id: str, state: str,
                         finalized: bool = False, **kw) -> None:
        sets = ["state=?", "updated_at=?"]
        args: list[Any] = [state, now]
        if finalized:
            sets.append("finalized=1")
        for k, v in kw.items():
            sets.append(f"{k}=?")
            args.append(v)
        args.append(action_id)
        c.execute(f"UPDATE cred_intents SET {','.join(sets)} WHERE action_id=?",
                  args)

    # ------------------------------------------------------------------
    # 在线自检（链完整性）
    # ------------------------------------------------------------------

    def verify_chain(self, account_id: str,
                     upto: Optional[int] = None) -> dict:
        """重算账户链。返回 {ok,last_seq,first_bad_seq,reason}。

        不依赖锚点（锚点是外部时间证据；链本身的改写由此即可识别）。
        """
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM cred_records WHERE account_id=? ORDER BY seq",
                (account_id,)).fetchall()
            prev = None
            expected = 1
            for r in rows:
                if upto is not None and r["seq"] > upto:
                    break
                if r["seq"] != expected:
                    return {"ok": False, "first_bad_seq": r["seq"],
                            "last_seq": expected - 1,
                            "reason": f"gap/dup: expected {expected}"}
                body = json.loads(r["body_json"])
                calc = b64e(chain_digest(prev, body))
                if r["prev_digest"] != (b64e(prev) if prev else None):
                    return {"ok": False, "first_bad_seq": r["seq"],
                            "last_seq": expected - 1,
                            "reason": "prev_digest mismatch"}
                if r["digest"] != calc:
                    return {"ok": False, "first_bad_seq": r["seq"],
                            "last_seq": expected - 1,
                            "reason": "digest mismatch"}
                prev = b64d(r["digest"])
                expected += 1
            return {"ok": True, "last_seq": expected - 1}

    # ------------------------------------------------------------------
    # 封存密钥代次（与 keystore 配合）
    # ------------------------------------------------------------------

    def ensure_genesis_generation(self, signing: SigningKey) -> None:
        """初始化首代封存密钥（幂等）。主账首启时调用。"""
        with self._lock:
            if self.conn.execute("SELECT COUNT(*) n FROM cred_key_gens") \
                    .fetchone()["n"]:
                return
            if self._reject():
                raise StoreRejecting("store rejecting writes")
            self.conn.execute("BEGIN IMMEDIATE")
            now = self._clock(self.conn)
            try:
                if not self.conn.execute(
                        "SELECT COUNT(*) n FROM cred_key_gens").fetchone()["n"]:
                    self.conn.execute(
                        "INSERT INTO cred_key_gens(gen,kid,public_b64,active,"
                        "rotated_at) VALUES(1,?,?,1,NULL)",
                        (signing.public_b64() and "seal-1",
                         signing.public_b64()))
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def active_generation(self) -> Optional[dict]:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM cred_key_gens WHERE active=1").fetchone()
            return dict(r) if r else None

    def key_generations(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT gen,kid,public_b64,active,rotated_at FROM cred_key_gens "
                "ORDER BY gen")]

    def rotation(self, gen_from: int) -> Optional[dict]:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM cred_rotations WHERE gen_from=?",
                (gen_from,)).fetchone()
            return dict(r) if r else None

    def commit_rotation(self, *, cert: dict, signature: bytes,
                        new_public_b64: str, new_kid: str,
                        new_gen: int) -> dict:
        """把旧私钥签好的换代证书落库 + 追加链记录（单事务）。

        证书体在 :mod:`whub.cred_seal` 构造；这里只负责原子落库：
        旧代次 active->0、新代次 active=1、rotation 行、链上 key_rotation。
        """
        with self._lock:
            if self._reject():
                raise StoreRejecting("store rejecting writes")
            self.conn.execute("BEGIN IMMEDIATE")
            now = self._clock(self.conn)
            try:
                old = self.conn.execute(
                    "SELECT * FROM cred_key_gens WHERE active=1").fetchone()
                if old is None:
                    raise LedgerError("no active sealing generation")
                if old["gen"] != cert["gen_from"]:
                    raise LedgerError("rotation base is not the active gen")
                rec = self.append_record(
                    self.conn, now, cert["account"], RECORD_ROTATION,
                    {"cert": cert}, action_id=None)
                self.conn.execute(
                    "INSERT INTO cred_rotations(gen_from,gen_to,kid_from,"
                    "kid_to,pub_from,pub_to,nonce,at,record_seq,signature) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (cert["gen_from"], cert["gen_to"], cert["kid_from"],
                     cert["kid_to"], cert["pub_from"], cert["pub_to"],
                     cert["nonce"], now, rec["seq"], b64e(signature)))
                self.conn.execute(
                    "UPDATE cred_key_gens SET active=0, rotated_at=? WHERE gen=?",
                    (now, cert["gen_from"]))
                self.conn.execute(
                    "INSERT INTO cred_key_gens(gen,kid,public_b64,active,"
                    "rotated_at) VALUES(?,?,?,1,NULL)",
                    (new_gen, new_kid, new_public_b64))
                self.conn.commit()
                return {"record_seq": rec["seq"], "gen_to": new_gen}
            except Exception:
                self.conn.rollback()
                raise

    def rotation_cert_for(self, gen: int) -> Optional[dict]:
        """导出用：取某个代次换代的证书与签名（gen 为旧代次）。"""
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM cred_rotations WHERE gen_from=?",
                (gen,)).fetchone()
            if not r:
                return None
            d = dict(r)
            # 规范证书体必须与签名时逐字节一致：v/account/gen_from/.../nonce/note。
            cert = {"v": 1, "account": "__keylineage__",
                    "gen_from": d["gen_from"], "gen_to": d["gen_to"],
                    "kid_from": d["kid_from"], "kid_to": d["kid_to"],
                    "pub_from": d["pub_from"], "pub_to": d["pub_to"],
                    "nonce": d["nonce"], "note": "rotated"}
            return {"cert": cert, "signature": d["signature"]}

    # ------------------------------------------------------------------
    # 留存 / 司法留置 / 隐私抹除
    # ------------------------------------------------------------------

    def set_retention(self, account_id: str, *, retain_until: Optional[float] = None,
                      legal_hold: Optional[bool] = None,
                      hold_reason: Optional[str] = None) -> dict:
        with self._lock:
            if self._reject():
                raise StoreRejecting("store rejecting writes")
            self.conn.execute("BEGIN IMMEDIATE")
            now = self._clock(self.conn)
            try:
                self.ensure_account(self.conn, account_id, now)
                if retain_until is not None:
                    self.conn.execute(
                        "UPDATE cred_retention SET retain_until=?, updated_at=? "
                        "WHERE account_id=?", (retain_until, now, account_id))
                if legal_hold is not None:
                    self.conn.execute(
                        "UPDATE cred_retention SET legal_hold=?, hold_reason=?, "
                        "updated_at=? WHERE account_id=?",
                        (1 if legal_hold else 0,
                         hold_reason if legal_hold else None, now, account_id))
                    if legal_hold:
                        self.conn.execute(
                            "UPDATE cred_scrubs SET blocked_by_hold=1,"
                            "updated_at=? WHERE account_id=?", (now, account_id))
                self.conn.commit()
                return self.retention(account_id)
            except Exception:
                self.conn.rollback()
                raise

    def retention(self, account_id: str) -> dict:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM cred_retention WHERE account_id=?",
                (account_id,)).fetchone()
            return dict(r) if r else {"account_id": account_id,
                                      "retain_until": 0, "legal_hold": 0}

    def scrub_progress(self, account_id: str) -> dict:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM cred_scrubs WHERE account_id=?",
                (account_id,)).fetchone()
            return dict(r) if r else {"account_id": account_id, "cursor_seq": 0,
                                      "scrubbed": 0, "blocked_by_hold": 0}

    def run_scrub(self, account_id: str, *, now_value=None, batch_limit=200):
        """已废弃：正文抹除由引擎 Engine.scrub_privacy 在主账完成。

        凭证册本身不含可识别正文（只有哈希），无需也不允许改动既有链条目。
        """
        return self.scrub_progress(account_id)

    def record_scrub(self, c, now, *, account_id: str,
                     refs, ttl_seconds: float,
                     mode: str = "retention_expired") -> dict:
        """在主账抹除事务内追加一条 privacy_scrubbed 凭证。

        refs 只含不可反推正文的引用：event_id、payload 哈希、入账链序号。
        """
        rec = self.append_record(
            c, now, account_id, RECORD_SCRUB,
            {"mode": mode, "ttl_seconds": round(ttl_seconds, 6),
             "count": len(refs), "refs": refs}, action_id=None)
        self._bump(c, METRIC_SCRUB, len(refs))
        return {"seq": rec["seq"], "count": len(refs)}

    def mark_scrub_cursor(self, c, now, account_id: str,
                          event_created_upto: float, scrubbed: int) -> None:
        c.execute(
            "INSERT INTO cred_scrubs(account_id,cursor_seq,scrubbed,"
            "blocked_by_hold,updated_at) VALUES(?,?,?,0,?) "
            "ON CONFLICT(account_id) DO UPDATE SET cursor_seq=excluded.cursor_seq,"
            "scrubbed=scrubbed+excluded.scrubbed,updated_at=excluded.updated_at",
            (account_id, event_created_upto, scrubbed, now))

    # ------------------------------------------------------------------
    # 视图
    # ------------------------------------------------------------------

    def accounts(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM cred_accounts ORDER BY account_id")]

    def anchor(self, account_id: str, anchor_no: int) -> Optional[dict]:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM cred_anchors WHERE account_id=? AND anchor_no=?",
                (account_id, anchor_no)).fetchone()
            return dict(r) if r else None

    def anchors(self, account_id: str) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM cred_anchors WHERE account_id=? ORDER BY anchor_no",
                (account_id,))]

    def latest_anchor(self, account_id: str) -> Optional[dict]:
        with self._lock:
            r = self.conn.execute(
                "SELECT * FROM cred_anchors WHERE account_id=? "
                "ORDER BY anchor_no DESC LIMIT 1", (account_id,)).fetchone()
            return dict(r) if r else None

    def insert_anchor_row(self, c, now, *, account_id: str, anchor_no: int,
                          gen: int, seq_from: int, seq_upto: int,
                          digest_upto: str, payload: dict, signature: bytes,
                          record_seq: int) -> None:
        c.execute(
            "INSERT INTO cred_anchors(account_id,anchor_no,gen,seq_from,"
            "seq_upto,digest_upto,payload_json,signature,at,record_seq) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (account_id, anchor_no, gen, seq_from, seq_upto, digest_upto,
             canonical(payload).decode(), b64e(signature), now, record_seq))

    def record_export(self, c, now, *, export_id: str, account_id: str,
                      seq_from: int, seq_cutoff: int, incremental_of,
                      path: str, status: str) -> None:
        c.execute(
            "INSERT INTO cred_exports(export_id,account_id,seq_from,seq_cutoff,"
            "incremental_of,path,status,created_at,finished_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (export_id, account_id, seq_from, seq_cutoff, incremental_of,
             path, status, now, now if status == "complete" else None))
        self._bump(c, METRIC_EXPORT_CUTOFF)

    def exports(self, account_id: Optional[str] = None) -> list[dict]:
        with self._lock:
            if account_id:
                rows = self.conn.execute(
                    "SELECT * FROM cred_exports WHERE account_id=? ORDER BY created_at",
                    (account_id,)).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM cred_exports ORDER BY created_at").fetchall()
            return [dict(r) for r in rows]
