"""共享 durable store 的仲裁引擎（SQLite 实现，接口可平移到 Postgres）。

跨进程正确性的唯一裁判是本引擎中的**数据库事务**：

* lane（= 端点内一个 object_key 的投递通道）的所有权行带
  ``owner_id / lease_epoch / fence_id / expires_at``；
* acquire / renew / handoff / claim / success / retry / dead / release
  全部是单条带 fence 条件（``owner_id=? AND lease_epoch=? AND fence_id=?``）
  的 UPDATE，影响 0 行即陈旧，事务内直接计入 ``stale_write_rejected``；
* 首次 acquire、expiry/orphan steal、drain/rebalance/shutdown handoff
  都会让 owner 变化并把 epoch+1、换发 fence_id；renew 只延长到期时间，
  绝不动 epoch/fence；
* 所有期限来自 store 进程独占的混合单调时钟（``_clock_now``）：
  以墙上时钟为读数、以持久化高水位兜底回拨，worker 的本地时钟完全不参与仲裁。

引擎单写者（调用方持锁 / HTTP store 天然串行化写事务），读不加闸门。
``reject_writes`` 用于注入 store outage：闸门开启时一切写事务抛
:class:`StoreUnavailable`，worker 因此不可能继续制造出站副作用。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from typing import Any, Callable, Optional

from . import anchor_crypto
from . import evidence_pack

log = logging.getLogger("whub.lease")

# ---- 稳定错误码（控制面/worker/验收共同依赖） ------------------------

class StoreError(Exception):
    code = "store_error"

    def __init__(self, message: str = "", **extra: Any):
        super().__init__(message or self.code)
        self.extra = extra


class StaleEpoch(StoreError):
    """owner/epoch/fence 不匹配：旧 owner 的回写被拒绝。"""
    code = "stale_epoch"


class LeaseNotOwned(StoreError):
    """行根本不处于该 worker 租约内（未持有 / 已交回公共池）。"""
    code = "lease_not_owned"


class StoreUnavailable(StoreError):
    """durable store 拒绝写入（outage 注入或 IO 故障）。"""
    code = "store_unavailable"


TERMINAL = ("succeeded", "canceled", "dead")
ACTIVE_METRICS = ("acquire", "renew", "steal", "stale_write_rejected",
                  "drain_handoff", "orphan_recovered")
EVIDENCE_METRICS = ("credential_append", "intent_recovery", "tamper_detected",
                    "anchor_seal", "export_cutoff", "privacy_erase")

DOMAIN_ENTRY = "whub/evidence-entry/v1"
DOMAIN_ANCHOR = "whub/evidence-anchor/v1"
DOMAIN_ROTATION = "whub/sealing-key-rotation/v1"
DOMAIN_EXPORT = "whub/evidence-export/v1"

TERMINAL_EVENTS = {"delivery_result"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    api_key     TEXT NOT NULL UNIQUE,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenants(id),
    name           TEXT NOT NULL,
    active_version INTEGER NOT NULL DEFAULT 0,
    parallelism    INTEGER NOT NULL DEFAULT 1,
    disabled       INTEGER NOT NULL DEFAULT 0,
    created_at     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoint_versions (
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    kid         TEXT NOT NULL,
    secret      TEXT NOT NULL,
    url         TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  REAL NOT NULL,
    retired_at  REAL,
    PRIMARY KEY (endpoint_id, version)
);

CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    endpoint_id     TEXT NOT NULL REFERENCES endpoints(id),
    idempotency_key TEXT,
    object_key      TEXT NOT NULL,
    payload         TEXT NOT NULL,
    created_at      REAL NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);

-- delivery lane：端点内同一 object_key 的串行通道，也是 lease 的仲裁单位。
CREATE TABLE IF NOT EXISTS lanes (
    lane_id     TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
    object_key  TEXT NOT NULL,
    last_seq    INTEGER NOT NULL DEFAULT 0,       -- 已分配的最大序号
    -- failover 必须沿用的水位与快照（始终等于当前队头 job 的快照）
    not_before  REAL NOT NULL DEFAULT 0,
    target_url  TEXT,
    sig_version INTEGER,
    kid         TEXT,
    -- ---- 持久化 lease 协议（题目要求等价暴露的字段）----
    owner_id    TEXT,                             -- NULL = 公共池
    lease_epoch INTEGER NOT NULL DEFAULT 0,
    fence_id    TEXT,                             -- 一次 owner 存续期的令牌
    expires_at  REAL,                             -- 全部以 store 时钟计
    draining    INTEGER NOT NULL DEFAULT 0,       -- owner 处于 drain 时的冗余镜像
    last_handoff_reason TEXT,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    UNIQUE (endpoint_id, object_key)
);
CREATE INDEX IF NOT EXISTS idx_lanes_owner ON lanes(owner_id);
CREATE INDEX IF NOT EXISTS idx_lanes_pool ON lanes(owner_id, expires_at);

CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    endpoint_id  TEXT NOT NULL REFERENCES endpoints(id),
    lane_id      TEXT NOT NULL REFERENCES lanes(lane_id),
    event_id     TEXT NOT NULL REFERENCES events(id),
    seq          INTEGER NOT NULL,
    -- 入队瞬间不可变快照；任何 owner 都只能按它签名、发往它记录的 URL
    sig_version  INTEGER NOT NULL,
    target_url   TEXT NOT NULL,
    kid          TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending|leased|succeeded|dead|canceled
    attempts     INTEGER NOT NULL DEFAULT 0,
    fail_count   INTEGER NOT NULL DEFAULT 0,
    last_status  INTEGER,
    last_error   TEXT,
    not_before   REAL NOT NULL DEFAULT 0,
    leased_by    TEXT,
    lease_epoch  INTEGER,
    fence_id     TEXT,
    leased_until REAL,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    UNIQUE (lane_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_jobs_claim ON jobs(lane_id, status, seq);
CREATE INDEX IF NOT EXISTS idx_jobs_endpoint ON jobs(endpoint_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_event ON jobs(event_id);

-- worker 成员（不同 OS 进程各占一行；incarnation 区分同 id 的新老进程）
CREATE TABLE IF NOT EXISTS workers (
    worker_id      TEXT PRIMARY KEY,
    incarnation    TEXT NOT NULL,
    host           TEXT NOT NULL DEFAULT '',
    port           INTEGER NOT NULL DEFAULT 0,
    draining       INTEGER NOT NULL DEFAULT 0,
    drain_until    REAL,
    last_heartbeat REAL NOT NULL,
    registered_at  REAL NOT NULL
);

-- 一次所有权变更一条因果记录（lane/old/new/old_epoch/new_epoch/reason）
CREATE TABLE IF NOT EXISTS ownership_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         REAL NOT NULL,
    lane_id    TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    object_key TEXT NOT NULL,
    old_owner  TEXT,
    new_owner  TEXT,
    old_epoch  INTEGER NOT NULL,
    new_epoch  INTEGER NOT NULL,
    reason     TEXT NOT NULL
);

-- 按 worker 持久化的指标计数（陈旧 worker 重启后计数不丢）
CREATE TABLE IF NOT EXISTS counters (
    worker_id TEXT NOT NULL,
    name      TEXT NOT NULL,
    value     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (worker_id, name)
);

-- 离线可核验凭证册：每客户一条只增、连续编号的摘要链。
CREATE TABLE IF NOT EXISTS evidence_entries (
    tenant_id    TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    event_type   TEXT NOT NULL,
    action_id    TEXT NOT NULL,
    anchor_id    TEXT,
    prev_digest  TEXT NOT NULL,
    digest       TEXT NOT NULL,
    body_json    TEXT NOT NULL,
    created_at   REAL NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_terminal
    ON evidence_entries(tenant_id, action_id)
    WHERE event_type='delivery_result';

CREATE TABLE IF NOT EXISTS evidence_anchors (
    tenant_id   TEXT NOT NULL,
    anchor_id   TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    generation  INTEGER NOT NULL,
    prev_anchor_id TEXT,
    digest      TEXT NOT NULL,
    signature   TEXT NOT NULL,
    signed_json TEXT NOT NULL,
    created_at  REAL NOT NULL,
    PRIMARY KEY (tenant_id, anchor_id)
);

CREATE TABLE IF NOT EXISTS sealing_keys (
    generation  INTEGER PRIMARY KEY,
    public_key  TEXT NOT NULL UNIQUE,
    started_at  REAL NOT NULL,
    retired_at  REAL
);
CREATE TABLE IF NOT EXISTS sealing_rotations (
    tenant_id       TEXT NOT NULL,
    from_generation INTEGER NOT NULL,
    to_generation   INTEGER NOT NULL,
    seq             INTEGER NOT NULL,
    action_id       TEXT NOT NULL,
    signed_json     TEXT NOT NULL,
    signature       TEXT NOT NULL,
    created_at      REAL NOT NULL,
    PRIMARY KEY (tenant_id, from_generation)
);

CREATE TABLE IF NOT EXISTS delivery_intents (
    action_id    TEXT PRIMARY KEY,
    job_id       TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    lane_id      TEXT NOT NULL,
    attempt_no   INTEGER NOT NULL,
    state        TEXT NOT NULL, -- prepared|dispatched|response_seen|settled
    outcome      TEXT,          -- success|retry|dead|skipped|safe_to_retry|outcome_unknown|converged
    worker_id    TEXT,
    lease_epoch  INTEGER,
    fence_id     TEXT,
    http_code    INTEGER,
    error_kind   TEXT,
    response_digest TEXT,
    request_digest  TEXT,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_intents_state ON delivery_intents(state, tenant_id);

CREATE TABLE IF NOT EXISTS retention_policies (
    tenant_id      TEXT PRIMARY KEY,
    retain_until_after REAL NOT NULL,
    updated_at     REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS legal_holds (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    reason      TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  REAL NOT NULL,
    released_at REAL
);
CREATE INDEX IF NOT EXISTS idx_holds_active ON legal_holds(tenant_id, active);

CREATE TABLE IF NOT EXISTS privacy_batches (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    status      TEXT NOT NULL,
    events_redacted INTEGER NOT NULL DEFAULT 0,
    attachments_redacted INTEGER NOT NULL DEFAULT 0,
    evidence_seq INTEGER,
    note        TEXT,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_exports (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    start_seq      INTEGER NOT NULL,
    cutoff_seq     INTEGER NOT NULL,
    receipt_seq    INTEGER,
    anchor_id      TEXT,
    path           TEXT,
    status         TEXT NOT NULL,
    chunk_size     INTEGER NOT NULL,
    created_at     REAL NOT NULL,
    completed_at   REAL,
    updated_at     REAL NOT NULL DEFAULT 0
);
"""


def new_fence() -> str:
    return "fence_" + secrets.token_hex(12)


class Engine:
    """所有方法线程安全；跨进程安全由事务保证，而非任何进程内锁。"""

    def __init__(self, path: str, private_key_dir: str | None = None):
        self._lock = threading.RLock()
        self.private_key_dir = private_key_dir or os.path.join(
            os.path.dirname(os.path.abspath(path)), "sealing-keys")
        os.makedirs(self.private_key_dir, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=10000;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()
            self._init_sealing_generation_locked()
        # 写闸门：True 时一切写事务失败（store outage 注入）
        self.reject_writes = False
        # 验收用故障点：在指定原子边界后立即 SIGKILL；空表示不启用。
        self.crash_after_commit = ""
        self.export_dir = os.path.join(os.path.dirname(os.path.abspath(path)),
                                       "evidence-exports")
        os.makedirs(self.export_dir, exist_ok=True)
        self.started_at = time.time()

    def close(self) -> None:
        with self._lock:
            self.conn.commit()
            self.conn.close()

    # ---- 单调时钟 ----------------------------------------------------

    def _clock_now(self, conn) -> float:
        """以 store 墙上时钟为读数，持久化高水位保证单调且可跨重启。

        worker 本地时钟永远不会进入这个函数。"""
        wall = time.time()
        row = conn.execute("SELECT value FROM meta WHERE key='clock_hi'").fetchone()
        hi = float(row["value"]) if row else 0.0
        now = wall if wall > hi else hi + 0.001
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('clock_hi',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now),))
        return now

    def now(self) -> float:
        """只读当前时间（不推高水位；写事务内一律使用 tx 传入的 now）。"""
        with self._lock:
            wall = time.time()
            row = self.conn.execute(
                "SELECT value FROM meta WHERE key='clock_hi'").fetchone()
            return max(wall, float(row["value"]) if row else 0.0)

    def _write(self, fn: Callable[[sqlite3.Connection, float], Any]) -> Any:
        """串行化的写事务包装：先过写闸门，再取 store 时间。

        StaleEpoch / LeaseNotOwned 是 fence 裁决的**预期结果**：拒绝发生前
        可能已写入 stale_write_rejected 计数，因此这类异常走 commit 而不是
        rollback，保证“被拒绝”这件事本身可观测、不丢。"""
        with self._lock:
            if self.reject_writes:
                raise StoreUnavailable("durable store is rejecting writes")
            conn = self.conn
            try:
                conn.execute("BEGIN IMMEDIATE")
                now = self._clock_now(conn)
                out = fn(conn, now)
                conn.commit()
                self._maybe_crash_after_commit()
                return out
            except (StaleEpoch, LeaseNotOwned):
                conn.commit()  # 保留 stale_write_rejected 计数
                raise
            except StoreUnavailable:
                conn.rollback()
                raise
            except Exception:
                conn.rollback()
                raise

    @staticmethod
    def _bump(conn, worker: str, name: str, n: int = 1) -> None:
        conn.execute(
            "INSERT INTO counters(worker_id,name,value) VALUES(?,?,?) "
            "ON CONFLICT(worker_id,name) DO UPDATE SET value=value+excluded.value",
            (worker, name, n))

    # ---- 防篡改凭证册：规范编码、摘要与封存密钥 ----------------------

    @staticmethod
    def canonical_json(obj: Any) -> bytes:
        return json.dumps(
            obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode("utf-8")

    @classmethod
    def _domain_digest(cls, domain: str, body: Any) -> str:
        raw = cls.canonical_json({"domain": domain, "body": body})
        return hashlib.sha256(raw).hexdigest()

    def _seed_path(self, generation: int) -> str:
        return os.path.join(self.private_key_dir,
                            f"sealing-key-generation-{generation:04d}.seed")

    def _write_seed_durable(self, generation: int, seed: bytes) -> None:
        path = self._seed_path(generation)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, seed)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read_seed(self, generation: int) -> bytes:
        with open(self._seed_path(generation), "rb") as f:
            seed = f.read()
        if len(seed) != 32:
            raise RuntimeError(f"invalid sealing seed for generation {generation}")
        return seed

    def _init_sealing_generation_locked(self) -> None:
        row = self.conn.execute(
            "SELECT MAX(generation) g FROM sealing_keys").fetchone()
        if row and row["g"] is not None:
            return
        seed, pub = anchor_crypto.generate_key()
        self._write_seed_durable(0, seed)
        self.conn.execute(
            "INSERT INTO sealing_keys(generation,public_key,started_at) "
            "VALUES(0,?,?)", (pub.hex(), self.now()))
        self.conn.commit()

    def current_sealing_generation(self, conn=None) -> dict:
        c = conn or self.conn
        row = c.execute(
            "SELECT * FROM sealing_keys WHERE retired_at IS NULL "
            "ORDER BY generation DESC LIMIT 1").fetchone()
        if row is None:
            raise RuntimeError("no sealing generation")
        return dict(row)

    def sealing_keys(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT generation,public_key,started_at,retired_at "
                "FROM sealing_keys ORDER BY generation")]

    def _append_evidence(self, c, now, tenant_id: str, event_type: str,
                         action_id: str, attributes: dict,
                         metric_worker: str = "store") -> sqlite3.Row:
        prev = c.execute(
            "SELECT * FROM evidence_entries WHERE tenant_id=? "
            "ORDER BY seq DESC LIMIT 1", (tenant_id,)).fetchone()
        seq = (prev["seq"] + 1) if prev else 1
        prev_digest = prev["digest"] if prev else "GENESIS"
        body = {"version": 1, "tenant_id": tenant_id, "seq": seq,
                "event_type": event_type, "action_id": action_id,
                "prev_digest": prev_digest, "created_at": now,
                "attributes": attributes}
        body_json = self.canonical_json(body).decode("ascii")
        digest = self._domain_digest(DOMAIN_ENTRY, body)
        c.execute(
            "INSERT INTO evidence_entries(tenant_id,seq,event_type,action_id,"
            "anchor_id,prev_digest,digest,body_json,created_at) "
            "VALUES(?,?,?,?,NULL,?,?,?,?)",
            (tenant_id, seq, event_type, action_id, prev_digest, digest,
             body_json, now))
        self._bump(c, metric_worker, "credential_append")
        log.info(
            "evidence_append tenant=%s seq=%s action=%s event=%s digest=%s "
            "prev_digest=%s anchor_id=%s",
            tenant_id, seq, action_id, event_type, digest[:16],
            prev_digest[:16], "-")
        return c.execute(
            "SELECT * FROM evidence_entries WHERE tenant_id=? AND seq=?",
            (tenant_id, seq)).fetchone()

    def _finish_anchor_entry(self, c, entry, generation: dict,
                             prev_anchor_id: str | None) -> str:
        c.execute("UPDATE evidence_entries SET anchor_id=? WHERE tenant_id=? AND seq=?",
                  (entry["action_id"], entry["tenant_id"], entry["seq"]))
        statement = {
            "version": 1, "domain": DOMAIN_ANCHOR,
            "tenant_id": entry["tenant_id"], "anchor_id": entry["action_id"],
            "seq": entry["seq"], "head_digest": entry["digest"],
            "generation": generation["generation"],
            "prev_anchor_id": prev_anchor_id, "created_at": entry["created_at"]}
        signed_json = self.canonical_json(statement).decode("ascii")
        signature = anchor_crypto.sign(
            self._read_seed(generation["generation"]),
            signed_json.encode("utf-8")).hex()
        c.execute(
            "INSERT INTO evidence_anchors(tenant_id,anchor_id,seq,generation,"
            "prev_anchor_id,digest,signature,signed_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (entry["tenant_id"], entry["action_id"], entry["seq"],
             generation["generation"], prev_anchor_id, entry["digest"],
             signature, signed_json, entry["created_at"]))
        self._bump(c, "store", "anchor_seal")
        log.info("anchor_sealed tenant=%s seq=%s action=%s anchor_id=%s "
                 "generation=%s digest=%s prev_digest=%s",
                 entry["tenant_id"], entry["seq"], entry["action_id"],
                 entry["action_id"], generation["generation"],
                 entry["digest"], entry["prev_digest"])
        return signature

    def _seal_anchor_tx(self, c, now, tenant_id: str, reason: str = "periodic",
                        export_id: str | None = None, force: bool = True) -> dict | None:
        latest = c.execute(
            "SELECT * FROM evidence_entries WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
            (tenant_id,)).fetchone()
        if latest is None:
            return None
        prev = c.execute(
            "SELECT anchor_id FROM evidence_anchors WHERE tenant_id=? "
            "ORDER BY seq DESC LIMIT 1", (tenant_id,)).fetchone()
        prev_id = prev["anchor_id"] if prev else None
        if not force and latest["anchor_id"] is not None:
            return {"anchor_id": latest["anchor_id"], "seq": latest["seq"],
                    "digest": latest["digest"], "reused": True}
        gen = self.current_sealing_generation(c)
        action_id = "anc_" + secrets.token_hex(12)
        attrs = {"reason": reason, "export_id": export_id,
                 "generation": gen["generation"], "prev_anchor_id": prev_id}
        entry = self._append_evidence(
            c, now, tenant_id, "anchor_sealed", action_id, attrs)
        self._finish_anchor_entry(c, entry, gen, prev_id)
        if self.crash_after_commit == "anchor_seal_commit":
            self._pending_crash = "anchor_seal_commit"
        return {"anchor_id": action_id, "seq": entry["seq"],
                "digest": entry["digest"], "generation": gen["generation"]}

    def seal_anchor(self, tenant_id: str, reason: str = "periodic",
                    export_id: str | None = None, force: bool = True) -> dict | None:
        def tx(c, now):
            return self._seal_anchor_tx(c, now, tenant_id, reason, export_id, force)
        return self._write(tx)

    def rotate_sealing_key(self) -> dict:
        def tx(c, now):
            old = self.current_sealing_generation(c)
            seed, pub = anchor_crypto.generate_key()
            self._write_seed_durable(old["generation"] + 1, seed)
            c.execute("UPDATE sealing_keys SET retired_at=? WHERE generation=?",
                      (now, old["generation"]))
            c.execute(
                "INSERT INTO sealing_keys(generation,public_key,started_at) "
                "VALUES(?,?,?)", (old["generation"] + 1, pub.hex(), now))
            boundaries = []
            old_seed = self._read_seed(old["generation"])
            for t in c.execute(
                    "SELECT DISTINCT tenant_id FROM evidence_entries ORDER BY tenant_id"):
                tid = t["tenant_id"]
                action_id = "rot_" + secrets.token_hex(12)
                entry = self._append_evidence(
                    c, now, tid, "sealing_key_rotated", action_id,
                    {"from_generation": old["generation"],
                     "to_generation": old["generation"] + 1,
                     "from_public_key": old["public_key"],
                     "to_public_key": pub.hex()})
                statement = {
                    "version": 1, "domain": DOMAIN_ROTATION,
                    "tenant_id": tid, "action_id": action_id,
                    "boundary_seq": entry["seq"], "boundary_digest": entry["digest"],
                    "from_generation": old["generation"],
                    "to_generation": old["generation"] + 1,
                    "from_public_key": old["public_key"],
                    "to_public_key": pub.hex(), "created_at": now}
                signed_json = self.canonical_json(statement).decode("ascii")
                signature = anchor_crypto.sign(
                    old_seed, signed_json.encode("utf-8")).hex()
                c.execute(
                    "INSERT INTO sealing_rotations(tenant_id,from_generation,"
                    "to_generation,seq,action_id,signed_json,signature,created_at)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (tid, old["generation"], old["generation"] + 1,
                     entry["seq"], action_id, signed_json, signature, now))
                sealed = self._seal_anchor_tx(
                    c, now, tid, reason="sealing_key_rotation")
                boundaries.append({"tenant_id": tid, "seq": entry["seq"],
                                   "action_id": action_id,
                                   "anchor_id": sealed["anchor_id"] if sealed else None,
                                   "boundary_digest": entry["digest"]})
            return {"from_generation": old["generation"],
                    "to_generation": old["generation"] + 1,
                    "new_public_key": pub.hex(), "boundaries": boundaries}
        return self._write(tx)

    def _maybe_crash_after_commit(self) -> None:
        point = getattr(self, "_pending_crash", "")
        self._pending_crash = ""
        if point and self.crash_after_commit == point:
            log.error("fault injection: SIGKILL after committed %s", point)
            os._exit(137)

    # ---- 一致性导出：冻结截止序号，导出期间主账照常变化 --------------

    def create_export(self, tenant_id: str, start_seq: int = 1,
                      label: str | None = None) -> dict:
        """Atomically choose a cutoff, then package without blocking later writes."""
        export_id = "exp_" + secrets.token_hex(12)
        path = os.path.join(self.export_dir, f"{export_id}.whubpak")

        def freeze_tx(c, now):
            cutoff_row = c.execute(
                "SELECT COALESCE(MAX(seq),0) s FROM evidence_entries WHERE tenant_id=?",
                (tenant_id,)).fetchone()
            cutoff = cutoff_row["s"]
            if cutoff == 0 or start_seq < 1 or start_seq > cutoff:
                raise ValueError("invalid start_seq for empty or partial chain")
            gen = self.current_sealing_generation(c)
            c.execute(
                "INSERT INTO evidence_exports(id,tenant_id,start_seq,cutoff_seq,"
                "path,status,chunk_size,created_at,updated_at) "
                "VALUES(?,?,?,?,?, 'building',?,?,?)",
                (export_id, tenant_id, start_seq, cutoff, path,
                 evidence_pack.CHUNK_SIZE, now, now))
            self._bump(c, "exporter", "export_cutoff")
            return cutoff, gen["generation"]

        cutoff, generation = self._write(freeze_tx)
        try:
            # A separate read snapshot means pressure writes may continue after
            # the frozen cutoff; queries are bounded to <=cutoff, so newer rows
            # can never enter this artifact.
            with self._lock:
                rows = self.conn.execute(
                    "SELECT * FROM evidence_entries WHERE tenant_id=? "
                    "AND seq BETWEEN ? AND ? ORDER BY seq",
                    (tenant_id, start_seq, cutoff)).fetchall()
                anchors = self.conn.execute(
                    "SELECT * FROM evidence_anchors WHERE tenant_id=? AND seq<=? "
                    "ORDER BY seq", (tenant_id, cutoff)).fetchall()
                rotations = self.conn.execute(
                    "SELECT * FROM sealing_rotations WHERE tenant_id=? AND seq<=? "
                    "ORDER BY seq", (tenant_id, cutoff)).fetchall()
                keys = self.conn.execute(
                    "SELECT generation,public_key,started_at,retired_at "
                    "FROM sealing_keys WHERE generation<=? ORDER BY generation",
                    (generation,)).fetchall()
                proof_now = self.now()
                if start_seq > 1:
                    prev_row = self.conn.execute(
                        "SELECT digest FROM evidence_entries WHERE tenant_id=? AND seq=?",
                        (tenant_id, start_seq - 1)).fetchone()
                    start_prev_digest = prev_row["digest"] if prev_row else None
                else:
                    start_prev_digest = "GENESIS"
            entries = [{"seq": r["seq"], "digest": r["digest"],
                        "prev_digest": r["prev_digest"],
                        "body": json.loads(r["body_json"])} for r in rows]
            anchor_json = [{"anchor_id": r["anchor_id"], "seq": r["seq"],
                            "generation": r["generation"],
                            "prev_anchor_id": r["prev_anchor_id"],
                            "head_digest": r["digest"],
                            "signature": r["signature"],
                            "signed": json.loads(r["signed_json"])}
                           for r in anchors]
            rotation_json = [dict(json.loads(r["signed_json"]),
                                  signature=r["signature"]) for r in rotations]
            key_json = [dict(r) for r in keys]
            files_raw = {
                "entries.json": evidence_pack.canonical(entries),
                "anchors.json": evidence_pack.canonical(anchor_json),
                "rotations.json": evidence_pack.canonical(rotation_json),
                "keys.json": evidence_pack.canonical(key_json)}
            manifest = {"version": 1, "format": evidence_pack.MAGIC.decode(),
                        "tenant_id": tenant_id, "export_id": export_id,
                        "label": label, "start_seq": start_seq,
                        "cutoff_seq": cutoff,
                        "chunk_size": evidence_pack.CHUNK_SIZE,
                        "files": []}
            for name, raw in files_raw.items():
                chunks = evidence_pack.chunk_hashes(raw)
                for ch in chunks:
                    ch["first_seq"] = start_seq if name == "entries.json" else None
                manifest["files"].append(
                    {"name": name, "length": len(raw),
                     "first_seq": start_seq if name == "entries.json" and chunks else None,
                     "chunks": chunks,
                     "sha256": hashlib.sha256(raw).hexdigest()})
            manifest_raw = evidence_pack.canonical(manifest)
            head_digest = entries[-1]["digest"]
            last_anchor_id = anchor_json[-1]["anchor_id"] if anchor_json else None
            proof_body = {"version": 1, "domain": DOMAIN_EXPORT,
                          "export_id": export_id, "tenant_id": tenant_id,
                          "start_seq": start_seq, "cutoff_seq": cutoff,
                          "start_prev_digest": start_prev_digest,
                          "head_digest": head_digest,
                          "last_anchor_id": last_anchor_id,
                          "manifest_digest": hashlib.sha256(manifest_raw).hexdigest(),
                          "generation": generation, "created_at": proof_now}
            signature = anchor_crypto.sign(
                self._read_seed(generation),
                evidence_pack.canonical(proof_body)).hex()
            files_raw["manifest.json"] = manifest_raw
            files_raw["proof.json"] = evidence_pack.canonical(
                {"signed": proof_body, "signature": signature})
            evidence_pack.write_pack(path, files_raw)

            def ready_tx(c, now):
                c.execute(
                    "UPDATE evidence_exports SET status='ready',completed_at=?,"
                    "updated_at=? WHERE id=?", (now, now, export_id))
            self._write(ready_tx)
            return {"export_id": export_id, "path": path,
                    "start_seq": start_seq, "cutoff_seq": cutoff,
                    "anchor_id": last_anchor_id,
                    "entry_count": len(entries)}
        except Exception:
            def fail_tx(c, now):
                c.execute(
                    "UPDATE evidence_exports SET status='failed',updated_at=? "
                    "WHERE id=?", (now, export_id))
            try:
                self._write(fail_tx)
            except Exception:
                pass
            raise

    def list_exports(self, tenant_id: str | None = None) -> list[dict]:
        with self._lock:
            if tenant_id:
                rows = self.conn.execute(
                    "SELECT * FROM evidence_exports WHERE tenant_id=? ORDER BY created_at",
                    (tenant_id,)).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM evidence_exports ORDER BY created_at").fetchall()
            return [dict(r) for r in rows]

    def evidence_head(self, tenant_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM evidence_entries WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
                (tenant_id,)).fetchone()
            return dict(row) if row else None

    def evidence_verify_local(self) -> list[dict]:
        out = []
        with self._lock:
            tenants = [r[0] for r in self.conn.execute(
                "SELECT DISTINCT tenant_id FROM evidence_entries")]
        for tid in tenants:
            prev = "GENESIS"
            expected = 1
            first_bad = None
            rows = self.list_evidence(tid)
            for row in rows:
                body = json.loads(row["body_json"])
                calc = self._domain_digest(DOMAIN_ENTRY, body)
                if row["seq"] != expected or row["prev_digest"] != prev or \
                        calc != row["digest"]:
                    first_bad = expected

                    def count_tx(c, now):
                        self._bump(c, "verifier", "tamper_detected")
                    self._write(count_tx)
                    break
                prev = row["digest"]
                expected += 1
            out.append({"tenant_id": tid, "entries": len(rows),
                        "head_digest": rows[-1]["digest"] if rows else None,
                        "head_seq": rows[-1]["seq"] if rows else 0,
                        "ok": first_bad is None, "first_bad_seq": first_bad})
        return out

    def list_evidence(self, tenant_id: str, start: int | None = None,
                      end: int | None = None) -> list[dict]:
        q = "SELECT * FROM evidence_entries WHERE tenant_id=?"
        args: list[Any] = [tenant_id]
        if start is not None:
            q += " AND seq>=?"; args.append(start)
        if end is not None:
            q += " AND seq<=?"; args.append(end)
        q += " ORDER BY seq"
        with self._lock:
            return [dict(r) for r in self.conn.execute(q, args)]

    # ---- 留存期限、司法留置与隐私清除 ------------------------------

    def set_retention(self, tenant_id: str, retain_until_after: float) -> dict:
        def tx(c, now):
            c.execute(
                "INSERT INTO retention_policies(tenant_id,retain_until_after,updated_at)"
                " VALUES(?,?,?) ON CONFLICT(tenant_id) DO UPDATE SET "
                "retain_until_after=excluded.retain_until_after,updated_at=excluded.updated_at",
                (tenant_id, retain_until_after, now))
            return {"tenant_id": tenant_id, "retain_until_after": retain_until_after}
        return self._write(tx)

    def add_legal_hold(self, tenant_id: str, reason: str) -> dict:
        def tx(c, now):
            hold_id = "hold_" + secrets.token_hex(12)
            c.execute(
                "INSERT INTO legal_holds(id,tenant_id,reason,active,created_at)"
                " VALUES(?,?,?,1,?)", (hold_id, tenant_id, reason, now))
            return {"hold_id": hold_id, "tenant_id": tenant_id,
                    "reason": reason, "active": True}
        return self._write(tx)

    def release_legal_hold(self, hold_id: str) -> bool:
        def tx(c, now):
            cur = c.execute(
                "UPDATE legal_holds SET active=0,released_at=? WHERE id=? AND active=1",
                (now, hold_id))
            return cur.rowcount > 0
        return self._write(tx)

    def legal_holds(self, tenant_id: str | None = None) -> list[dict]:
        q = "SELECT * FROM legal_holds"
        args: list[Any] = []
        if tenant_id:
            q += " WHERE tenant_id=?"; args.append(tenant_id)
        with self._lock:
            return [dict(r) for r in self.conn.execute(q + " ORDER BY created_at",
                                                        args)]

    def run_privacy_sweep(self, now: float | None = None) -> list[dict]:
        """清除逾期且未被留置的可识别正文；链与计数保持可验。"""
        if now is None:
            now = time.time()

        def tx(c, ts):
            results = []
            policies = c.execute("SELECT * FROM retention_policies").fetchall()
            for p in policies:
                if p["retain_until_after"] > now:
                    continue
                active_holds = c.execute(
                    "SELECT COUNT(*) n FROM legal_holds WHERE tenant_id=? AND active=1",
                    (p["tenant_id"],)).fetchone()["n"]
                batch_id = "red_" + secrets.token_hex(12)
                if active_holds:
                    c.execute(
                        "INSERT INTO privacy_batches(id,tenant_id,status,note,"
                        "created_at,updated_at) VALUES(?,?, 'blocked',?,?,?)",
                        (batch_id, p["tenant_id"], "legal_hold_active", ts, ts))
                    results.append({"tenant_id": p["tenant_id"],
                                    "status": "blocked_legal_hold",
                                    "batch_id": batch_id,
                                    "events_redacted": 0,
                                    "attachments_redacted": 0})
                    continue
                events = c.execute(
                    "SELECT id, payload FROM events WHERE tenant_id=? AND payload<>''",
                    (p["tenant_id"],)).fetchall()
                count = 0
                for ev in events:
                    c.execute(
                        "UPDATE events SET payload='[REDACTED]' WHERE id=?",
                        (ev["id"],))
                    count += 1
                entry = self._append_evidence(
                    c, ts, p["tenant_id"], "privacy_erased",
                    "prv_" + secrets.token_hex(12),
                    {"batch_id": batch_id, "events_redacted": count,
                     "attachments_redacted": 0,
                     "retention_deadline": p["retain_until_after"]},
                    metric_worker="privacy")
                c.execute(
                    "INSERT INTO privacy_batches(id,tenant_id,status,"
                    "events_redacted,attachments_redacted,evidence_seq,"
                    "created_at,updated_at) VALUES(?,?, 'complete',?,?,?,?,?)",
                    (batch_id, p["tenant_id"], count, 0, entry["seq"], ts, ts))
                self._bump(c, "privacy", "privacy_erase", count)
                results.append({"tenant_id": p["tenant_id"], "status": "complete",
                                "batch_id": batch_id, "events_redacted": count,
                                "attachments_redacted": 0,
                                "evidence_seq": entry["seq"]})
            return results
        return self._write(tx)

    def privacy_batches(self, tenant_id: str | None = None) -> list[dict]:
        q = "SELECT * FROM privacy_batches"
        args: list[Any] = []
        if tenant_id:
            q += " WHERE tenant_id=?"; args.append(tenant_id)
        with self._lock:
            return [dict(r) for r in self.conn.execute(
                q + " ORDER BY created_at", args)]


    def create_tenant(self, tid: str, name: str, api_key: str) -> None:
        self._write(lambda c, now: c.execute(
            "INSERT INTO tenants(id,name,api_key,created_at) VALUES(?,?,?,?)",
            (tid, name, api_key, now)))

    def tenant_by_key(self, api_key: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM tenants WHERE api_key=?", (api_key,)).fetchone()

    def tenant(self, tid: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM tenants WHERE id=?", (tid,)).fetchone()

    def create_endpoint(self, eid: str, tenant_id: str, name: str,
                        version: int, kid: str, secret: str, url: str,
                        parallelism: int) -> None:
        def tx(c, now):
            c.execute(
                "INSERT INTO endpoints(id,tenant_id,name,active_version,"
                "parallelism,created_at) VALUES(?,?,?,?,?,?)",
                (eid, tenant_id, name, version, parallelism, now))
            c.execute(
                "INSERT INTO endpoint_versions(endpoint_id,version,kid,secret,"
                "url,status,created_at) VALUES(?,?,?,?,?,'active',?)",
                (eid, version, kid, secret, url, now))
        self._write(tx)

    def endpoint(self, eid: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM endpoints WHERE id=?", (eid,)).fetchone()

    def endpoints_for_tenant(self, tenant_id: str) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(
                "SELECT * FROM endpoints WHERE tenant_id=? ORDER BY created_at",
                (tenant_id,)))

    def active_endpoint_ids(self) -> list[str]:
        with self._lock:
            return [r["id"] for r in self.conn.execute(
                "SELECT id FROM endpoints WHERE disabled=0")]

    def set_parallelism(self, eid: str, n: int) -> None:
        self._write(lambda c, now: c.execute(
            "UPDATE endpoints SET parallelism=? WHERE id=?", (n, eid)))

    def set_disabled(self, eid: str, disabled: bool) -> None:
        self._write(lambda c, now: c.execute(
            "UPDATE endpoints SET disabled=? WHERE id=?",
            (1 if disabled else 0, eid)))

    def version(self, eid: str, version: int) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM endpoint_versions WHERE endpoint_id=? AND version=?",
                (eid, version)).fetchone()

    def versions(self, eid: str) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(
                "SELECT * FROM endpoint_versions WHERE endpoint_id=? "
                "ORDER BY version", (eid,)))

    def rotate_key(self, eid: str, url: str, secret: Optional[str] = None,
                   kid: Optional[str] = None) -> sqlite3.Row:
        def tx(c, now):
            row = c.execute("SELECT * FROM endpoints WHERE id=?", (eid,)).fetchone()
            if row is None:
                raise KeyError("endpoint not found")
            nv = row["active_version"] + 1
            new_secret = secret or ("whsec_" + secrets.token_hex(24))
            new_kid = kid or f"key-{nv:x}"
            c.execute(
                "INSERT INTO endpoint_versions(endpoint_id,version,kid,secret,url,"
                "status,created_at) VALUES(?,?,?,?,?,'active',?)",
                (eid, nv, new_kid, new_secret, url, now))
            c.execute("UPDATE endpoints SET active_version=? WHERE id=?",
                      (nv, eid))
            return c.execute(
                "SELECT * FROM endpoint_versions WHERE endpoint_id=? AND version=?",
                (eid, nv)).fetchone()
        return self._write(tx)

    def retire_version(self, eid: str, version: int) -> dict:
        def tx(c, now):
            v = c.execute(
                "SELECT * FROM endpoint_versions WHERE endpoint_id=? AND version=?",
                (eid, version)).fetchone()
            if v is None:
                raise KeyError("version not found")
            n = c.execute(
                "SELECT COUNT(*) n FROM jobs WHERE endpoint_id=? AND sig_version=? "
                "AND status IN ('pending','leased')", (eid, version)).fetchone()["n"]
            if n:
                return {"retired": False, "inflight": n}
            c.execute(
                "UPDATE endpoint_versions SET status='retired', retired_at=? "
                "WHERE endpoint_id=? AND version=?", (now, eid, version))
            return {"retired": True, "inflight": 0}
        return self._write(tx)

    # ---- 事件入队（建 lane + 不可变快照 job + 序号分配，单事务） ------

    def find_event(self, tenant_id: str, idem_key: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM events WHERE tenant_id=? AND idempotency_key=?",
                (tenant_id, idem_key)).fetchone()

    def event(self, event_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT * FROM events WHERE id=?", (event_id,)).fetchone()

    def enqueue(self, *, lane_id: str, event_id: str, tenant_id: str,
                eid: str, idem_key: Optional[str], object_key: str,
                payload: str, job_id: str) -> sqlite3.Row:
        def tx(c, now):
            ep = c.execute("SELECT * FROM endpoints WHERE id=?", (eid,)).fetchone()
            if ep is None:
                raise KeyError("endpoint not found")
            if ep["disabled"]:
                raise RuntimeError("endpoint disabled")
            v = c.execute(
                "SELECT * FROM endpoint_versions WHERE endpoint_id=? AND version=?",
                (eid, ep["active_version"])).fetchone()
            c.execute(
                "INSERT INTO events(id,tenant_id,endpoint_id,idempotency_key,"
                "object_key,payload,created_at) VALUES(?,?,?,?,?,?,?)",
                (event_id, tenant_id, eid, idem_key, object_key, payload, now))
            # 建 lane（不获取所有权；入队与 worker 仲裁彻底解耦）
            c.execute(
                "INSERT INTO lanes(lane_id,endpoint_id,object_key,created_at,"
                "updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(endpoint_id,object_key) DO UPDATE SET updated_at=?",
                (lane_id, eid, object_key, now, now, now))
            lane = c.execute("SELECT * FROM lanes WHERE lane_id=?",
                             (lane_id,)).fetchone()
            seq = lane["last_seq"] + 1
            c.execute(
                "UPDATE lanes SET last_seq=?, updated_at=? WHERE lane_id=?",
                (seq, now, lane_id))
            c.execute(
                "INSERT INTO jobs(id,endpoint_id,lane_id,event_id,seq,"
                "sig_version,target_url,kid,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (job_id, eid, lane_id, event_id, seq, v["version"], v["url"],
                 v["kid"], now, now))
            payload_digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            self._append_evidence(
                c, now, tenant_id, "message_enqueued", "msg_" + event_id,
                {"event_id": event_id, "delivery_id": job_id,
                 "endpoint_id": eid, "lane_id": lane_id, "object_key": object_key,
                 "idempotency_key": idem_key, "delivery_seq": seq,
                 "sig_version": v["version"], "payload_digest": payload_digest,
                 "payload_bytes": len(payload.encode("utf-8"))},
                metric_worker="api")
            # lane 行上的水位快照始终跟踪“队头 job”：此前没有未完成 job 时，
            # 新快照就是队头；否则保持旧队头快照，直到队头结算后刷新。
            unfinished = c.execute(
                "SELECT COUNT(*) n FROM jobs WHERE lane_id=? AND seq<? "
                "AND status NOT IN ('succeeded','canceled')",
                (lane_id, seq)).fetchone()["n"]
            if not unfinished:
                c.execute(
                    "UPDATE lanes SET target_url=?, sig_version=?, kid=?, "
                    "updated_at=? WHERE lane_id=?",
                    (v["url"], v["version"], v["kid"], now, lane_id))
            return c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return self._write(tx)

    def _refresh_lane_head(self, c, lane_id: str, now: float) -> None:
        """队头结算后，把 lane 的水位/快照同步到新队头。"""
        head = c.execute(
            "SELECT * FROM jobs WHERE lane_id=? AND status NOT IN "
            "('succeeded','canceled') ORDER BY seq LIMIT 1",
            (lane_id,)).fetchone()
        if head is None:
            c.execute(
                "UPDATE lanes SET not_before=0,target_url=NULL,sig_version=NULL,"
                "kid=NULL,updated_at=? WHERE lane_id=?", (now, lane_id))
        else:
            c.execute(
                "UPDATE lanes SET not_before=MAX(0,?), target_url=?, sig_version=?,"
                "kid=?, updated_at=? WHERE lane_id=?",
                (head["not_before"], head["target_url"], head["sig_version"],
                 head["kid"], now, lane_id))

    # ---- worker 成员与心跳 -------------------------------------------

    def register_worker(self, worker_id: str, host: str = "",
                        port: int = 0) -> dict:
        def tx(c, now):
            old = c.execute("SELECT * FROM workers WHERE worker_id=?",
                            (worker_id,)).fetchone()
            incarnation = new_fence()
            c.execute(
                "INSERT INTO workers(worker_id,incarnation,host,port,draining,"
                "last_heartbeat,registered_at) VALUES(?,?,?,?,0,?,?) "
                "ON CONFLICT(worker_id) DO UPDATE SET incarnation=excluded.incarnation,"
                "host=excluded.host,port=excluded.port,draining=0,drain_until=NULL,"
                "last_heartbeat=excluded.last_heartbeat",
                (worker_id, incarnation, host, port, now, now))
            restarted = []
            if old is not None and old["incarnation"] != incarnation:
                # 同 worker_id 的新进程：旧进程的 fence 已随其死亡失效。
                # 其名下 lane 立即交还公共池（jobs 退回 pending），
                # 由在场成员下一轮 sweep 作为 orphan 回收，不必等 TTL。
                for lane in c.execute(
                        "SELECT * FROM lanes WHERE owner_id=?",
                        (worker_id,)).fetchall():
                    self._release_lane(c, now, lane, reason="worker_restart")
                    restarted.append(lane["lane_id"])
                self._bump(c, worker_id, "orphan_recovered", len(restarted))
            return {"worker_id": worker_id, "incarnation": incarnation,
                    "registered_at": now, "restarted_lanes": restarted}
        return self._write(tx)

    def heartbeat(self, worker_id: str, incarnation: str) -> dict:
        def tx(c, now):
            row = c.execute("SELECT * FROM workers WHERE worker_id=?",
                            (worker_id,)).fetchone()
            if row is None or row["incarnation"] != incarnation:
                raise LeaseNotOwned("unknown or superseded worker incarnation")
            c.execute("UPDATE workers SET last_heartbeat=? WHERE worker_id=?",
                      (now, worker_id))
            return {"worker_id": worker_id, "now": now,
                    "draining": bool(row["draining"]),
                    "drain_until": row["drain_until"]}
        return self._write(tx)

    def deregister_worker(self, worker_id: str, incarnation: str,
                          ttl: float = 30.0) -> dict:
        """优雅退出：成员下线，其 lane 立即 handoff（epoch+1）或交还公共池。"""
        def tx(c, now):
            row = c.execute("SELECT * FROM workers WHERE worker_id=?",
                            (worker_id,)).fetchone()
            if row is None or row["incarnation"] != incarnation:
                raise LeaseNotOwned("unknown or superseded worker incarnation")
            moved = self._handoff_away(c, now, worker_id, "worker_shutdown",
                                       release_ok=True, ttl=ttl)
            c.execute("DELETE FROM workers WHERE worker_id=?", (worker_id,))
            return {"worker_id": worker_id, "moved": moved}
        return self._write(tx)

    def set_drain(self, worker_id: str, draining: bool,
                  deadline: Optional[float] = None) -> dict:
        def tx(c, now):
            row = c.execute("SELECT * FROM workers WHERE worker_id=?",
                            (worker_id,)).fetchone()
            if row is None:
                raise LeaseNotOwned("worker not found")
            until = (now + deadline) if (draining and deadline) else None
            c.execute("UPDATE workers SET draining=?, drain_until=? WHERE worker_id=?",
                      (1 if draining else 0, until, worker_id))
            c.execute("UPDATE lanes SET draining=? WHERE owner_id=?",
                      (1 if draining else 0, worker_id))
            return {"worker_id": worker_id, "draining": draining,
                    "drain_until": until, "now": now}
        return self._write(tx)

    # ---- lease：acquire / renew / touch / handoff --------------------

    def _log_ownership(self, c, now, lane: sqlite3.Row, new_owner,
                       new_epoch: int, reason: str) -> None:
        c.execute(
            "INSERT INTO ownership_log(at,lane_id,endpoint_id,object_key,"
            "old_owner,new_owner,old_epoch,new_epoch,reason) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (now, lane["lane_id"], lane["endpoint_id"], lane["object_key"],
             lane["owner_id"], new_owner, lane["lease_epoch"], new_epoch, reason))
        # 单条结构化日志即可还原因果链：lane/old/new/old_epoch/new_epoch/reason
        log.info(
            "ownership_change lane=%s endpoint=%s object=%s old_owner=%s "
            "new_owner=%s old_epoch=%s new_epoch=%s reason=%s",
            lane["lane_id"], lane["endpoint_id"], lane["object_key"],
            lane["owner_id"], new_owner, lane["lease_epoch"], new_epoch, reason)

    def _take_ownership(self, c, now, lane_id, new_owner, ttl, reason,
                        old_epoch: Optional[int] = None) -> bool:
        """fenced owner 变更：epoch+1、换 fence、连带把在途 job 退回 pending。

        调用方必须已通过 WHERE 选出可拿的 lane；这里再次以旧 epoch 做 CAS，
        与并发 sweep 竞争时只有一个事务能赢。"""
        lane = c.execute("SELECT * FROM lanes WHERE lane_id=?",
                         (lane_id,)).fetchone()
        if lane is None or lane["owner_id"] == new_owner:
            return False
        if old_epoch is not None and lane["lease_epoch"] != old_epoch:
            return False
        new_epoch = lane["lease_epoch"] + 1
        fence = new_fence()
        cur = c.execute(
            "UPDATE lanes SET owner_id=?, lease_epoch=?, fence_id=?, "
            "expires_at=?, draining=0, last_handoff_reason=?, updated_at=? "
            "WHERE lane_id=? AND lease_epoch=?",
            (new_owner, new_epoch, fence, now + ttl, reason, now,
             lane_id, lane["lease_epoch"]))
        if cur.rowcount == 0:
            return False
        # 旧 owner 在途的 job 全部退回公共池；旧 owner 之后的 complete 必陈旧
        c.execute(
            "UPDATE jobs SET status='pending', leased_by=NULL, lease_epoch=NULL,"
            " fence_id=NULL, leased_until=NULL, updated_at=? "
            "WHERE lane_id=? AND status='leased'", (now, lane_id))
        ep = c.execute("SELECT tenant_id FROM endpoints WHERE id=?",
                       (lane["endpoint_id"],)).fetchone()
        if ep is None:
            raise LeaseNotOwned("endpoint missing for lane")
        tenant_id = ep["tenant_id"]
        handoff_action = "own_" + secrets.token_hex(12)
        self._append_evidence(
            c, now, tenant_id, "ownership_handover", handoff_action,
            {"lane_id": lane_id, "endpoint_id": lane["endpoint_id"],
             "object_key": lane["object_key"], "old_owner": lane["owner_id"],
             "new_owner": new_owner, "old_epoch": lane["lease_epoch"],
             "new_epoch": new_epoch, "reason": reason})
        self._log_ownership(c, now, lane, new_owner, new_epoch, reason)
        return True

    def _release_lane(self, c, now, lane: sqlite3.Row,
                      reason: str = "release") -> None:
        """交还公共池（owner=NULL）；epoch 保留，下一次 acquire 仍会 +1。"""
        c.execute(
            "UPDATE lanes SET owner_id=NULL, fence_id=NULL, expires_at=NULL,"
            "draining=0, last_handoff_reason=?, updated_at=? "
            "WHERE lane_id=?", (reason, now, lane["lane_id"]))
        ep = c.execute("SELECT tenant_id FROM endpoints WHERE id=?",
                       (lane["endpoint_id"],)).fetchone()
        if ep is None:
            raise LeaseNotOwned("endpoint missing for lane")
        tenant_id = ep["tenant_id"]
        action_id = "own_" + secrets.token_hex(12)
        self._append_evidence(
            c, now, tenant_id, "ownership_handover", action_id,
            {"lane_id": lane["lane_id"], "endpoint_id": lane["endpoint_id"],
             "object_key": lane["object_key"], "old_owner": lane["owner_id"],
             "new_owner": None, "old_epoch": lane["lease_epoch"],
             "new_epoch": lane["lease_epoch"], "reason": reason})
        self._log_ownership(c, now, lane, None, lane["lease_epoch"], reason)
        c.execute(
            "UPDATE jobs SET status='pending', leased_by=NULL, lease_epoch=NULL,"
            "fence_id=NULL, leased_until=NULL, updated_at=? "
            "WHERE lane_id=? AND status='leased'", (now, lane["lane_id"]))

    def renew(self, lane_id: str, worker_id: str, epoch: int, fence: str,
              incarnation: str, ttl: float) -> dict:
        """renew 只能延长 owner+epoch+fence 全匹配且尚未过期的行。"""
        def tx(c, now):
            w = c.execute("SELECT * FROM workers WHERE worker_id=?",
                          (worker_id,)).fetchone()
            if w is None or w["incarnation"] != incarnation:
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch("worker incarnation superseded")
            row = c.execute("SELECT * FROM lanes WHERE lane_id=?",
                            (lane_id,)).fetchone()
            if row is None:
                self._bump(c, worker_id, "stale_write_rejected")
                raise LeaseNotOwned("lane vanished")
            cur = c.execute(
                "UPDATE lanes SET expires_at=?, updated_at=? "
                "WHERE lane_id=? AND owner_id=? AND lease_epoch=? AND fence_id=? "
                "AND expires_at>?",
                (now + ttl, now, lane_id, worker_id, epoch, fence, now))
            if cur.rowcount == 0:
                # 旧 fence、旧 epoch 或已过期：暂停过久的 worker 一律被拒
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch(
                    "renew rejected", owner=row["owner_id"],
                    epoch=row["lease_epoch"], expires_at=row["expires_at"],
                    now=now)
            self._bump(c, worker_id, "renew")
            return {"lane_id": lane_id, "owner_id": worker_id,
                    "lease_epoch": epoch, "expires_at": now + ttl}
        return self._write(tx)

    def touch(self, lane_id: str, worker_id: str, epoch: int, fence: str,
              ttl: float) -> dict:
        """发送前的 fence 探针：必须过写闸门 + fence 校验，二者皆否则禁止出站。"""
        def tx(c, now):
            cur = c.execute(
                "UPDATE lanes SET expires_at=MAX(expires_at,?), updated_at=? "
                "WHERE lane_id=? AND owner_id=? AND lease_epoch=? AND fence_id=? "
                "AND expires_at>?",
                (now + ttl, now, lane_id, worker_id, epoch, fence, now))
            if cur.rowcount == 0:
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch("touch rejected")
            return {"ok": True, "now": now, "expires_at": now + ttl}
        return self._write(tx)

    def release(self, lane_id: str, worker_id: str, epoch: int,
                fence: str) -> dict:
        def tx(c, now):
            lane = c.execute("SELECT * FROM lanes WHERE lane_id=?",
                             (lane_id,)).fetchone()
            cur = c.execute(
                "UPDATE lanes SET owner_id=NULL, fence_id=NULL, expires_at=NULL,"
                "draining=0, last_handoff_reason='release', updated_at=? "
                "WHERE lane_id=? AND owner_id=? AND lease_epoch=? AND fence_id=?",
                (now, lane_id, worker_id, epoch, fence))
            if cur.rowcount == 0:
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch("release rejected")
            if lane is not None:
                self._log_ownership(c, now, lane, None, epoch, "release")
                c.execute(
                    "UPDATE jobs SET status='pending', leased_by=NULL,"
                    "lease_epoch=NULL,fence_id=NULL,leased_until=NULL,updated_at=? "
                    "WHERE lane_id=? AND status='leased'", (now, lane_id))
            return {"released": True}
        return self._write(tx)

    # ---- sweep：acquire 公共池 / steal 过期 / drain 空闲 handoff ------

    def _active_workers(self, c, now):
        return {r["worker_id"]: r for r in c.execute(
            "SELECT * FROM workers")}

    def sweep(self, worker_id: str, incarnation: str, ttl: float,
              acquire_budget: int) -> dict:
        """单轮扫描。fence 让多个进程同时 sweep 也安全：每条 lane 只有一个赢家。"""
        def tx(c, now):
            w = c.execute("SELECT * FROM workers WHERE worker_id=?",
                          (worker_id,)).fetchone()
            if w is None or w["incarnation"] != incarnation:
                raise LeaseNotOwned("worker not registered")
            acquired: list[str] = []
            stolen: list[dict] = []
            handed: list[dict] = []

            if not w["draining"]:
                # 1) 公共池里的无主 lane（含尚未被任何人 acquire 的新 lane）
                rows = c.execute(
                    "SELECT lane_id FROM lanes WHERE owner_id IS NULL "
                    "ORDER BY updated_at, lane_id LIMIT ?",
                    (acquire_budget,)).fetchall()
                for r in rows:
                    if self._take_ownership(c, now, r["lane_id"], worker_id,
                                            ttl, "acquire"):
                        acquired.append(r["lane_id"])
                        self._bump(c, worker_id, "acquire")

                # 2) 过期可 steal：租约到期（STW/crash）；或 owner 成员已不存在
                #    （显式 deregister 之外消失，即 orphan）。
                rows = c.execute(
                    "SELECT l.lane_id, l.owner_id, l.lease_epoch, l.expires_at "
                    "FROM lanes l LEFT JOIN workers w ON w.worker_id=l.owner_id "
                    "WHERE l.owner_id IS NOT NULL AND l.owner_id<>? "
                    "AND (l.expires_at<? OR w.worker_id IS NULL) "
                    "ORDER BY l.expires_at LIMIT ?",
                    (worker_id, now, acquire_budget)).fetchall()
                for r in rows:
                    owner = c.execute("SELECT * FROM workers WHERE worker_id=?",
                                      (r["owner_id"],)).fetchone()
                    if owner is None:
                        reason, metric = "orphan_recovered", "orphan_recovered"
                    elif owner["draining"]:
                        reason, metric = "drain_handoff", "drain_handoff"
                    else:
                        reason, metric = "expiry_steal", "steal"
                    if self._take_ownership(c, now, r["lane_id"], worker_id,
                                            ttl, reason, r["lease_epoch"]):
                        stolen.append({"lane_id": r["lane_id"], "reason": reason})
                        self._bump(c, worker_id, metric)

            # 3) drain 中的 lane：无在途 job 即可提前交给最闲的健康成员
            rows = c.execute(
                "SELECT l.lane_id, l.owner_id, l.lease_epoch FROM lanes l "
                "JOIN workers w ON w.worker_id=l.owner_id "
                "WHERE w.draining=1 ORDER BY l.updated_at").fetchall()
            for r in rows:
                busy = c.execute(
                    "SELECT COUNT(*) n FROM jobs WHERE lane_id=? AND status='leased'",
                    (r["lane_id"],)).fetchone()["n"]
                if busy:
                    continue  # deadline 内允许手头工作继续收尾
                if r["owner_id"] == worker_id:
                    target = self._pick_target(c, now, exclude=worker_id)
                    if target is None:
                        lane = c.execute("SELECT * FROM lanes WHERE lane_id=?",
                                         (r["lane_id"],)).fetchone()
                        self._release_lane(c, now, lane)
                        handed.append({"lane_id": r["lane_id"], "to": None})
                    elif self._take_ownership(c, now, r["lane_id"], target, ttl,
                                              "drain_handoff", r["lease_epoch"]):
                        handed.append({"lane_id": r["lane_id"], "to": target})
                        self._bump(c, r["owner_id"], "drain_handoff")
                else:
                    target = self._pick_target(
                        c, now, exclude=r["owner_id"], prefer=worker_id)
                    if target == worker_id and self._take_ownership(
                            c, now, r["lane_id"], worker_id, ttl,
                            "drain_handoff", r["lease_epoch"]):
                        handed.append({"lane_id": r["lane_id"], "to": worker_id})
                        self._bump(c, r["owner_id"], "drain_handoff")
            return {"acquired": acquired, "stolen": stolen, "drain_handoffs": handed}
        return self._write(tx)

    def _pick_target(self, c, now, exclude: Optional[str] = None,
                     prefer: Optional[str] = None) -> Optional[str]:
        """最闲的、健康且不在 drain 的 worker；prefer 仅用于确认其仍合格。"""
        rows = c.execute(
            "SELECT w.worker_id, COUNT(l.lane_id) AS n FROM workers w "
            "LEFT JOIN lanes l ON l.owner_id=w.worker_id "
            "WHERE w.draining=0 AND w.worker_id IS NOT NULL "
            "GROUP BY w.worker_id ORDER BY n, w.worker_id").fetchall()
        cand = [r["worker_id"] for r in rows
                if r["worker_id"] != exclude and r["worker_id"] is not None]
        if prefer is not None and prefer in cand:
            return prefer
        return cand[0] if cand else None

    def _handoff_away(self, c, now, worker_id: str, reason: str,
                      release_ok: bool, ttl: float = 30.0) -> list[dict]:
        out = []
        rows = c.execute("SELECT * FROM lanes WHERE owner_id=?",
                         (worker_id,)).fetchall()
        for lane in rows:
            target = self._pick_target(c, now, exclude=worker_id)
            if target is not None:
                if self._take_ownership(c, now, lane["lane_id"], target, ttl,
                                        reason, lane["lease_epoch"]):
                    out.append({"lane_id": lane["lane_id"], "to": target})
            elif release_ok:
                self._release_lane(c, now, lane)
                out.append({"lane_id": lane["lane_id"], "to": None})
        return out

    # ---- rebalance（受 cap 约束的渐进搬运） ---------------------------

    def rebalance(self, budget: int, trigger: str = "api",
                  ttl: float = 30.0) -> dict:
        def tx(c, now):
            moved = []
            for _ in range(max(budget, 0)):
                rows = c.execute(
                    "SELECT w.worker_id, COUNT(l.lane_id) AS n FROM workers w "
                    "LEFT JOIN lanes l ON l.owner_id=w.worker_id "
                    "WHERE w.draining=0 GROUP BY w.worker_id "
                    "ORDER BY n DESC, w.worker_id").fetchall()
                if len(rows) < 2:
                    break
                hi_row, lo_row = rows[0], rows[-1]
                hi, lo = hi_row["worker_id"], lo_row["worker_id"]
                if hi_row["n"] - lo_row["n"] < 2:
                    break
                # 只搬空闲 lane：任何在途 leased job 的 lane 都不搬，
                # 避免把正在进行的 HTTP 发送搬到新 owner（fence 拒绝 + 延迟）。
                lane = c.execute(
                    "SELECT l.* FROM lanes l WHERE l.owner_id=? AND NOT EXISTS "
                    "(SELECT 1 FROM jobs j WHERE j.lane_id=l.lane_id "
                    "AND j.status='leased') ORDER BY l.updated_at LIMIT 1",
                    (hi,)).fetchone()
                if lane is None:
                    break
                if self._take_ownership(c, now, lane["lane_id"], lo, ttl,
                                        "rebalance", lane["lease_epoch"]):
                    moved.append({"lane_id": lane["lane_id"], "from": hi, "to": lo})
            return {"moved": moved, "budget": budget, "trigger": trigger}
        return self._write(tx)

    def rebalance_with_ttl(self, budget: int, ttl: float,
                           trigger: str = "join") -> dict:
        return self.rebalance(budget, trigger, ttl=ttl)

    def mark_dispatched(self, action_id: str, worker_id: str, epoch: int,
                        fence: str) -> dict:
        def tx(c, now):
            row = c.execute("SELECT * FROM delivery_intents WHERE action_id=?",
                            (action_id,)).fetchone()
            if row is None:
                raise LeaseNotOwned("attempt intent missing")
            if row["worker_id"] != worker_id or row["lease_epoch"] != epoch or \
                    row["fence_id"] != fence:
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch("dispatch marker with stale fence")
            if row["state"] == "prepared":
                c.execute(
                    "UPDATE delivery_intents SET state='dispatched', updated_at=? "
                    "WHERE action_id=?", (now, action_id))
            return {"action_id": action_id, "state": "dispatched"}
        return self._write(tx)

    def finish_attempt(self, *, action_id: str, worker_id: str, epoch: int,
                       fence: str, code: Optional[int], error: str,
                       error_kind: str, response_digest: str,
                       not_before: Optional[float] = None) -> dict:
        def tx(c, now):
            intent = c.execute("SELECT * FROM delivery_intents WHERE action_id=?",
                               (action_id,)).fetchone()
            if intent is None:
                raise LeaseNotOwned("attempt intent missing")
            if intent["worker_id"] != worker_id or intent["lease_epoch"] != epoch \
                    or intent["fence_id"] != fence:
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch("finish with stale fence")
            j = c.execute(
                "SELECT j.*, e.tenant_id FROM jobs j JOIN events e ON e.id=j.event_id "
                "WHERE j.id=?", (intent["job_id"],)).fetchone()
            if j is None:
                raise LeaseNotOwned("job missing")
            # 已恢复/已结算时保持幂等，绝不为一次动作再写第二个终态凭证。
            existing = c.execute(
                "SELECT seq FROM evidence_entries WHERE tenant_id=? AND action_id=? "
                "AND event_type='delivery_result'",
                (j["tenant_id"], action_id)).fetchone()
            if existing:
                return {"job_id": j["id"], "status": j["status"],
                        "action_id": action_id, "idempotent": True,
                        "evidence_seq": existing["seq"]}
            if code is not None:
                response_attrs = {
                    "delivery_id": j["id"], "event_id": j["event_id"],
                    "endpoint_id": j["endpoint_id"], "lane_id": j["lane_id"],
                    "attempt_no": intent["attempt_no"],
                    "action_id": action_id, "http_code": code,
                    "response_digest": response_digest, "worker_id": worker_id}
                self._append_evidence(
                    c, now, j["tenant_id"], "peer_response",
                    "rsp_" + secrets.token_hex(12), response_attrs,
                    metric_worker=worker_id)
                c.execute(
                    "UPDATE delivery_intents SET state='response_seen',"
                    "http_code=?,response_digest=?,updated_at=? WHERE action_id=?",
                    (code, response_digest, now, action_id))
            ok = code is not None and 200 <= code < 300
            if ok:
                status, outcome = "succeeded", "success"
                status_sql = ("status='succeeded',last_status=?,last_error=NULL,"
                              "not_before=0,leased_by=NULL,lease_epoch=NULL,"
                              "fence_id=NULL,leased_until=NULL,updated_at=?")
                status_args: tuple = (code, now)
            elif error_kind == "permanent":
                status, outcome = "dead", "dead"
                status_sql = ("status='dead',attempts=attempts+1,last_status=?,"
                              "last_error=?,leased_by=NULL,lease_epoch=NULL,"
                              "fence_id=NULL,leased_until=NULL,updated_at=?")
                status_args = (code, error, now)
            else:
                status, outcome = "pending", "retry"
                nbf = not_before if not_before is not None else now
                status_sql = ("status='pending',attempts=attempts+1,"
                              "fail_count=fail_count+1,last_status=?,last_error=?,"
                              "not_before=?,leased_by=NULL,lease_epoch=NULL,"
                              "fence_id=NULL,leased_until=NULL,updated_at=?")
                status_args = (code, error, nbf, now)
            cur = c.execute(
                f"UPDATE jobs SET {status_sql} WHERE id=? AND status='leased' "
                "AND leased_by=? AND lease_epoch=? AND fence_id=?",
                status_args + (j["id"], worker_id, epoch, fence))
            if cur.rowcount == 0:
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch("job terminal write with stale fence")
            result_attrs = {
                "delivery_id": j["id"], "event_id": j["event_id"],
                "endpoint_id": j["endpoint_id"], "lane_id": j["lane_id"],
                "attempt_no": intent["attempt_no"], "outcome": outcome,
                "http_code": code, "error_kind": error_kind if not ok else None,
                "response_digest": response_digest, "job_status": status,
                "worker_id": worker_id}
            terminal = self._append_evidence(
                c, now, j["tenant_id"], "delivery_result", action_id,
                result_attrs, metric_worker=worker_id)
            c.execute(
                "UPDATE delivery_intents SET state='settled',outcome=?,"
                "http_code=COALESCE(?,http_code),error_kind=?,updated_at=? "
                "WHERE action_id=?",
                (outcome, code, None if ok else error_kind, now, action_id))
            if status == "pending":
                c.execute(
                    "UPDATE lanes SET not_before=MAX(not_before,?),updated_at=? "
                    "WHERE lane_id=?", (status_args[2], now, j["lane_id"]))
            else:
                self._refresh_lane_head(c, j["lane_id"], now)
            if self.crash_after_commit == "attempt_finish_commit":
                self._pending_crash = "attempt_finish_commit"
            return {"job_id": j["id"], "status": status,
                    "action_id": action_id, "idempotent": False,
                    "evidence_seq": terminal["seq"]}
        return self._write(tx)

    # ---- job：claim / success / retry / dead / replay / skip ----------

    def claim(self, lane_id: str, worker_id: str, epoch: int, fence: str
              ) -> Optional[sqlite3.Row]:
        def tx(c, now):
            lane = c.execute("SELECT * FROM lanes WHERE lane_id=?",
                             (lane_id,)).fetchone()
            if lane is None or lane["owner_id"] != worker_id \
                    or lane["lease_epoch"] != epoch or lane["fence_id"] != fence:
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch("claim with non-owner fence")
            if not lane["owner_id"] or lane["expires_at"] is None \
                    or lane["expires_at"] <= now:
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch("claim on expired lease")
            # 端点并行度：跨所有 owner 统计在途 job
            used = c.execute(
                "SELECT COUNT(*) n FROM jobs WHERE endpoint_id=? AND status='leased'",
                (lane["endpoint_id"],)).fetchone()["n"]
            ep = c.execute("SELECT parallelism FROM endpoints WHERE id=?",
                           (lane["endpoint_id"],)).fetchone()
            if ep is not None and used >= ep["parallelism"]:
                return None
            # lane 内已有在途 job：严格队头串行
            busy = c.execute(
                "SELECT COUNT(*) n FROM jobs WHERE lane_id=? AND status='leased'",
                (lane_id,)).fetchone()["n"]
            if busy:
                return None
            head = c.execute(
                "SELECT * FROM jobs WHERE lane_id=? AND status NOT IN "
                "('succeeded','canceled') ORDER BY seq LIMIT 1",
                (lane_id,)).fetchone()
            if head is None or head["status"] != "pending":
                return None  # 空 lane / dead 队头阻塞
            water = max(lane["not_before"], head["not_before"])
            if water > now:
                return None  # 继任者也不许提前发出
            cur = c.execute(
                "UPDATE jobs SET status='leased', attempts=attempts+1, "
                "leased_by=?, lease_epoch=?, fence_id=?, leased_until=?, "
                "updated_at=? WHERE id=? AND status='pending'",
                (worker_id, epoch, fence, lane["expires_at"], now, head["id"]))
            if cur.rowcount == 0:
                return None
            return c.execute("SELECT * FROM jobs WHERE id=?",
                             (head["id"],)).fetchone()
        return self._write(tx)

    @staticmethod
    def _attempt_action_id(job_id: str, attempt: int, worker_id: str,
                           epoch: int) -> str:
        raw = f"{job_id}|{attempt}|{worker_id}|{epoch}"
        return "act_" + hashlib.sha256(raw.encode()).hexdigest()[:24]

    def begin_attempt(self, *, job_id: str, worker_id: str, epoch: int,
                      fence: str, request_digest: str, payload_digest: str,
                      host: str, path: str) -> dict:
        """在副作用前写入出站意图与凭证；这是发送的唯一可恢复闸门。"""
        def tx(c, now):
            j = c.execute(
                "SELECT j.*, e.tenant_id FROM jobs j JOIN events e ON e.id=j.event_id "
                "WHERE j.id=?", (job_id,)).fetchone()
            if j is None:
                raise LeaseNotOwned("job not found")
            if j["status"] != "leased" or j["leased_by"] != worker_id or \
                    j["lease_epoch"] != epoch or j["fence_id"] != fence:
                self._bump(c, worker_id, "stale_write_rejected")
                raise StaleEpoch("begin attempt with stale lease")
            action_id = self._attempt_action_id(
                job_id, j["attempts"], worker_id, epoch)
            existing = c.execute(
                "SELECT * FROM delivery_intents WHERE action_id=?",
                (action_id,)).fetchone()
            if existing is not None:
                return {"action_id": action_id, "attempt_no": j["attempts"],
                        "state": existing["state"], "idempotent": True}
            c.execute(
                "INSERT INTO delivery_intents(action_id,job_id,tenant_id,lane_id,"
                "attempt_no,state,worker_id,lease_epoch,fence_id,request_digest,"
                "created_at,updated_at) VALUES(?,?,?,?,?, 'prepared',?,?,?,?,?,?)",
                (action_id, job_id, j["tenant_id"], j["lane_id"],
                 j["attempts"], worker_id, epoch, fence, request_digest, now, now))
            self._append_evidence(
                c, now, j["tenant_id"], "outbound_attempt", action_id,
                {"delivery_id": job_id, "event_id": j["event_id"],
                 "endpoint_id": j["endpoint_id"], "lane_id": j["lane_id"],
                 "attempt_no": j["attempts"], "lease_epoch": epoch,
                 "worker_id": worker_id, "host": host, "path": path,
                 "request_digest": request_digest,
                 "payload_digest": payload_digest},
                metric_worker=worker_id)
            if self.crash_after_commit == "attempt_begin_commit":
                self._pending_crash = "attempt_begin_commit"
            return {"action_id": action_id, "attempt_no": j["attempts"],
                    "state": "prepared", "idempotent": False}
        return self._write(tx)

    def _fence_job(self, c, now, job_id, worker_id, epoch, fence,
                   set_sql: str, args: tuple, metric_reject: bool = True):
        lane = c.execute("SELECT * FROM lanes l JOIN jobs j ON j.lane_id=l.lane_id "
                         "WHERE j.id=?", (job_id,)).fetchone()
        cur = c.execute(
            f"UPDATE jobs SET {set_sql} WHERE id=? AND status='leased' "
            "AND leased_by=? AND lease_epoch=? AND fence_id=? "
            "AND EXISTS (SELECT 1 FROM lanes l WHERE l.lane_id=jobs.lane_id "
            "AND l.owner_id=? AND l.lease_epoch=? AND l.fence_id=?)",
            args + (job_id, worker_id, epoch, fence, worker_id, epoch, fence))
        if cur.rowcount == 0:
            if metric_reject:
                self._bump(c, worker_id, "stale_write_rejected")
            raise StaleEpoch("job write with stale fence", job_id=job_id)
        return lane

    def complete_success(self, job_id: str, worker_id: str, epoch: int,
                         fence: str, code: int) -> dict:
        def tx(c, now):
            lane = self._fence_job(
                c, now, job_id, worker_id, epoch, fence,
                "status='succeeded', last_status=?, last_error=NULL, "
                "not_before=0, leased_by=NULL, lease_epoch=NULL, fence_id=NULL,"
                "leased_until=NULL, updated_at=?",
                (code, now))
            self._refresh_lane_head(c, lane["lane_id"], now)
            return {"job_id": job_id, "status": "succeeded"}
        return self._write(tx)

    def complete_retry(self, job_id: str, worker_id: str, epoch: int,
                       fence: str, code: Optional[int], error: str,
                       not_before: float) -> dict:
        def tx(c, now):
            lane = self._fence_job(
                c, now, job_id, worker_id, epoch, fence,
                "status='pending', attempts=attempts+1, fail_count=fail_count+1,"
                "last_status=?, last_error=?, not_before=?, leased_by=NULL,"
                "lease_epoch=NULL, fence_id=NULL, leased_until=NULL, updated_at=?",
                (code, error, not_before, now))
            # lane 级 not_before 水位：failover 后继任者也必须遵守
            c.execute(
                "UPDATE lanes SET not_before=MAX(not_before,?), updated_at=? "
                "WHERE lane_id=?", (not_before, now, lane["lane_id"]))
            return {"job_id": job_id, "status": "pending", "not_before": not_before}
        return self._write(tx)

    def complete_dead(self, job_id: str, worker_id: str, epoch: int,
                      fence: str, code: int, error: str) -> dict:
        def tx(c, now):
            lane = self._fence_job(
                c, now, job_id, worker_id, epoch, fence,
                "status='dead', attempts=attempts+1, last_status=?, last_error=?,"
                "leased_by=NULL, lease_epoch=NULL, fence_id=NULL, leased_until=NULL,"
                "updated_at=?", (code, error, now))
            self._refresh_lane_head(c, lane["lane_id"], now)
            return {"job_id": job_id, "status": "dead"}
        return self._write(tx)

    def replay(self, job_id: str) -> dict:
        """人工重放（控制面权威，不需要 worker fence；成功态拒绝重放）。"""
        def tx(c, now):
            j = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if j is None:
                raise KeyError("job not found")
            if j["status"] in ("pending", "leased"):
                return {"status": j["status"], "replayed": False,
                        "reason": "already in flight"}
            if j["status"] == "succeeded":
                return {"status": "succeeded", "replayed": False,
                        "reason": "already acknowledged; replay refused"}
            c.execute(
                "UPDATE jobs SET status='pending', attempts=0, fail_count=0,"
                "last_error=NULL, not_before=0, leased_by=NULL, lease_epoch=NULL,"
                "fence_id=NULL, leased_until=NULL, updated_at=? WHERE id=?",
                (now, job_id))
            c.execute("UPDATE lanes SET not_before=0, updated_at=? WHERE lane_id=?",
                      (now, j["lane_id"]))
            e = c.execute("SELECT tenant_id FROM events WHERE id=?",
                          (j["event_id"],)).fetchone()
            self._append_evidence(
                c, now, e["tenant_id"], "operator_replayed",
                "opl_" + secrets.token_hex(12),
                {"delivery_id": job_id, "event_id": j["event_id"],
                 "endpoint_id": j["endpoint_id"], "lane_id": j["lane_id"],
                 "previous_status": j["status"]})
            return {"status": "pending", "replayed": True}
        return self._write(tx)

    def skip(self, job_id: str) -> bool:
        def tx(c, now):
            j = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if j is None:
                return False
            c.execute(
                "UPDATE jobs SET status='canceled', leased_by=NULL, lease_epoch=NULL,"
                "fence_id=NULL, leased_until=NULL, updated_at=? "
                "WHERE id=? AND status IN ('dead','pending','leased')",
                (now, job_id))
            changed = c.execute("SELECT changes() n").fetchone()["n"]
            if changed:
                self._refresh_lane_head(c, j["lane_id"], now)
                c.execute(
                    "UPDATE delivery_intents SET state='settled',outcome='skipped',"
                    "updated_at=? WHERE job_id=? AND state<>'settled'",
                    (now, job_id))
                e = c.execute("SELECT tenant_id FROM events WHERE id=?",
                              (j["event_id"],)).fetchone()
                self._append_evidence(
                    c, now, e["tenant_id"], "delivery_result",
                    "skip_" + secrets.token_hex(12),
                    {"delivery_id": job_id, "event_id": j["event_id"],
                     "endpoint_id": j["endpoint_id"], "lane_id": j["lane_id"],
                     "outcome": "skipped", "job_status": "canceled"})
            return bool(changed)
        return self._write(tx)

    def list_pending_intents(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT i.*, j.status AS job_status FROM delivery_intents i "
                "JOIN jobs j ON j.id=i.job_id WHERE i.state<>'settled' "
                "ORDER BY i.created_at").fetchall()
            return [dict(r) for r in rows]

    def recover_intents(self, *, observed_action_ids: list[str] | None = None,
                        resolve_observed: bool = False) -> dict:
        """把崩溃后悬挂意图分为可安全再试、结局待查、已收敛。

        ``observed_action_ids`` 是对账器从接收方实际动作得到的动作编号。
        默认只做分类；显式要求时才把待查的已观察动作收敛为成功，且终态
        凭证按原 action_id 幂等插入。
        """
        observed = set(observed_action_ids or [])

        def tx(c, now):
            classified = []
            resolved = 0
            for intent in c.execute(
                    "SELECT i.*, j.status job_status FROM delivery_intents i "
                    "JOIN jobs j ON j.id=i.job_id WHERE i.state<>'settled' "
                    "ORDER BY i.created_at").fetchall():
                terminal = c.execute(
                    "SELECT seq FROM evidence_entries WHERE tenant_id=? "
                    "AND action_id=? AND event_type='delivery_result'",
                    (intent["tenant_id"], intent["action_id"])).fetchone()
                if terminal:
                    cls = "converged"
                    c.execute(
                        "UPDATE delivery_intents SET state='settled',"
                        "outcome='converged',updated_at=? WHERE action_id=?",
                        (now, intent["action_id"]))
                elif intent["state"] == "prepared":
                    cls = "safe_to_retry"
                elif intent["action_id"] in observed:
                    cls = "converged" if resolve_observed else "outcome_unknown"
                else:
                    cls = "outcome_unknown"
                if cls == "safe_to_retry":
                    c.execute(
                        "UPDATE delivery_intents SET outcome='safe_to_retry',"
                        "updated_at=? WHERE action_id=?",
                        (now, intent["action_id"]))
                    c.execute(
                        "UPDATE jobs SET status='pending',leased_by=NULL,"
                        "lease_epoch=NULL,fence_id=NULL,leased_until=NULL,"
                        "updated_at=? WHERE id=? AND status='leased'",
                        (now, intent["job_id"]))
                elif cls == "outcome_unknown":
                    c.execute(
                        "UPDATE delivery_intents SET outcome='outcome_unknown',"
                        "updated_at=? WHERE action_id=?",
                        (now, intent["action_id"]))
                elif cls == "converged" and not terminal:
                    j = c.execute("SELECT * FROM jobs WHERE id=?",
                                  (intent["job_id"],)).fetchone()
                    self._append_evidence(
                        c, now, intent["tenant_id"], "peer_response",
                        "rsp_rec_" + secrets.token_hex(12),
                        {"delivery_id": j["id"], "event_id": j["event_id"],
                         "endpoint_id": j["endpoint_id"], "lane_id": j["lane_id"],
                         "attempt_no": intent["attempt_no"],
                         "action_id": intent["action_id"], "http_code": 200,
                         "response_digest": intent["response_digest"],
                         "source": "reconciler_observation",
                         "worker_id": intent["worker_id"]})
                    self._append_evidence(
                        c, now, intent["tenant_id"], "delivery_result",
                        intent["action_id"],
                        {"delivery_id": j["id"], "event_id": j["event_id"],
                         "endpoint_id": j["endpoint_id"], "lane_id": j["lane_id"],
                         "attempt_no": intent["attempt_no"], "outcome": "success",
                         "http_code": 200,
                         "response_digest": intent["response_digest"],
                         "job_status": "succeeded",
                         "source": "reconciler_observation",
                         "worker_id": intent["worker_id"]})
                    c.execute(
                        "UPDATE jobs SET status='succeeded',last_status=200,"
                        "leased_by=NULL,lease_epoch=NULL,fence_id=NULL,"
                        "leased_until=NULL,updated_at=? WHERE id=?",
                        (now, j["id"]))
                    c.execute(
                        "UPDATE delivery_intents SET state='settled',"
                        "outcome='converged',http_code=200,updated_at=? "
                        "WHERE action_id=?", (now, intent["action_id"]))
                    self._refresh_lane_head(c, j["lane_id"], now)
                    resolved += 1
                classified.append({"action_id": intent["action_id"],
                                   "job_id": intent["job_id"],
                                   "tenant_id": intent["tenant_id"],
                                   "state": intent["state"],
                                   "classification": cls})
            counts = {"safe_to_retry": 0, "outcome_unknown": 0,
                      "converged": 0}
            for item in classified:
                counts[item["classification"]] += 1
            self._bump(c, "reconciler", "intent_recovery", len(classified))
            return {"intents": classified, "counts": counts,
                    "resolved_observed": resolved}
        return self._write(tx)

    # ---- 查询 / 运维视图 ---------------------------------------------

    def job(self, job_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute("SELECT * FROM jobs WHERE id=?",
                                     (job_id,)).fetchone()

    def job_for_event(self, event_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute("SELECT * FROM jobs WHERE event_id=?",
                                     (event_id,)).fetchone()

    def delivery_secret(self, eid: str, version: int) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(
                "SELECT secret,kid,url,version FROM endpoint_versions "
                "WHERE endpoint_id=? AND version=?", (eid, version)).fetchone()

    def list_jobs(self, eid: str, limit: int = 100,
                  status: Optional[str] = None) -> list[sqlite3.Row]:
        q = ("SELECT j.*, e.object_key AS ev_object FROM jobs j "
             "JOIN events e ON e.id=j.event_id WHERE j.endpoint_id=?")
        args: list[Any] = [eid]
        if status:
            q += " AND j.status=?"
            args.append(status)
        q += " ORDER BY j.seq DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            return list(self.conn.execute(q, args))

    def lane(self, lane_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute("SELECT * FROM lanes WHERE lane_id=?",
                                     (lane_id,)).fetchone()

    def lanes_for_endpoint(self, eid: str) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(
                "SELECT * FROM lanes WHERE endpoint_id=? ORDER BY object_key",
                (eid,)))

    def list_leases(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(
                "SELECT * FROM lanes ORDER BY endpoint_id, object_key"))

    def list_workers(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(
                "SELECT * FROM workers ORDER BY worker_id"))

    def worker(self, worker_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self.conn.execute("SELECT * FROM workers WHERE worker_id=?",
                                     (worker_id,)).fetchone()

    def owned_lanes(self, worker_id: str) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(
                "SELECT * FROM lanes WHERE owner_id=? ORDER BY endpoint_id,object_key",
                (worker_id,)))

    def active_job_count(self, worker_id: str) -> int:
        with self._lock:
            return self.conn.execute(
                "SELECT COUNT(*) n FROM jobs WHERE leased_by=? AND status='leased'",
                (worker_id,)).fetchone()["n"]

    def orphan_lanes(self) -> list[sqlite3.Row]:
        """无主且仍有未完成 job 的 lane（应当为空）。"""
        with self._lock:
            return list(self.conn.execute(
                "SELECT l.* FROM lanes l WHERE l.owner_id IS NULL AND EXISTS "
                "(SELECT 1 FROM jobs j WHERE j.lane_id=l.lane_id "
                "AND j.status NOT IN ('succeeded','canceled'))"))

    def counters(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.conn.execute(
                "SELECT * FROM counters ORDER BY worker_id,name"))

    def ownership_log(self, limit: int = 2000) -> list[sqlite3.Row]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM ownership_log ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
            return rows[::-1]

    def counts(self, eid: str) -> dict:
        with self._lock:
            rows = self.conn.execute(
                "SELECT status, COUNT(*) c FROM jobs WHERE endpoint_id=? "
                "GROUP BY status", (eid,)).fetchall()
            out = {r["status"]: r["c"] for r in rows}
            nxt = self.conn.execute(
                "SELECT MIN(not_before) nb FROM jobs WHERE endpoint_id=? "
                "AND status IN ('pending','leased')", (eid,)).fetchone()
            out["next_eligible_at"] = nxt["nb"] if nxt and nxt["nb"] else 0
            return out

    def pending_version_counts(self, eid: str) -> dict:
        with self._lock:
            rows = self.conn.execute(
                "SELECT sig_version v, COUNT(*) c FROM jobs WHERE endpoint_id=? "
                "AND status IN ('pending','leased') GROUP BY sig_version",
                (eid,)).fetchall()
            return {str(r["v"]): r["c"] for r in rows}

    def set_crash_point(self, point: str = "") -> dict:
        allowed = {"", "anchor_seal_commit", "attempt_begin_commit",
                   "attempt_finish_commit"}
        if point not in allowed:
            raise ValueError("unknown crash point")
        self.crash_after_commit = point
        return {"crash_after_commit": point}

    def reset_for_test(self) -> None:
        """验收专用：每个场景一个全新数据库，这里仅提供热清空兜底。"""
        def tx(c, now):
            for t in ("ownership_log", "counters", "jobs", "lanes", "events",
                      "workers", "endpoint_versions", "endpoints", "tenants",
                      "evidence_entries", "evidence_anchors",
                      "sealing_rotations", "delivery_intents", "legal_holds",
                      "privacy_batches", "evidence_exports"):
                c.execute(f"DELETE FROM {t}")
                c.execute(f"DELETE FROM sqlite_sequence WHERE name='{t}'")
        self._write(tx)
