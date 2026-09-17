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
import secrets
import sqlite3
import threading
import time
from typing import Any, Callable, Optional

from .cred import (
    RECORD_HANDOFF, RECORD_INGEST, RECORD_REPLAY, RECORD_SKIP,
)

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
"""


def new_fence() -> str:
    return "fence_" + secrets.token_hex(12)


class Engine:
    """所有方法线程安全；跨进程安全由事务保证，而非任何进程内锁。"""

    def __init__(self, path: str):
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False,
                                    isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=10000;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        # 防篡改凭证册：同一 SQLite 文件 => 凭证追加可与主账状态同事务。
        from .cred import Ledger
        self.cred = Ledger(
            self.conn,
            reject_flag=lambda: self.reject_writes,
            clock=self._clock_now,
            shared_lock=self._lock)
        # 写闸门：True 时一切写事务失败（store outage 注入）
        self.reject_writes = False
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

    # ---- 租户 / 端点 / 版本（沿用原语义） -----------------------------

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
            # 凭证：消息入账。只存正文的 SHA256/长度等不可反推材料，
            # 正文本身绝不进凭证。
            payload_digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            self.cred.append_record(
                c, now, tenant_id, RECORD_INGEST,
                {"event_id": event_id, "delivery_id": job_id,
                 "endpoint_id": eid, "lane_id": lane_id,
                 "object_key": object_key, "lane_seq": seq,
                 "payload_sha256": payload_digest,
                 "payload_bytes": len(payload.encode("utf-8")),
                 "sig_version": v["version"], "kid": v["kid"]},
                action_id=job_id)
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
        self._cred_handoff(c, now, lane, new_owner, new_epoch, reason)
        self._log_ownership(c, now, lane, new_owner, new_epoch, reason)
        return True

    def _cred_handoff(self, c, now, lane: sqlite3.Row, new_owner,
                      new_epoch: int, reason: str) -> None:
        """所有权交接凭证（每个相关客户账户各一条；不含任何秘密）。"""
        try:
            ep = c.execute(
                "SELECT tenant_id FROM endpoints WHERE id=?",
                (lane["endpoint_id"],)).fetchone()
            tenant_id = ep["tenant_id"] if ep else None
        except Exception:
            tenant_id = None
        if not tenant_id:
            return
        self.cred.append_record(
            c, now, tenant_id, RECORD_HANDOFF,
            {"lane_id": lane["lane_id"], "endpoint_id": lane["endpoint_id"],
             "object_key": lane["object_key"],
             "old_owner": lane["owner_id"], "new_owner": new_owner,
             "old_epoch": lane["lease_epoch"], "new_epoch": new_epoch,
             "reason": reason}, action_id=None)

    def _release_lane(self, c, now, lane: sqlite3.Row,
                      reason: str = "release") -> None:
        """交还公共池（owner=NULL）；epoch 保留，下一次 acquire 仍会 +1。"""
        c.execute(
            "UPDATE lanes SET owner_id=NULL, fence_id=NULL, expires_at=NULL,"
            "draining=0, last_handoff_reason=?, updated_at=? "
            "WHERE lane_id=?", (reason, now, lane["lane_id"]))
        self._cred_handoff(c, now, lane, None, lane["lease_epoch"], reason)
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
            job = c.execute("SELECT * FROM jobs WHERE id=?",
                            (head["id"],)).fetchone()
            # 凭证 tx1（副作用之前）：登记出站意图 + pending 的 attempt。
            # 此刻绝不记录成功；崩溃在此之后、发送之前 => 安全再试。
            attempt_no = job["attempts"]
            action_id = self.action_id(job["id"], attempt_no)
            self.cred.begin_intent(
                c, now, account_id=self._tenant_for_job(c, job["id"]),
                action_id=action_id, lane_id=job["lane_id"],
                job_id=job["id"], attempt_no=attempt_no,
                body={"delivery_id": job["id"], "event_id": job["event_id"],
                      "lane_id": job["lane_id"], "lane_seq": job["seq"],
                      "endpoint_id": job["endpoint_id"],
                      "attempt": attempt_no, "worker_id": worker_id,
                      "lease_epoch": epoch, "kid": job["kid"],
                      "sig_version": job["sig_version"],
                      "phase": "pre_side_effect"})
            return job
        return self._write(tx)

    @staticmethod
    def action_id(job_id: str, attempt_no: int) -> str:
        """一次出站尝试的确定性幂等键（job + 第几次尝试）。"""
        return f"{job_id}:a{attempt_no}"

    @staticmethod
    def _tenant_for_job(c, job_id: str) -> str:
        row = c.execute(
            "SELECT e.tenant_id AS tid FROM jobs j JOIN endpoints e "
            "ON e.id=j.endpoint_id WHERE j.id=?", (job_id,)).fetchone()
        return row["tid"] if row else "unknown"

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
                         fence: str, code: int,
                         peer_event_id: Optional[str] = None,
                         response_bytes: int = 0) -> dict:
        def tx(c, now):
            lane = self._fence_job(
                c, now, job_id, worker_id, epoch, fence,
                "status='succeeded', last_status=?, last_error=NULL, "
                "not_before=0, leased_by=NULL, lease_epoch=NULL, fence_id=NULL,"
                "leased_until=NULL, updated_at=?",
                (code, now))
            self._refresh_lane_head(c, lane["lane_id"], now)
            # 凭证 tx2：对方应答 + 唯一终态成功凭证（幂等，绝不双份）。
            attempt_no = lane["attempts"]
            action_id = self.action_id(job_id, attempt_no)
            self.cred.finalize_success(
                c, now, account_id=self._tenant_for_job(c, job_id),
                action_id=action_id, code=code, peer_event=peer_event_id,
                response_body_meta={"response_bytes": response_bytes,
                                    "worker_id": worker_id,
                                    "lease_epoch": epoch})
            return {"job_id": job_id, "status": "succeeded",
                    "action_id": action_id}
        return self._write(tx)

    def mark_attempt_sent(self, job_id: str, attempt_no: int, code: int,
                          kind: str) -> None:
        """副作用已返回、终态事务尚未提交时的“sent”标记（缩小待查窗口）。

        非 fence 写：只更新本节点刚 claim 的意图行；终态仍由
        complete_* 在 fence 事务内收敛。"""
        def tx(c, now):
            self.cred.mark_sent(c, now, self.action_id(job_id, attempt_no),
                                code, kind)
        try:
            self._write(tx)
        except Exception:
            # 标记失败不影响主流程：对账器会把它保守判为 in_doubt/safe_retry
            log.debug("mark_attempt_sent failed for %s", job_id, exc_info=True)

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
            # 凭证：对可重试失败只记应答（非终态），意图退回 safe_retry，
            # 绝不把“尚未被对方确认成功”记成成功。
            attempt_no = lane["attempts"]
            action_id = self.action_id(job_id, attempt_no)
            self.cred.finalize_failure(
                c, now, account_id=self._tenant_for_job(c, job_id),
                action_id=action_id, code=code,
                kind="nack" if code is not None else "transport",
                reason_class=("http_" + str(code)) if code is not None
                else "transport_error", terminal=False)
            return {"job_id": job_id, "status": "pending",
                    "not_before": not_before, "action_id": action_id}
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
            # 凭证：永久失败终态（队头阻塞，等人工 replay/skip）。
            attempt_no = lane["attempts"]
            action_id = self.action_id(job_id, attempt_no)
            self.cred.finalize_failure(
                c, now, account_id=self._tenant_for_job(c, job_id),
                action_id=action_id, code=code,
                kind="nack" if code else "transport",
                reason_class=("http_" + str(code)) if code else "transport_error",
                terminal=True)
            return {"job_id": job_id, "status": "dead", "action_id": action_id}
        return self._write(tx)

    def replay(self, job_id: str, operator: str = "operator") -> dict:
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
            # 凭证：操作员再次执行（不含正文/密钥）。
            self.cred.append_record(
                c, now, self._tenant_for_job(c, job_id), RECORD_REPLAY,
                {"delivery_id": job_id, "event_id": j["event_id"],
                 "lane_id": j["lane_id"], "lane_seq": j["seq"],
                 "endpoint_id": j["endpoint_id"],
                 "prev_status": j["status"], "operator": operator,
                 "kid": j["kid"], "sig_version": j["sig_version"]},
                action_id=job_id + ":replay")
            return {"status": "pending", "replayed": True}
        return self._write(tx)

    def skip(self, job_id: str, operator: str = "operator") -> bool:
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
                # 凭证：操作员跳过。
                self.cred.append_record(
                    c, now, self._tenant_for_job(c, job_id), RECORD_SKIP,
                    {"delivery_id": job_id, "event_id": j["event_id"],
                     "lane_id": j["lane_id"], "lane_seq": j["seq"],
                     "endpoint_id": j["endpoint_id"],
                     "prev_status": j["status"], "operator": operator},
                    action_id=job_id + ":skip")
            return bool(changed)
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

    # ---- 凭证对账：悬挂意图三分类 ------------------------------------

    def reconcile_intents(self, peer_probe=None) -> dict:
        """扫描悬挂意图并归类为 safe_retry / in_doubt / converged。

        ``peer_probe(job_row, action_id) -> dict|None`` 可选：对
        recorded/sent 的意图向对方核实是否已观察到该 event_id。
        返回 {safe_retry:[...], in_doubt:[...], converged:[...]}。

        判定规则（绝不伪造成功，绝不产生双份终态凭证）：
          * 主账 job 已 succeeded/canceled/dead 且意图未 finalize
            => converged（补记账，不重发，不补第二张成功凭证）；
          * job 仍 leased 且租约有效 => 跳过（动作在途，非悬挂）；
          * recorded + job 已退回 pending，对方未见该投递 => safe_retry；
          * 对方已见 event_id 但主账未落成功 => in_doubt（结局待查，
            需人工/对方权威确认，禁止盲发第二条）；
          * sent 且无法向对方核实 => in_doubt（保守）。
        """
        from .cred import (INTENT_CONVERGED, INTENT_IN_DOUBT,
                           INTENT_RECORDED, INTENT_SAFE_RETRY, INTENT_SENT)
        summary = {"safe_retry": [], "in_doubt": [], "converged": []}

        dangling = self.cred.pending_intents()
        for it in dangling:
            j = self.job(it["job_id"])
            if j is None:
                continue
            lane = self.lane(j["lane_id"])
            now = self.now()
            in_flight = (j["status"] == "leased" and lane is not None
                         and lane["owner_id"] and lane["expires_at"]
                         and lane["expires_at"] > now)
            if in_flight:
                continue  # 仍在有效租约内：不是悬挂意图

            observed = False
            if peer_probe is not None and it["state"] in (INTENT_RECORDED,
                                                          INTENT_SENT):
                try:
                    pr = peer_probe(j, it["action_id"])
                    observed = bool(pr and pr.get("observed"))
                except Exception:
                    observed = False

            def classify(c, ts):
                if j["status"] == "succeeded":
                    self.cred.set_intent_state(
                        c, ts, it["action_id"], INTENT_CONVERGED,
                        finalized=True)
                    summary["converged"].append(
                        {"action_id": it["action_id"], "job_id": j["id"],
                         "basis": "main_ledger_succeeded"})
                elif j["status"] in ("dead", "canceled"):
                    self.cred.set_intent_state(
                        c, ts, it["action_id"], INTENT_CONVERGED,
                        finalized=True)
                    summary["converged"].append(
                        {"action_id": it["action_id"], "job_id": j["id"],
                         "basis": "main_ledger_" + j["status"]})
                elif observed:
                    # 对方已收到但主账未结算：结局待查，严禁再发
                    self.cred.set_intent_state(
                        c, ts, it["action_id"], INTENT_IN_DOUBT)
                    summary["in_doubt"].append(
                        {"action_id": it["action_id"], "job_id": j["id"],
                         "basis": "peer_observed_without_local_terminal"})
                else:
                    # recorded/sent 但对方未见、主账已退回：安全再试
                    # （接收方按 event_id 幂等，即使实际已达也不会二次确认）
                    self.cred.set_intent_state(
                        c, ts, it["action_id"], INTENT_SAFE_RETRY)
                    summary["safe_retry"].append(
                        {"action_id": it["action_id"], "job_id": j["id"],
                         "basis": ("not_observed_retryable"
                                   if it["state"] == INTENT_RECORDED
                                   else "sent_unobserved_treat_retryable")})

            self._write(classify)
        if dangling:
            self.cred.transact(
                lambda c, ts: self.cred._bump(
                    c, "intent_recoveries",
                    len(summary["safe_retry"])
                    + len(summary["in_doubt"])
                    + len(summary["converged"])))
        return summary

    def intents_view(self) -> list[dict]:
        """运维面：当前待查/悬挂意图（含 recorded/sent/in_doubt/safe_retry）。"""
        from .cred import INTENT_CONVERGED
        rows = self.cred.pending_intents(
            states=("recorded", "sent", "in_doubt", "safe_retry"))
        now = self.now()
        out = []
        for it in rows:
            j = self.job(it["job_id"])
            lane = self.lane(it["lane_id"]) if j else None
            in_flight = bool(
                j and j["status"] == "leased" and lane and lane["owner_id"]
                and lane["expires_at"] and lane["expires_at"] > now)
            out.append({**it, "job_status": j["status"] if j else None,
                        "in_flight_lease": in_flight})
        return out

    # ---- 隐私抹除（主账正文 / 受保护附件） ----------------------------

    _PAYLOAD_TOMBSTONE = json.dumps(
        {"_redacted": True, "reason": "retention_expired"},
        ensure_ascii=False)

    def set_retention(self, tenant_id: str, *,
                      retain_seconds: Optional[float] = None,
                      legal_hold: Optional[bool] = None,
                      hold_reason: Optional[str] = None) -> dict:
        """留存策略。retain_seconds=TTL 秒数（相对事件 created_at），
        0/None=长期留存；legal_hold=True 期间拒绝抹除。"""
        return self.cred.transact(
            lambda c, ts: self._set_retention_tx(
                c, ts, tenant_id, retain_seconds, legal_hold, hold_reason))

    def _set_retention_tx(self, c, now, tenant_id, ttl_seconds, legal_hold,
                          hold_reason) -> dict:
        self.cred.ensure_account(c, tenant_id, now)
        if ttl_seconds is not None:
            c.execute(
                "UPDATE cred_retention SET retain_until=?, updated_at=? "
                "WHERE account_id=?",
                (float(ttl_seconds), now, tenant_id))
        if legal_hold is not None:
            c.execute(
                "UPDATE cred_retention SET legal_hold=?, hold_reason=?, "
                "updated_at=? WHERE account_id=?",
                (1 if legal_hold else 0,
                 hold_reason if legal_hold else None, now, tenant_id))
        return dict(c.execute(
            "SELECT * FROM cred_retention WHERE account_id=?",
            (tenant_id,)).fetchone())

    def retention_view(self, tenant_id: str) -> dict:
        return self.cred.retention(tenant_id)

    def scrub_privacy(self, tenant_id: str, *, batch_size: int = 100,
                      ttl_override: Optional[float] = None) -> dict:
        """按账户 TTL 抹除主账可识别正文（司法留置期间拒办）。

        凭证链不动（链上只有哈希）；在一个事务内：选中已过 TTL 的事件 ->
        events.payload 置墓碑 -> 追加 privacy_scrubbed 凭证（只引用
        event_id/哈希/入账序号）-> 推进游标。
        """
        def tx(c, now):
            ret = self.cred.retention(tenant_id)
            if ret.get("legal_hold"):
                return {"ran": False, "blocked": "legal_hold",
                        "reason": ret.get("hold_reason"), "scrubbed": 0}
            ttl = ttl_override if ttl_override is not None \
                else (ret.get("retain_until") or 0)
            rows = c.execute(
                "SELECT ev.id AS event_id, ev.payload AS payload, ev.created_at,"
                " r.seq AS ingest_seq FROM events ev JOIN endpoints ep "
                "ON ep.id=ev.endpoint_id "
                "LEFT JOIN cred_records r ON r.account_id=? "
                "AND r.type='message_ingested' AND r.action_id=("
                "SELECT j.id FROM jobs j WHERE j.event_id=ev.id LIMIT 1) "
                "WHERE ep.tenant_id=? AND ev.payload NOT LIKE ? "
                "ORDER BY ev.created_at, ev.id LIMIT ?",
                (tenant_id, tenant_id, '{"_redacted%', batch_size)).fetchall()
            chosen = [r for r in rows if ttl and now - r["created_at"] >= ttl]
            refs = []
            for r in chosen:
                ph = hashlib.sha256(r["payload"].encode("utf-8")).hexdigest()
                c.execute("UPDATE events SET payload=? WHERE id=?",
                          (self._PAYLOAD_TOMBSTONE, r["event_id"]))
                refs.append({"event_id": r["event_id"],
                             "payload_sha256": ph,
                             "ingest_seq": r["ingest_seq"]})
            if chosen:
                upto = max(r["created_at"] for r in chosen)
                self.cred.record_scrub(
                    c, now, account_id=tenant_id, refs=refs,
                    ttl_seconds=float(ttl), mode="ttl_expired")
                self.cred.mark_scrub_cursor(
                    c, now, tenant_id, upto, len(chosen))
            return {"ran": True, "blocked": None, "scrubbed": len(chosen),
                    "ttl_seconds": ttl,
                    "remaining": len(rows) - len(chosen)}
        return self._write(tx)

    def scrub_progress(self, tenant_id: str) -> dict:
        return self.cred.scrub_progress(tenant_id)

    # ---- 凭证查询（透传给 cred.Ledger）-------------------------------

    def cred_head(self, account_id: str) -> dict:
        return self.cred.head(account_id)

    def cred_verify_chain(self, account_id: str, upto=None) -> dict:
        return self.cred.verify_chain(account_id, upto=upto)
    def cred_records(self, account_id: str, seq_from: int = 1,
                     seq_to: Optional[int] = None) -> list[dict]:
        return self.cred.records(account_id, seq_from, seq_to)

    def cred_anchors(self, account_id: str) -> list[dict]:
        return self.cred.anchors(account_id)

    def cred_latest_anchor(self, account_id: str) -> Optional[dict]:
        return self.cred.latest_anchor(account_id)

    def cred_audit_tail(self, limit: int = 50) -> list[dict]:
        return self.cred.audit_tail(limit)

    def cred_metrics(self) -> dict:
        return self.cred.metrics()

    def cred_accounts(self) -> list[dict]:
        return self.cred.accounts()

    def cred_generations(self) -> list[dict]:
        return self.cred.key_generations()

    def cred_exports(self, account_id: Optional[str] = None) -> list[dict]:
        return self.cred.exports(account_id)


    def reset_for_test(self) -> None:
        """验收专用：每个场景一个全新数据库，这里仅提供热清空兜底。

        封存密钥代次/换代证书（cred_key_gens/cred_rotations）刻意保留：
        它代表跨场景的密钥沿革连续性。"""
        def tx(c, now):
            for t in ("ownership_log", "counters", "jobs", "lanes", "events",
                      "workers", "endpoint_versions", "endpoints", "tenants",
                      "cred_intents", "cred_finalized", "cred_anchors",
                      "cred_records", "cred_accounts", "cred_retention",
                      "cred_exports", "cred_scrubs", "cred_metrics",
                      "cred_audit"):
                c.execute(f"DELETE FROM {t}")
                c.execute(f"DELETE FROM sqlite_sequence WHERE name='{t}'")
        self._write(tx)
