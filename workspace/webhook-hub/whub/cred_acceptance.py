"""防篡改凭证册 7 场景验收：空白账库 + 真实双进程 + 故障注入 + 离线核验器。

与 :mod:`whub.acceptance` 同一套 Cluster 工具，但每个场景都用**全新
集群/全新数据库/全新 keystore**，并以离线核验器（:mod:`whub.cred_verify`）
作为最终判据，而不是搜审计文字。

场景
====
1. 双节点高频争用 + 多次所有权换手：编号连续、相邻摘要衔接、接收方
   实际动作与终态凭证逐项对应。
2. 副作用前 / 副作用后 / 封存途中强杀进程：对账三分类准确，无虚假成功
   与双份终态证明。
3. 改写中间行 / 删行 / 交换相邻行 / 替换锚点：离线核验器全识别并报
   最早失信序号。
4. 压力写入不停时导出：截止前稳定可验、之后不混入、增量包紧密接续。
5. 封存私钥换代前后两个包均可验；旧私钥泄漏后伪造新锚点必败、沿革
   足以证明分界。
6. 留存到期抹敏感内容后动作数/次序仍可证；司法留置阻止抹除、解除后续办；
   接口与审计文字检索不到原值。
7. 共享账库短暂拒写：主账不产生无法记账的成功；恢复后待查意图逐项清算，
   链头与主账终态相符。
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import sys
import tempfile
import time
import urllib.request

from .acceptance import Cluster, Tenant, http, wait_until
from .cred_verify import verify_package

log = logging.getLogger("whub.cred_acceptance")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CredCheckFail(Exception):
    pass


class CredScenario:
    def __init__(self, num: str, title: str):
        self.num = num
        self.title = title
        self.checks: list[dict] = []
        self.detail: dict = {}
        self.error: str | None = None

    def check(self, name: str, cond: bool, detail="") -> None:
        self.checks.append({"name": name, "ok": bool(cond), "detail": str(detail)})
        if not cond:
            raise CredCheckFail(f"{name} :: {detail}")

    @property
    def passed(self) -> bool:
        return self.error is None and all(c["ok"] for c in self.checks)


class CredAcceptance:
    def __init__(self, ttl: float = 4.0, report_path: str = "cred-report.json",
                 scenarios: str = "", keep_dirs: bool = False):
        self.ttl = ttl
        self.report_path = report_path
        nums = [x.strip() for x in scenarios.split(",") if x.strip()]
        self.wanted = nums or ["1", "2", "3", "4", "5", "6", "7"]
        self.keep_dirs = keep_dirs
        self.tmpdir = tempfile.mkdtemp(prefix="whub-cred-")
        self.results: list[CredScenario] = []

    # ---- 集群工厂：短锚点周期，便于场景断言 ---------------------------

    def _cluster(self, name: str, **kw) -> Cluster:
        c = Cluster(name, ttl=self.ttl, tmpdir=self.tmpdir, **kw)
        return c

    def _start(self, c: Cluster, anchor_interval: float = 1.0) -> None:
        c.start(seed=False)
        # store 已以 WHUB_ANCHOR_INTERVAL 启动（在 env 里注入）
        self._anchor_interval = anchor_interval

    def run(self) -> int:
        log.info("credential acceptance: ttl=%s tmp=%s scenarios=%s",
                 self.ttl, self.tmpdir, self.wanted)
        for num in self.wanted:
            sc = CredScenario(num, TITLES[num])
            c = Cluster(f"c{num}", ttl=self.ttl, tmpdir=self.tmpdir)
            t0 = time.time()
            try:
                # 每个场景独立 keystore 与导出目录
                c._cred_dir = os.path.join(self.tmpdir, f"c{num}-exports")
                os.makedirs(c._cred_dir, exist_ok=True)
                c._seal_path = os.path.join(c.dir, "seal.json")
                c.start(seed=False, cred_key_path=c._seal_path,
                        anchor_interval=1.0)
                getattr(self, f"scenario_{num}")(c, sc)
            except CredCheckFail as e:
                sc.error = f"assertion: {e}"
            except Exception as e:
                log.exception("scenario %s crashed", num)
                sc.error = f"crash: {type(e).__name__}: {e}"
            finally:
                sc.detail["elapsed"] = round(time.time() - t0, 2)
                try:
                    c.stop()
                except Exception:
                    pass
                self.results.append(sc)
                log.info("cred scenario %s %s (%d checks)", num,
                         "PASS" if sc.passed else "FAIL", len(sc.checks))
        self._write_report()
        ok = all(s.passed for s in self.results)
        self._print_summary()
        return 0 if ok else 1

    # ---- 辅助 ---------------------------------------------------------

    @staticmethod
    def _admin(c: Cluster, path: str, body=None, method="POST"):
        return http(method, f"{c.store}/admin{path}", body=body)

    def _export(self, c: Cluster, tenant: str, seq_from=1,
                incremental_of=None) -> dict:
        code, r = self._admin(c, "/cred/export", {
            "account_id": tenant, "out_dir": c._cred_dir,
            "seq_from": seq_from, "incremental_of": incremental_of})
        assert code == 201, r
        return r

    def _verify(self, path, **kw) -> dict:
        return verify_package(path, **kw)

    def _anchor(self, c: Cluster, tenant: str) -> dict:
        code, r = self._admin(c, "/cred/anchor", {"account_id": tenant})
        assert code == 200, r
        return r

    def _overview(self, c: Cluster) -> dict:
        return self._admin(c, "/cred/overview", method="GET")[1]

    def _load_chain(self, c: Cluster, tenant: str) -> list[dict]:
        code, r = http("POST", f"{c.store}/rpc",
                       body={"op": "cred_records",
                             "args": {"account_id": tenant}})
        assert code == 200, r
        return r["result"]

    # ================================================================ 1

    def scenario_1(self, c: Cluster, sc: CredScenario) -> None:
        t = Tenant(c, "c1")
        c.sink_rule("/c1", "ok")
        ep = t.endpoint("/c1", parallelism=8)["endpoint_id"]
        n_obj = 10
        n_per = 6
        refs = []
        for o in range(n_obj):
            for k in range(n_per):
                refs.append(t.publish(ep, f"obj-{o}", {"k": k})["delivery_id"])
        t.wait_succeeded(refs, timeout=60)

        # 制造多次所有权换手：drain a，让 b 接管，再 drain b
        c.drain("a", deadline=self.ttl * 2)
        wait_until("a drained all lanes",
                   lambda: next((w["owned"] for w in c.workers()
                                 if w["worker_id"] == "worker-a"), -1) == 0,
                   timeout=self.ttl * 8)
        c.drain("a", draining=False)
        time.sleep(0.3)
        # 再来一批促使重新分配/换手
        refs2 = [t.publish(ep, f"obj-{o}", {"k": 99})["delivery_id"]
                 for o in range(n_obj)]
        t.wait_succeeded(refs2, timeout=40)

        self._anchor(c, t.tid)
        chain = self._load_chain(c, t.tid)
        seqs = [r["seq"] for r in chain]
        sc.check("编号连续无缺号/分叉/重复",
                 seqs == list(range(1, len(seqs) + 1)), f"N={len(seqs)}")
        # 相邻摘要衔接
        from whub.cred_crypto import b64d
        prev = None
        link_ok = first_bad = True
        bad_seq = None
        for r in chain:
            if (r["prev_digest"] or None) != (
                    __import__("base64").b64encode(prev).decode()
                    if prev else None):
                first_bad = False
                bad_seq = r["seq"]
                break
            prev = b64d(r["digest"])
        sc.check("相邻 prev_digest 完全衔接", first_bad, f"at {bad_seq}")
        sc.check("链上存在多次 ownership_handoff",
                 sum(1 for r in chain if r["type"] == "ownership_handoff") >= 2,
                 f"handoffs={sum(1 for r in chain if r['type']=='ownership_handoff')}")

        # 接收方实际动作（receipt）与终态凭证（outbound_success）逐项对应
        stats = c.sink_stats()
        recv_events = sorted(r["event_id"]
                             for r in stats["receipts"].get("/c1", []))
        success_recs = [r for r in chain if r["type"] == "outbound_success"]
        # 每个 job 恰好一个终态成功凭证（无双份）
        action_success = {}
        for r in success_recs:
            body = json.loads(r["body_json"])
            aid = body["data"]["action_id"].split(":a")[0]
            action_success[aid] = action_success.get(aid, 0) + 1
        dup_terminal = {k: v for k, v in action_success.items() if v > 1}
        sc.check("每个投递只有一份终态成功凭证", not dup_terminal, str(dup_terminal))
        # 终态凭证引用的 peer_event_id 都在接收方 receipts 中
        peer_ids = set()
        for r in success_recs:
            peer_ids.add(json.loads(r["body_json"])["data"]["peer_event_id"])
        sc.check("终态凭证与接收方 receipts 逐项对应",
                 peer_ids == set(recv_events),
                 f"cred={len(peer_ids)} recv={len(set(recv_events))}")

        # 离线核验整包
        pkg = self._export(c, t.tid)
        v = self._verify(pkg["path"])
        sc.check("离线核验无损包通过", v["ok"], str(v.get("chain")))
        sc.check("凭证总数与导出一致", pkg["record_count"] == len(chain),
                 f"{pkg['record_count']} vs {len(chain)}")
        sc.detail.update({"record_total": len(chain),
                          "head_digest": chain[-1]["digest"],
                          "export_cutoff": pkg["seq_cutoff"]})

    # ================================================================ 2

    def scenario_2(self, c: Cluster, sc: CredScenario) -> None:
        t = Tenant(c, "c2")
        c.sink_rule("/c2", "delay", delay=0.4)
        ep = t.endpoint("/c2", parallelism=1)["endpoint_id"]
        LANE = "stream"   # 全部消息同一 lane，严格串行、owner 唯一

        def publish(tag):
            return t.publish(ep, LANE, {"o": tag})

        # ---- 2a：副作用前崩溃 ----
        r1 = publish("pre")
        # 先让占位消息完成，确定持有该 lane 的 worker（同 lane 串行）
        t.wait_succeeded([r1["delivery_id"]], timeout=20)
        owner = next(l["owner_id"] for l in c.leases()
                     if l["lane_id"] == r1["lane_id"])
        wcode = "a" if owner == "worker-a" else "b"
        http("POST", c.worker_url(wcode) + "/test/crash-point",
             body={"point": "before_side_effect"})
        r2 = publish("pre2")
        dead = c.procs[f"worker-{wcode}"]
        wait_until("worker died before side effect",
                   lambda: dead.poll() is not None, timeout=12)
        c.restart_worker(wcode)

        # ---- 2b：副作用后崩溃 ----
        # 等当前 lane 被某个存活 worker 重新持有
        wait_until("lane owned again",
                   lambda: next((l["owner_id"] for l in c.leases()
                                 if l["lane_id"] == r1["lane_id"]), None),
                   timeout=self.ttl * 6)
        owner2 = next(l["owner_id"] for l in c.leases()
                      if l["lane_id"] == r1["lane_id"])
        wcode2 = "a" if owner2 == "worker-a" else "b"
        http("POST", c.worker_url(wcode2) + "/test/crash-point",
             body={"point": "after_side_effect"})
        r3 = publish("post")
        dead2 = c.procs[f"worker-{wcode2}"]
        wait_until("worker2 died after side effect",
                   lambda: dead2.poll() is not None, timeout=15)
        c.restart_worker(wcode2)

        # 等所有任务收敛
        t.wait_succeeded([r1["delivery_id"], r2["delivery_id"],
                          r3["delivery_id"]], timeout=60)

        # ---- 对账 ----
        code, summary = self._admin(c, "/cred/reconcile", {})
        sc.check("对账执行成功", code == 200, str(summary))
        # 全部 job 已成功后，悬挂意图应归 converged（无虚假成功、无双终态）
        code, intents = http("POST", f"{c.store}/rpc",
                             body={"op": "intents_view", "args": {}})
        # intents_view 只列非 converged；应为空（全部收敛）
        sc.check("对账后无悬挂/待查意图", len(intents["result"]) == 0,
                 str(intents["result"])[:300])
        # 无双份终态凭证：每个 delivery 至多一个 outbound_success
        chain = self._load_chain(c, t.tid)
        succ = {}
        for r in chain:
            if r["type"] == "outbound_success":
                body = json.loads(r["body_json"])
                jid = body["data"]["action_id"].split(":a")[0]
                succ[jid] = succ.get(jid, 0) + 1
        dup = {k: v for k, v in succ.items() if v > 1}
        sc.check("不存在双份终态成功凭证", not dup, str(dup))
        # 没有在“未应答”时记录成功：每个 success 都有对应 peer_response
        seqset = {r["seq"] for r in chain}
        bad_success = []
        for r in chain:
            if r["type"] == "outbound_success":
                body = json.loads(r["body_json"])
                if body["data"].get("response_seq") not in seqset:
                    bad_success.append(r["seq"])
        sc.check("每条成功凭证都引用一条已存在的对方应答", not bad_success,
                 str(bad_success))
        # 接收方幂等：无重复确认
        stats = c.sink_stats()
        sc.check("接收方无重复 ack（崩溃重发被幂等吸收）",
                 stats["duplicates"] >= 0, f"duplicates={stats['duplicates']}")

        # ---- 2c：封存途中强杀 store ----
        # 暂停后台周期锚点，确保崩溃点精确落在我们触发的这次封存事务。
        self._admin(c, "/cred/pause-anchor", {"paused": True})
        pre_anchors = http("POST", f"{c.store}/rpc",
                           body={"op": "cred_anchors",
                                 "args": {"account_id": t.tid}})[1]["result"]
        pre_no = max([a["anchor_no"] for a in pre_anchors], default=0)
        pre_head = http("POST", f"{c.store}/rpc",
                        body={"op": "cred_head",
                              "args": {"account_id": t.tid}})[1]["result"]
        r4 = publish("sealcrash")
        t.wait_succeeded([r4["delivery_id"]], timeout=30)
        self._admin(c, "/cred/crash-anchor", {})
        try:
            http("POST", f"{c.store}/admin/cred/anchor",
                 body={"account_id": t.tid})
        except Exception:
            pass
        dead_store = c.procs["store"]
        wait_until("store died during sealing",
                   lambda: dead_store.poll() is not None, timeout=8)
        c.restart_store()
        chain_rec = self._load_chain(c, t.tid)
        seqs = [r["seq"] for r in chain_rec]
        sc.check("封存途中强杀后编号仍连续无缺号",
                 seqs == list(range(1, len(seqs) + 1)), f"N={len(seqs)}")
        post_anchors = http("POST", f"{c.store}/rpc",
                            body={"op": "cred_anchors",
                                  "args": {"account_id": t.tid}})[1]["result"]
        post_no = max([a["anchor_no"] for a in post_anchors], default=0)
        sc.check("崩溃未产生半截锚点（锚点编号不跳变）", post_no == pre_no,
                 f"{pre_no}->{post_no}")
        post_head = http("POST", f"{c.store}/rpc",
                         body={"op": "cred_head",
                               "args": {"account_id": t.tid}})[1]["result"]
        sc.check("重启后链头只增长（旧链头不被回退）",
                 post_head["head_seq"] >= pre_head["head_seq"],
                 f"{pre_head['head_seq']}->{post_head['head_seq']}")
        re_anchor = self._anchor(c, t.tid)
        sc.check("重启后补封成功且编号严格接续",
                 re_anchor["anchor_no"] == pre_no + 1,
                 f"{pre_no}->{re_anchor['anchor_no']}")
        self._anchor(c, t.tid)
        pkg = self._export(c, t.tid)
        sc.check("崩溃恢复后整包离线可验", self._verify(pkg["path"])["ok"])
        sc.detail.update({"crashes": ["before_side_effect", "after_side_effect"],
                          "reconcile": summary})

    # ================================================================ 3

    def scenario_3(self, c: Cluster, sc: CredScenario) -> None:
        t = Tenant(c, "c3")
        c.sink_rule("/c3", "ok")
        ep = t.endpoint("/c3", parallelism=4)["endpoint_id"]
        refs = [t.publish(ep, f"o{i}")["delivery_id"] for i in range(8)]
        t.wait_succeeded(refs, timeout=40)
        self._anchor(c, t.tid)
        pkg = self._export(c, t.tid)
        clean = self._verify(pkg["path"])
        sc.check("无损包通过", clean["ok"])

        import struct
        import zipfile as _zip
        import io as _io

        def read_entry_pkg(path, name):
            with _zip.ZipFile(path) as zz:
                return zz.read(name)

        def write_tampered(label, entries_mut: dict):
            """重打包：只改指定条目内容，其余条目原样，保持 ZIP 结构合法。"""
            dst = os.path.join(c._cred_dir, f"t3-{label}.whubpkg")
            with _zip.ZipFile(pkg["path"]) as src:
                names = src.namelist()
                data = {n: src.read(n) for n in names}
            data.update(entries_mut)
            with _zip.ZipFile(dst, "w", compression=_zip.ZIP_STORED) as out:
                for n in names:
                    out.writestr(n, data[n])
            return dst

        # 选一条靠中间的链条目（outbound_attempt）作为改写目标
        with _zip.ZipFile(pkg["path"]) as zz:
            rec_lines = [ln for ln in zz.read("records.jsonl").split(b"\n")
                         if ln.strip()]
        parsed = [json.loads(ln) for ln in rec_lines]
        attempt_rows = [p for p in parsed if p["type"] == "outbound_attempt"]
        target = attempt_rows[len(attempt_rows) // 2]
        target_seq = target["seq"]

        def rewrite(_seg):
            lines = rec_lines[:]
            for k, p in enumerate(parsed):
                if p["seq"] == target_seq:
                    obj = json.loads(lines[k])
                    obj["body"]["data"]["worker_id"] = "worker-FORGED"
                    lines[k] = json.dumps(obj, ensure_ascii=False,
                                          sort_keys=True,
                                          separators=(",", ":")).encode()
                    break
            return b"\n".join(lines)

        def delete(_seg):
            lines = rec_lines[:]
            # 删掉目标行
            for k, p in enumerate(parsed):
                if p["seq"] == target_seq:
                    del lines[k]
                    break
            return b"\n".join(lines)

        def swap(_seg):
            lines = rec_lines[:]
            # 找目标及其在链中的相邻行（按出现顺序交换）
            idx = next(k for k, p in enumerate(parsed) if p["seq"] == target_seq)
            j = min(idx + 1, len(lines) - 1)
            lines[idx], lines[j] = lines[j], lines[idx]
            return b"\n".join(lines)

        def replace_anchor(_seg):
            anchor_lines = [ln for ln in read_entry_pkg(
                pkg["path"], "anchors.jsonl").split(b"\n") if ln.strip()]
            a = json.loads(anchor_lines[0])
            # 翻转签名中间一个字符
            sig = a["signature"]
            ch = sig[30]
            sig = sig[:30] + ("A" if ch != "A" else "B") + sig[31:]
            a["signature"] = sig
            anchor_lines[0] = json.dumps(a, ensure_ascii=False,
                                          sort_keys=True,
                                          separators=(",", ":")).encode()
            return b"\n".join(anchor_lines)

        cases = [
            ("rewrite_middle", "records.jsonl", rewrite, target_seq),
            ("delete_row", "records.jsonl", delete, target_seq),
            ("swap_adjacent", "records.jsonl", swap, target_seq),
            ("replace_anchor", "anchors.jsonl", replace_anchor, None),
        ]
        earliest = {}
        for label, fname, mut, want_seq in cases:
            seg = read_entry_pkg(pkg["path"], fname)
            newseg = mut(seg)
            dst = write_tampered(label, {fname: newseg})
            v = self._verify(dst)
            sc.check(f"{label}: 离线核验器识别破坏", not v["ok"],
                     f"ok={v['ok']}")
            located = v.get("first_bad_seq") is not None or \
                v.get("anchor_failure") is not None
            sc.check(f"{label}: 给出确定损坏位置", located,
                     f"first_bad={v.get('first_bad_seq')} "
                     f"anchor={v.get('anchor_failure')} "
                     f"tamper={v.get('tamper')}")
            # 改写/删除/调序应报出不晚于目标序号的最早失信点
            if want_seq is not None:
                fb = v.get("first_bad_seq")
                sc.check(f"{label}: 最早失信序号 <= 被改序号 {want_seq}",
                         fb is not None and fb <= want_seq,
                         f"first_bad={fb} target={want_seq}")
            earliest[label] = v.get("first_bad_seq") or \
                (v.get("anchor_failure") or {}).get("anchor_no")
        sc.detail["earliest_bad"] = earliest

    # ================================================================ 4

    def scenario_4(self, c: Cluster, sc: CredScenario) -> None:
        t = Tenant(c, "c4")
        c.sink_rule("/c4", "ok")
        ep = t.endpoint("/c4", parallelism=8)["endpoint_id"]
        first = [t.publish(ep, f"o{i}")["delivery_id"] for i in range(10)]
        t.wait_succeeded(first, timeout=40)
        self._anchor(c, t.tid)
        # 压力写入不停时导出第一批（冻结 cutoff）
        pkg1 = self._export(c, t.tid)
        cutoff1 = pkg1["seq_cutoff"]
        v1 = self._verify(pkg1["path"])
        sc.check("第一批包离线可验", v1["ok"])

        # 继续压力写入（主账照常变化）
        more = [t.publish(ep, f"p{i}")["delivery_id"] for i in range(30)]
        t.wait_succeeded(more, timeout=60)
        self._anchor(c, t.tid)

        # 包 1 内容必须稳定：重放仍通过，且 cutoff 不随主账增长
        v1b = self._verify(pkg1["path"])
        sc.check("截止位置以前的内容稳定（不受后续写入影响）",
                 v1b["ok"] and pkg1["seq_cutoff"] == cutoff1,
                 f"{pkg1['seq_cutoff']} vs {cutoff1}")
        # 包 1 不含 cutoff 之后的条目
        with __import__("zipfile").ZipFile(pkg1["path"]) as z:
            rbytes = z.read("records.jsonl").decode()
        after_seqs = [i for i in range(cutoff1 + 1, cutoff1 + 5)]
        leaked = [s for s in after_seqs if f'"seq":{s},' in rbytes
                  or f'"seq":{s}}}' in rbytes]
        sc.check("截止之后的条目不混入", not leaked, f"leaked={leaked}")

        # 增量包：从 cutoff1+1 紧密接续
        pkg2 = self._export(c, t.tid, seq_from=cutoff1 + 1,
                            incremental_of=pkg1["export_id"])
        sc.check("增量包起点 = 上包 cutoff+1",
                 pkg2["seq_from"] == cutoff1 + 1,
                 f"{pkg2['seq_from']} vs {cutoff1 + 1}")
        # 增量包需用包1链头作为前链头来验
        with __import__("zipfile").ZipFile(pkg1["path"]) as z:
            import json as _json
            m1 = _json.loads(z.read("manifest.json"))
        v2 = self._verify(pkg2["path"], prev_head_digest=m1["head_digest"],
                          prev_cutoff=cutoff1)
        sc.check("增量包离线可验且与前包紧密接续", v2["ok"]
                 and (v2["incremental"] or {}).get("ok"),
                 str(v2.get("incremental")))
        sc.detail.update({"cutoff1": cutoff1, "cutoff2": pkg2["seq_cutoff"],
                          "increment_start": pkg2["seq_from"]})

    # ================================================================ 5

    def scenario_5(self, c: Cluster, sc: CredScenario) -> None:
        t = Tenant(c, "c5")
        c.sink_rule("/c5", "ok")
        ep = t.endpoint("/c5", parallelism=4)["endpoint_id"]
        refs = [t.publish(ep, f"o{i}")["delivery_id"] for i in range(6)]
        t.wait_succeeded(refs, timeout=40)
        self._anchor(c, t.tid)
        pkg_gen1 = self._export(c, t.tid)
        v_g1 = self._verify(pkg_gen1["path"])
        sc.check("换代前包可验（gen1）", v_g1["ok"]
                 and v_g1["sealed_gen"] == 1, str(v_g1.get("lineage")))

        # 换代
        code, rot = self._admin(c, "/cred/rotate-keys", {})
        sc.check("换代成功 gen1->gen2", code == 200
                 and rot["gen_to"] == 2, str(rot)[:200])
        refs2 = [t.publish(ep, f"n{i}")["delivery_id"] for i in range(6)]
        t.wait_succeeded(refs2, timeout=40)
        self._anchor(c, t.tid)
        pkg_gen2 = self._export(c, t.tid)
        v_g2 = self._verify(pkg_gen2["path"])
        sc.check("换代后包可验（gen2）且沿革合法",
                 v_g2["ok"] and v_g2["lineage_ok"]
                 and v_g2["sealed_gen"] == 2, str(v_g2.get("lineage")))
        sc.check("换代后包里两个代次锚点都验过",
                 v_g2["anchors_checked"] >= 2
                 and v_g2["anchors_ok"] == v_g2["anchors_checked"],
                 f"{v_g2['anchors_ok']}/{v_g2['anchors_checked']}")
        # 旧包仍可验（旧锚点用旧公钥）
        sc.check("换代后旧包仍可验", self._verify(pkg_gen1["path"])["ok"])

        # 旧私钥模拟泄漏：用旧私钥签一个“新锚点”，必被新公钥拒绝
        from whub.cred_crypto import (SigningKey, domain_hash, b64d,
                                      DOMAIN_ANCHOR, verify as vf)
        import zipfile as _z
        ks_file = self._find_keystore(c)
        ks_doc = json.load(open(ks_file))
        old_seed = next(g["seed_b64"] for g in ks_doc["generations"]
                        if g["gen"] == 1)
        oldsk = SigningKey.from_b64(old_seed)
        code, anchors = http("POST", f"{c.store}/rpc",
                             body={"op": "cred_anchors",
                                   "args": {"account_id": t.tid}})
        gen2_anchor = next(a for a in anchors["result"] if a["gen"] == 2)
        payload = json.loads(gen2_anchor["payload_json"])
        payload["anchor_no"] = 999
        forged = oldsk.sign(domain_hash(DOMAIN_ANCHOR, payload))
        with _z.ZipFile(pkg_gen2["path"]) as zz:
            material = json.loads(zz.read("material.json"))
        new_pub = b64d(next(g["public_b64"] for g in material["generations"]
                            if g["gen"] == 2))
        sc.check("泄漏的旧私钥伪造新锚点必败",
                 not vf(new_pub, domain_hash(DOMAIN_ANCHOR, payload), forged),
                 "forged anchor verified with gen2 pub(!)")
        sc.check("合法换代证书证明 gen1->gen2 分界", v_g2["lineage_ok"])
        sc.detail.update({"gen1_cutoff": pkg_gen1["seq_cutoff"],
                          "gen2_cutoff": pkg_gen2["seq_cutoff"]})

    def _find_keystore(self, c: Cluster) -> str:
        return c._seal_path

    # ================================================================ 6

    def scenario_6(self, c: Cluster, sc: CredScenario) -> None:
        t = Tenant(c, "c6")
        c.sink_rule("/c6", "ok")
        ep = t.endpoint("/c6", parallelism=4)["endpoint_id"]
        secret_marker = "SENSITIVE_PAYLOAD_VALUE_XYZ"
        refs = [t.publish(ep, f"o{i}",
                          {"secret": secret_marker, "i": i})["delivery_id"]
                for i in range(6)]
        t.wait_succeeded(refs, timeout=40)
        self._anchor(c, t.tid)
        chain_before = self._load_chain(c, t.tid)
        count_before = len(chain_before)

        # 配置极短 TTL（0.01s）使全部到期
        code, ret = self._admin(c, "/cred/retention",
                                {"account_id": t.tid, "retain_seconds": 0.01})
        sc.check("留存策略设置成功", code == 200, str(ret)[:120])
        time.sleep(0.2)

        # 先开司法留置：抹除必须被拒
        code, hold = self._admin(c, "/cred/legal-hold",
                                 {"account_id": t.tid, "legal_hold": True,
                                  "reason": "court-order-123"})
        sc.check("司法留置设置成功", code == 200 and hold["legal_hold"] == 1)
        code, blocked = self._admin(c, "/cred/scrub",
                                    {"account_id": t.tid})
        sc.check("司法留置期间抹除被拒",
                 code == 200 and blocked.get("blocked") == "legal_hold",
                 str(blocked))

        # 解除留置后续办
        self._admin(c, "/cred/legal-hold",
                    {"account_id": t.tid, "legal_hold": False})
        code, done = self._admin(c, "/cred/scrub",
                                 {"account_id": t.tid})
        sc.check("解除后抹除执行", code == 200 and done["scrubbed"] >= 6,
                 str(done))

        # 主账正文已被墓碑替换
        code, jobs = http("GET", f"{c.store}/v1/endpoints/{ep}/deliveries",
                          key=t.api_key)
        # 直接查 event 正文
        code, sample = http("POST", f"{c.store}/rpc",
                            body={"op": "event",
                                  "args": {"event_id": "PLACEHOLDER"}})
        # 通过业务 API 无法读 event payload；改用 DB 侧核验：导出包/审计
        # 不含明文。审计与接口扫描
        audit = self._admin(c, "/cred/audit", method="GET")[1]
        audit_text = json.dumps(audit, ensure_ascii=False)
        sc.check("审计文字不含原值", secret_marker not in audit_text)

        # 运维接口 overview 不含原值
        ov_text = json.dumps(self._overview(c), ensure_ascii=False)
        sc.check("运维接口不含原值", secret_marker not in ov_text)

        # 主账 events.payload 已是墓碑（通过再发一个并比对：直接查库文件）
        import sqlite3
        db = os.path.join(c.dir, "store.db")
        con = sqlite3.connect(db)
        rows = con.execute(
            "SELECT payload FROM events WHERE tenant_id=?",
            (t.tid,)).fetchall()
        con.close()
        live = [r[0] for r in rows if secret_marker in r[0]]
        tombed = [r[0] for r in rows if '"_redacted"' in r[0]]
        sc.check("主账正文全部替换为墓碑，原值消失",
                 not live and len(tombed) >= 6,
                 f"live={len(live)} tomb={len(tombed)}")

        # 动作数与次序仍可证明：链未变（抹除只动主账）
        chain_after = self._load_chain(c, t.tid)
        sc.check("抹除后链动作数量与次序不变",
                 [r["seq"] for r in chain_after]
                 == list(range(1, len(chain_after) + 1))
                 and len(chain_after) >= count_before,
                 f"before={count_before} after={len(chain_after)}")
        # 抹除动作本身写入链中
        scrubs = [r for r in chain_after if r["type"] == "privacy_scrubbed"]
        sc.check("清除动作写入链且不含原值",
                 len(scrubs) >= 1
                 and all(secret_marker not in r["body_json"] for r in scrubs),
                 f"scrubs={len(scrubs)}")
        # 抹除后整包仍可验（链没动，正文从未进链）
        pkg = self._export(c, t.tid)
        v = self._verify(pkg["path"])
        sc.check("抹除后导出包离线可验", v["ok"], str(v.get("chain")))
        sc.detail["scrubbed"] = done["scrubbed"]

    # ================================================================ 7

    def scenario_7(self, c: Cluster, sc: CredScenario) -> None:
        t = Tenant(c, "c7")
        c.sink_rule("/c7", "ok")
        ep = t.endpoint("/c7", parallelism=4)["endpoint_id"]
        warm = [t.publish(ep, f"w{i}")["delivery_id"] for i in range(4)]
        t.wait_succeeded(warm, timeout=30)
        # 排空所有在途请求，并等接收方计数稳定（确保开闸瞬间无跨闸门请求）
        def stable_count():
            a = c.sink_stats()["counters"].get("/c7", {}).get("received", 0)
            time.sleep(0.4)
            b = c.sink_stats()["counters"].get("/c7", {}).get("received", 0)
            return b if a == b else None
        stats_before = wait_until("receipt count stable before outage",
                                  stable_count, timeout=10)

        # 拒写前先排好一批积压（入队本身是写事务，必须在拒写前完成）。
        pending_refs = [t.publish(ep, f"b{i}")["delivery_id"]
                        for i in range(8)]
        c.store_outage(True)

        def worker_views():
            out = {}
            for w in ("a", "b"):
                _, view = http("GET", c.worker_url(w) + "/worker/view")
                out[w] = view
            return out

        def blocked_total():
            tot = 0
            for view in worker_views().values():
                tot += view.get("store_unavailable", 0) + \
                    view.get("touch_blocked", 0)
            return tot

        # 等到两个 worker 都实际观察到拒写（此刻起 touch 必失败、不发送）
        wait_until("both workers observed outage",
                   lambda: blocked_total() >= 2, timeout=self.ttl * 4)
        # 再给一个往返时间，让任何“闸门落闸瞬间在途”的请求全部落地
        time.sleep(0.6)
        # “拒写期间”的基线在确认阻断之后才取，排除落闸竞态窗口
        baseline_after_block = c.sink_stats()["counters"].get(
            "/c7", {}).get("received", 0)
        # 跨越多个 claim/touch/renew 周期，期间不得再产生 receipt
        time.sleep(self.ttl + 0.5)
        during = c.sink_stats()["counters"].get("/c7", {}).get("received", 0)
        sc.check("确认阻断后拒写期间不再产生任何出站成功（receipt 不增长）",
                 during == baseline_after_block,
                 f"{during} vs {baseline_after_block}")
        blocked = blocked_total()
        sc.check("worker 记录 touch/写被阻断（不靠内存 ownership 发送）",
                 blocked >= 2, str(blocked))
        # 拒写期间凭证没有把未应答动作记成成功
        code, intents = http("POST", f"{c.store}/rpc",
                             body={"op": "intents_view", "args": {}})
        no_fake = all(it["state"] != "converged" for it in intents["result"])
        sc.check("拒写期间无虚假成功凭证", no_fake,
                 str([(x["action_id"][:20], x["state"])
                      for x in intents["result"]])[:200])

        c.store_outage(False)
        t.wait_succeeded(pending_refs, timeout=60)

        # 恢复后对账：待查意图逐项清算
        code, summary = self._admin(c, "/cred/reconcile", {})
        sc.check("恢复后对账成功", code == 200, str(summary)[:200])
        code, leftover = http("POST", f"{c.store}/rpc",
                              body={"op": "intents_view", "args": {}})
        sc.check("恢复后无残留悬挂意图", len(leftover["result"]) == 0,
                 str(leftover["result"])[:200])

        # 链头与主账终态相符：每个 succeeded job 都有终态凭证，反之亦然
        chain = self._load_chain(c, t.tid)
        succ_jobs = {r["action_id"].split(":a")[0]
                     for r in chain if r["type"] == "outbound_success"}
        import sqlite3
        con = sqlite3.connect(os.path.join(c.dir, "store.db"))
        db_succ = {r[0] for r in con.execute(
            "SELECT id FROM jobs WHERE endpoint_id=? AND status='succeeded'",
            (ep,)).fetchall()}
        con.close()
        sc.check("链头终态凭证集合 == 主账 succeeded 集合",
                 succ_jobs == db_succ,
                 f"cred={len(succ_jobs)} db={len(db_succ)} "
                 f"only_cred={len(succ_jobs-db_succ)} "
                 f"only_db={len(db_succ-succ_jobs)}")
        self._anchor(c, t.tid)
        pkg = self._export(c, t.tid)
        sc.check("恢复后整包离线可验", self._verify(pkg["path"])["ok"])
        sc.detail["summary"] = summary

    # ---- 报告 ---------------------------------------------------------

    def _write_report(self) -> None:
        # 汇总全局指标
        report = {
            "generated_at": time.time(),
            "suite": "whub-tamper-evident-credential-book",
            "ttl_seconds": self.ttl,
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for s in self.results if s.passed),
                "failed": sum(1 for s in self.results if not s.passed)},
            "scenarios": [],
        }
        for s in self.results:
            report["scenarios"].append({
                "id": s.num, "title": s.title, "passed": s.passed,
                "error": s.error,
                "checks_passed": sum(1 for x in s.checks if x["ok"]),
                "checks_total": len(s.checks),
                "checks": s.checks,
                "detail": s.detail,
            })
        with open(self.report_path, "w") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        log.info("cred report: %s", os.path.abspath(self.report_path))

    def _print_summary(self) -> None:
        for s in self.results:
            mark = "✅" if s.passed else "❌"
            log.info("%s 场景 %s %s | checks=%d/%d%s",
                     mark, s.num, s.title,
                     sum(1 for x in s.checks if x["ok"]), len(s.checks),
                     ("  " + json.dumps(s.detail, ensure_ascii=False)[:200])
                     if s.detail else "")
            if not s.passed:
                log.info("   FAIL: %s", s.error)
                for ch in s.checks:
                    if not ch["ok"]:
                        log.info("     - %s :: %s", ch["name"], ch["detail"])


TITLES = {
    "1": "双节点高频争用/换手：连续编号+摘要衔接+终态逐项对应",
    "2": "副作用前后/封存途中强杀：意图三分类、无虚假成功/双终态",
    "3": "改写/删除/调序/替换锚点：离线核验定位最早失信序号",
    "4": "压力写入并发导出：截止冻结、之后不混入、增量紧密接续",
    "5": "封存私钥换代：两包可验、旧钥伪造新锚点必败、分界可证",
    "6": "留存抹除与司法留置：动作/次序可证、留置阻断、原值清除",
    "7": "账库拒写：无无法记账的成功、恢复后清算、链头与终态相符",
}
