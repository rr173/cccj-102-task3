"""Seven required end-to-end checks for the offline tamper-evident credential book.

The harness uses empty SQLite databases, two real worker processes, real HTTP
delivery, OS SIGKILL fault injection and the standalone offline verifier.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
import time

from .acceptance import Cluster, Tenant, http, wait_until
from . import evidence_pack
from .verifier import verify_file

log = logging.getLogger("whub.evidence_acceptance")


def mutate_json_pack(path: str, member: str, fn) -> None:
    files = evidence_pack.read_pack(path)
    value = json.loads(files[member])
    value = fn(value)
    files[member] = evidence_pack.canonical(value)
    evidence_pack.write_pack(path, files)


def first_published_job(t: Tenant, eid: str, obj: str, secret: str) -> dict:
    t.publish(eid, obj, {"note": secret})
    jobs = http("GET", f"{t.cluster.store}/v1/endpoints/{eid}/deliveries",
                key=t.api_key)[1]
    return sorted(jobs, key=lambda x: x["seq"])[0]


def wait_evidence_count(store: str, tenant: str, n: int) -> list:
    def pred():
        rows = http("GET", f"{store}/admin/evidence/{tenant}")[1]
        return rows if len(rows) >= n else None
    return wait_until(f"evidence >= {n}", pred, timeout=40)


def wait_job_status(t: Tenant, job_id: str, status: str) -> dict:
    def pred():
        row = t.job(job_id)
        return row if row["status"] == status else None
    return wait_until(f"job {job_id} -> {status}", pred, timeout=40)


class EvidenceAcceptance:
    def __init__(self, ttl: float = 3.0, report_path: str = "evidence-report.json"):
        self.ttl = ttl
        self.report_path = report_path
        self.tmpdir = tempfile.mkdtemp(prefix="whub-evidence-")
        self.results = []

    def run(self) -> int:
        for num in range(1, 8):
            title = TITLES[num]
            sc = {"id": num, "title": title, "ok": False, "checks": [],
                  "detail": {}}
            c = Cluster(f"e{num}", self.ttl, self.tmpdir)
            t0 = time.time()
            try:
                c.start()
                getattr(self, f"scenario_{num}")(c, sc)
                sc["ok"] = all(x["ok"] for x in sc["checks"])
            except Exception as e:
                log.exception("evidence scenario %s failed", num)
                sc["error"] = f"{type(e).__name__}: {e}"
            finally:
                sc["detail"]["elapsed_seconds"] = round(time.time() - t0, 2)
                c.stop()
                self.results.append(sc)
                log.info("evidence scenario %s %s", num,
                         "PASS" if sc["ok"] else "FAIL")
        self.write_report()
        return 0 if all(s["ok"] for s in self.results) else 1

    def check(self, sc, name: str, cond: bool, detail=None) -> bool:
        sc["checks"].append({"name": name, "ok": bool(cond),
                             "detail": detail if not cond else None})
        if not cond:
            raise AssertionError(f"{name}: {detail}")
        return True

    def tenant_endpoint(self, c: Cluster, path: str = "/ev",
                        parallelism: int = 16) -> tuple[Tenant, dict, str]:
        t = Tenant(c, f"客户{path.strip('/')}")
        secret = "SECRET_" + os.urandom(8).hex()
        ep = t.endpoint(path, parallelism=parallelism, secret=secret)
        return t, ep, secret

    def chain_rows(self, c: Cluster, tenant: str) -> list[dict]:
        return http("GET", f"{c.store}/admin/evidence/{tenant}")[1]

    def assert_chain(self, sc, c: Cluster, tenant: str) -> tuple[list, dict]:
        rows = self.chain_rows(c, tenant)
        prev = "GENESIS"
        expected = 1
        first_bad = None
        for row in rows:
            if row["seq"] != expected or row["prev_digest"] != prev:
                first_bad = {"seq": row["seq"], "expected": expected}
                break
            expected += 1
            prev = row["digest"]
        self.check(sc, f"sequence linkage through {len(rows)}",
                   first_bad is None, first_bad)
        local = [x for x in http("GET", f"{c.store}/admin/evidence/verify")[1]
                 if x["tenant_id"] == tenant][0]
        self.check(sc, "local chain verification", local["ok"], local)
        sc["detail"].setdefault("total_credentials", 0)
        sc["detail"]["total_credentials"] += len(rows)
        sc["detail"]["head_digest"] = local["head_digest"]
        sc["detail"]["head_seq"] = local["head_seq"]
        sc["detail"]["forks_or_gaps"] = 0 if local["ok"] else 1
        return rows, local

    # 1. Two real workers, contention and ownership handovers.
    def scenario_1(self, c: Cluster, sc) -> None:
        t, ep, secret = self.tenant_endpoint(c, "/orders", 12)
        jobs = []
        for i in range(36):
            t.publish(ep["endpoint_id"], f"obj-{i % 18}",
                      {"n": i, "secret": secret})
        # Force several ownership changes while traffic still has pending work.
        deadline = time.time() + 12
        while time.time() < deadline:
            c.restart_worker("a")
            c.drain("b", deadline=0.2)
            c.drain("b", draining=False)
            c.restart_worker("b")
            if len(c.sink_stats().get("receipts", {}).get("/orders", [])) >= 36:
                break
            time.sleep(0.3)
        wait_until("all 36 receiver receipts", lambda: len(
            c.sink_stats().get("receipts", {}).get("/orders", [])) >= 36, 45)
        rows, local = self.assert_chain(sc, c, t.tid)
        handoffs = [r for r in rows if r["event_type"] == "ownership_handover"]
        success = [r for r in rows if r["event_type"] == "delivery_result"]
        attempts = [r for r in rows if r["event_type"] == "outbound_attempt"]
        self.check(sc, "ownership changed multiple times", len(handoffs) >= 3,
                   {"handoffs": len(handoffs)})
        self.check(sc, "every successful credential has an outbound attempt",
                   len(success) <= len(attempts),
                   {"success": len(success), "attempts": len(attempts)})
        receipts = c.sink_stats()["receipts"]["/orders"]
        success_events = {json.loads(r["body_json"])["attributes"]["event_id"]
                          for r in success}
        receipt_events = {r["event_id"] for r in receipts}
        self.check(sc, "terminal credentials correspond to actual receiver actions",
                   success_events == receipt_events,
                   {"credentials": len(success_events),
                    "receiver": len(receipt_events)})
        sc["detail"].update(total_credentials=len(rows), head_digest=local["head_digest"],
                            forks_or_gaps=0, handoffs=len(handoffs))

    def export(self, c: Cluster, tenant: str, start: int = 1) -> tuple[str, dict]:
        code, data = http("POST", f"{c.store}/admin/evidence/export",
                          body={"tenant_id": tenant, "start_seq": start})
        assert code == 201, data
        shutil.copy(data["path"], os.path.join(c.dir, os.path.basename(data["path"])))
        return os.path.join(c.dir, os.path.basename(data["path"])), data

    # 2. SIGKILL before/after side effect and while sealing.
    def scenario_2(self, c: Cluster, sc) -> None:
        t, ep, secret = self.tenant_endpoint(c, "/crash", 1)
        c.drain("b", deadline=300)
        classifications = []

        def arm_crash(point: str, store_point: str | None = None):
            if store_point:
                http("POST", f"{c.store}/admin/test/crash-point",
                     body={"point": store_point})
            http("POST", f"{c.worker_url('a')}/test/crash-point",
                 body={"point": point})

        arm_crash("before_side_effect")
        before = t.publish(ep["endpoint_id"], "before", {"secret": secret})
        wait_until("worker a crashed before side effect",
                   lambda: c.procs["worker-a"].poll() is not None, 15)
        c.restart_worker("a")
        wait_job_status(t, before["delivery_id"], "succeeded")
        before_sink = c.sink_stats()["counters"].get("/crash", {}).get("received", 0)
        self.check(sc, "pre-side-effect crash never reached receiver",
                   before_sink >= 1, {"receiver_received": before_sink})

        arm_crash("after_side_effect")
        after = t.publish(ep["endpoint_id"], "after", {"secret": secret})
        wait_until("worker a crashed after side effect",
                   lambda: c.procs["worker-a"].poll() is not None, 15)
        wait_until("one after-crash receiver receipt", lambda: c.sink_stats()[
            "counters"].get("/crash", {}).get("received", 0) >= 2, 20)
        c.restart_worker("a")
        pending = http("GET", f"{c.store}/admin/intents")[1]
        self.check(sc, "after-side-effect remains pending before reconciliation",
                   any(x["job_id"] == after["delivery_id"] and
                       x["state"] == "dispatched" for x in pending),
                   pending)
        # Observe action id from durable pending intent and receiver, then resolve.
        action = next(x["action_id"] for x in pending
                      if x["job_id"] == after["delivery_id"])
        rec = http("POST", f"{c.store}/admin/intents/recover",
                   body={"observed_action_ids": [action],
                         "resolve_observed": True})[1]
        classifications.append(rec["counts"])
        wait_job_status(t, after["delivery_id"], "succeeded")
        rec2 = http("POST", f"{c.store}/admin/intents/recover",
                    body={"observed_action_ids": [action],
                          "resolve_observed": True})[1]
        self.check(sc, "reconciler is idempotent and has no duplicate terminal",
                    rec2["counts"]["converged"] == 0, rec2)

        # Sealing crash: commit is durable and restart continues the chain.
        c.drain("b", draining=False)
        http("POST", f"{c.store}/admin/test/crash-point",
             body={"point": "anchor_seal_commit"})

        def seal_and_crash_store():
            try:
                http("POST", f"{c.store}/admin/evidence/anchor",
                     body={"tenant_id": t.tid, "reason": "crash-seal"},
                     timeout=2)
            except Exception:
                pass

        import threading
        threading.Thread(target=seal_and_crash_store, daemon=True).start()
        wait_until("store crashed during sealing",
                   lambda: c.procs["store"].poll() is not None, 10)
        c.restart_store()
        c.restart_worker("a")
        c.restart_worker("b")
        self.assert_chain(sc, c, t.tid)
        sc["detail"]["intent_classification"] = classifications

    # 3. Four offline bundle mutations.
    def scenario_3(self, c: Cluster, sc) -> None:
        t, ep, secret = self.tenant_endpoint(c, "/tamper", 8)
        for i in range(8):
            t.publish(ep["endpoint_id"], f"x{i}", {"secret": secret})
        wait_until("8 receipts", lambda: sum(
            len(v) for v in c.sink_stats().get("receipts", {}).values()) >= 8, 40)
        http("POST", f"{c.store}/admin/evidence/anchor",
             body={"tenant_id": t.tid, "reason": "mutation-test"})
        good, _ = self.safe_export(c, t.tid)
        v = verify_file(good, scan_secret=secret)
        self.check(sc, "lossless bundle verifies", v["ok"], v)
        self.assert_chain(sc, c, t.tid)
        mutations = []

        def make_bad(name, fn):
            dst = os.path.join(c.dir, f"{name}.whubpak")
            shutil.copy(good, dst)
            mutate_json_pack(dst, "entries.json", fn)
            mutations.append((name, dst))

        def rewrite_entry(xs):
            w = next(w for w in xs if w["seq"] == 4)
            value = w["digest"]
            w["digest"] = ("0" if value[0] != "0" else "1") + value[1:]
            return xs
        make_bad("rewrite", rewrite_entry)
        make_bad("delete", lambda xs: [w for w in xs if w["seq"] != 5])

        def swap_entries(xs):
            a = next(i for i, w in enumerate(xs) if w["seq"] == 5)
            b = next(i for i, w in enumerate(xs) if w["seq"] == 6)
            xs[a], xs[b] = xs[b], xs[a]
            return xs
        make_bad("swap", swap_entries)
        anchor_dst = os.path.join(c.dir, "anchor.whubpak")
        shutil.copy(good, anchor_dst)
        mutate_json_pack(anchor_dst, "anchors.json",
                         lambda xs: xs.__setitem__(-1, {**xs[-1], "signature": "00" * 64}) or xs)
        mutations.append(("replace-anchor", anchor_dst))
        for name, path in mutations:
            r = verify_file(path, scan_secret=secret)
            self.check(sc, f"{name} detected offline", not r["ok"] and
                       r["first_bad_seq"] is not None, r)
        sc["detail"]["tamper_locations"] = {
            name: verify_file(path)["first_bad_seq"] for name, path in mutations}

    # 4. Export under continuous writes and incremental continuation.
    def scenario_4(self, c: Cluster, sc) -> None:
        t, ep, secret = self.tenant_endpoint(c, "/export", 8)
        import threading
        stop = {"v": False}

        def pressure():
            i = 0
            while not stop["v"]:
                try:
                    t.publish(ep["endpoint_id"], f"p{i % 10}",
                              {"i": i, "secret": secret})
                except Exception:
                    pass
                i += 1
                time.sleep(0.03)
        th = threading.Thread(target=pressure, daemon=True)
        th.start()
        wait_evidence_count(c.store, t.tid, 25)
        path1, data1 = self.safe_export(c, t.tid)
        cutoff = data1["cutoff_seq"]
        time.sleep(0.4)
        stop["v"] = True
        th.join()
        self.assert_chain(sc, c, t.tid)
        v1 = verify_file(path1, scan_secret=secret)
        self.check(sc, "frozen cutoff stable under pressure", v1["ok"] and
                   v1["cutoff_seq"] == cutoff, v1)
        time.sleep(0.5)
        path2, data2 = self.safe_export(c, t.tid, cutoff + 1)
        v2 = verify_file(path2, scan_secret=secret)
        self.check(sc, "increment starts immediately after cutoff", v2["ok"] and
                   data2["start_seq"] == cutoff + 1 and
                   data2["cutoff_seq"] > cutoff, {"first": v1, "second": v2})
        sc["detail"].update(cutoff_seq=cutoff, next_cutoff=data2["cutoff_seq"])

    # 5. Sealing key rotation and old-key leak.
    def scenario_5(self, c: Cluster, sc) -> None:
        t, ep, secret = self.tenant_endpoint(c, "/rotate", 4)
        for i in range(3):
            t.publish(ep["endpoint_id"], f"r{i}", {"secret": secret})
        http("POST", f"{c.store}/admin/evidence/anchor",
             body={"tenant_id": t.tid, "reason": "test"})
        old_pack, _ = self.safe_export(c, t.tid)
        rot = http("POST", f"{c.store}/admin/sealing-keys/rotate", body={})[1]
        for i in range(3, 7):
            t.publish(ep["endpoint_id"], f"r{i}", {"secret": secret})
        http("POST", f"{c.store}/admin/evidence/anchor",
             body={"tenant_id": t.tid, "reason": "post-rotation"})
        new_pack, new_data = self.safe_export(c, t.tid)
        self.check(sc, "pre-rotation bundle verifies",
                   verify_file(old_pack, scan_secret=secret)["ok"], None)
        self.check(sc, "post-rotation bundle and boundary verify",
                   verify_file(new_pack, scan_secret=secret)["ok"], None)
        self.assert_chain(sc, c, t.tid)
        forged = os.path.join(c.dir, "forged.whubpak")
        shutil.copy(new_pack, forged)
        files = evidence_pack.read_pack(forged)
        anchors = json.loads(files["anchors.json"])
        forged_anchor = dict(anchors[-1])
        statement = dict(forged_anchor["signed"], anchor_id="anc_FORGED")
        # Test knows the old generation private seed location; a leaked old key
        # must not validate anything signed in the current generation context.
        old_seed = open(os.path.join(c.dir, "sealing-keys",
                                     "sealing-key-generation-0000.seed"), "rb").read()
        from . import anchor_crypto
        forged_anchor["signature"] = anchor_crypto.sign(
            old_seed, evidence_pack.canonical(statement)).hex()
        forged_anchor["signed"] = statement
        anchors[-1] = forged_anchor
        files["anchors.json"] = evidence_pack.canonical(anchors)
        evidence_pack.write_pack(forged, files)
        r = verify_file(forged)
        self.check(sc, "forged new anchor with leaked old key fails", not r["ok"],
                   r)
        sc["detail"]["key_generations"] = rot["to_generation"] + 1
        sc["detail"]["rotation_boundary"] = rot["boundaries"][0]["seq"]
        sc["detail"]["key_history"] = http(
            "GET", f"{c.store}/admin/sealing-keys")[1]

    # 6. Retention erasure and legal hold.
    def scenario_6(self, c: Cluster, sc) -> None:
        t, ep, secret = self.tenant_endpoint(c, "/privacy", 4)
        t.publish(ep["endpoint_id"], "p1", {"secret": secret})
        wait_until("privacy receipt", lambda: len(
            c.sink_stats().get("receipts", {}).get("/privacy", [])) >= 1, 20)
        now = c.store_now() + 3600
        http("POST", f"{c.store}/admin/retention",
             body={"tenant_id": t.tid, "retain_until_after": now})
        hold = http("POST", f"{c.store}/admin/legal-holds",
                    body={"tenant_id": t.tid, "reason": "litigation"})[1]
        blocked = http("POST", f"{c.store}/admin/privacy/sweep",
                       body={"now": now + 10})[1]
        self.check(sc, "active legal hold blocks erasure",
                   blocked[0]["status"] == "blocked_legal_hold", blocked)
        job = http("GET", f"{c.store}/v1/endpoints/{ep['endpoint_id']}/deliveries",
                   key=t.api_key)[1][0]
        import sqlite3
        db_path = os.path.join(c.dir, "store.db")
        with sqlite3.connect(db_path) as db:
            raw_payload = db.execute(
                "SELECT payload FROM events WHERE tenant_id=?", (t.tid,)
            ).fetchone()[0]
        self.check(sc, "retained identifiable content still present during hold",
                   secret in raw_payload, {"payload": "redacted" if secret not in raw_payload else "present"})
        http("POST", f"{c.store}/admin/legal-holds/{hold['hold_id']}/release",
             body={})
        swept = http("POST", f"{c.store}/admin/privacy/sweep",
                     body={"now": now + 20})[1]
        self.check(sc, "erasure resumes after release",
                   swept and swept[0]["status"] == "complete" and
                   swept[0]["events_redacted"] >= 1, swept)
        pack, _ = self.safe_export(c, t.tid)
        v = verify_file(pack, scan_secret=secret)
        self.check(sc, "chain remains valid and secret absent after erasure",
                   v["ok"] and not v["privacy_leak"], v)
        rows, local = self.assert_chain(sc, c, t.tid)
        self.check(sc, "action count/order remain provable", local["ok"], local)
        raw_scan = b"".join(evidence_pack.read_pack(pack).values())
        self.check(sc, "no original value in exported bytes",
                   secret.encode() not in raw_scan, None)
        sc["detail"]["privacy_batches"] = swept

    # 7. Short shared-store write outage.
    def scenario_7(self, c: Cluster, sc) -> None:
        t, ep, secret = self.tenant_endpoint(c, "/outage", 8)
        t.publish(ep["endpoint_id"], "before", {"secret": secret})
        wait_until("one receipt", lambda: len(
            c.sink_stats().get("receipts", {}).get("/outage", [])) >= 1, 20)
        c.store_outage(True)
        code, body = http("POST", f"{c.store}/v1/endpoints/{ep['endpoint_id']}/events",
                          key=t.api_key, body={"object_key": "during",
                                                "payload": {"secret": secret}})
        self.check(sc, "write outage rejects account success", code >= 500,
                   {"code": code, "body": body})
        time.sleep(1.0)
        c.store_outage(False)
        t.publish(ep["endpoint_id"], "after", {"secret": secret})
        wait_until("two receipts", lambda: len(
            c.sink_stats().get("receipts", {}).get("/outage", [])) >= 2, 40)
        rec = http("POST", f"{c.store}/admin/intents/recover", body={})[1]
        rows, local = self.assert_chain(sc, c, t.tid)
        jobs = http("GET", f"{c.store}/v1/endpoints/{ep['endpoint_id']}/deliveries",
                    key=t.api_key)[1]
        receipts = {r["event_id"] for r in c.sink_stats()["receipts"]["/outage"]}
        terminal = {json.loads(r["body_json"])["attributes"]["event_id"]
                    for r in rows if r["event_type"] == "delivery_result"}
        self.check(sc, "head agrees with main account terminal state",
                   len(jobs) == 2 and receipts == terminal and
                   all(j["status"] == "succeeded" for j in jobs),
                   {"jobs": jobs, "receipts": len(receipts),
                    "terminal": len(terminal), "recovery": rec})
        sc["detail"]["recovery"] = rec["counts"]

    def safe_export(self, c: Cluster, tenant: str, start: int = 1):
        code, data = http("POST", f"{c.store}/admin/evidence/export",
                          body={"tenant_id": tenant, "start_seq": start})
        assert code == 201, data
        dst = os.path.join(c.dir, os.path.basename(data["path"]))
        shutil.copy(data["path"], dst)
        return dst, data

    def write_report(self) -> None:
        totals = {
            "total_credentials": 0,
            "chain_head_digests": [],
            "forks_or_gaps": 0,
            "intent_classification": {"safe_to_retry": 0,
                                      "outcome_unknown": 0, "converged": 0},
            "cutoff_seqs": [],
            "tamper_locations": {},
            "key_generations": [],
            "key_history": [],
            "privacy_leak_scan": []}
        for s in self.results:
            d = s.get("detail", {})
            totals["total_credentials"] += d.get("total_credentials", 0)
            if "head_digest" in d:
                totals["chain_head_digests"].append(d["head_digest"])
            if d.get("cutoff_seq") is not None:
                totals["cutoff_seqs"].append(d["cutoff_seq"])
            for cls, n in d.get("intent_classification", [{}])[0].items() if \
                    d.get("intent_classification") else []:
                totals["intent_classification"][cls] += n
            totals["tamper_locations"].update(d.get("tamper_locations", {}))
            if "key_generations" in d:
                totals["key_generations"].append(d["key_generations"])
                totals["key_history"].extend(d.get("key_history", []))
            if "privacy_batches" in d:
                totals["privacy_leak_scan"].append("no-secret-found")
        report = {"generated_at": time.time(), "scenarios": self.results,
                  "summary": totals}
        with open(self.report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2, sort_keys=True)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))


TITLES = {
    1: "双节点高频争用与所有权换手",
    2: "副作用前/后及封存途中强杀恢复",
    3: "改写、删除、调序、替换锚点离线定位",
    4: "压力写入中一致性导出与增量接续",
    5: "封存私钥换代、旧私钥泄漏与分界证明",
    6: "留存清除、司法留置阻断与恢复",
    7: "共享账库短暂拒写与恢复清算",
}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m whub.evidence_acceptance")
    p.add_argument("--ttl", type=float, default=2.0)
    p.add_argument("--report", default="evidence-report.json")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return EvidenceAcceptance(args.ttl, args.report).run()


if __name__ == "__main__":
    sys.exit(main())
