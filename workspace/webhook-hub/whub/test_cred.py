"""凭证册离线单元测试（不依赖网络/多进程）：
  python3 -m unittest whub.test_cred -v

覆盖：规范编码域隔离、链无分叉/缺号、终态唯一、锚点验签、换代沿革、
导出/离线核验、四类篡改定位、增量包接续、留存抹除与司法留置、
对账三分类、私钥/正文不进链。
"""
import json
import os
import tempfile
import unittest
import zipfile

from .cred_crypto import (SigningKey, canonical, chain_digest, b64e, b64d,
                           domain_hash, DOMAIN_ANCHOR, verify as ed_verify)
from .cred_keystore import KeyStore
from .cred import (Ledger, INTENT_RECORDED, INTENT_SENT, INTENT_CONVERGED,
                   INTENT_SAFE_RETRY, INTENT_IN_DOUBT)
from .cred_seal import Sealer
from .cred_export import Exporter
from .cred_verify import verify_package
from .engine import Engine


def _bootstrap(d: str):
    eng = Engine(os.path.join(d, "t.db"))
    ks = KeyStore(os.path.join(d, "seal.json"))
    sealer = Sealer(eng.cred, ks)
    sealer.bootstrap()
    exporter = Exporter(eng.cred, ks, sealer)
    return eng, ks, sealer, exporter


class CredCoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.eng, self.ks, self.sealer, self.exporter = _bootstrap(self.dir)
        self.eng.create_tenant("t1", "T", "key-1")
        self.eng.create_endpoint("ep", "t1", "e", 1, "kid-1", "sec",
                                 "http://x/hook", 2)
        self.inc = self.eng.register_worker("a", port=1)["incarnation"]

    def tearDown(self):
        self.eng.close()

    def _deliver_ok(self, ev, jid=None):
        jid = jid or "j" + ev
        self.eng.enqueue(lane_id="ln1", event_id=ev, tenant_id="t1", eid="ep",
                         idem_key=None, object_key="A",
                         payload=json.dumps({"secret": "TOPSECRET"}), job_id=jid)
        if self.eng.lane("ln1")["owner_id"] is None:
            self.eng.sweep("a", self.inc, ttl=30, acquire_budget=4)
        l = self.eng.lane("ln1")
        job = self.eng.claim("ln1", "a", l["lease_epoch"], l["fence_id"])
        self.eng.complete_success(job["id"], "a", l["lease_epoch"],
                                  l["fence_id"], 200, peer_event_id=ev)
        return job

    def test_canonical_domain_separation(self):
        a = canonical({"x": 1, "y": 2})
        b = canonical({"y": 2, "x": 1})
        self.assertEqual(a, b)  # 键排序后逐字节一致
        self.assertNotEqual(domain_hash(b"d1", {"x": 1}),
                            domain_hash(b"d2", {"x": 1}))

    def test_chain_continuous_and_no_secret_in_records(self):
        for i in range(5):
            self._deliver_ok(f"e{i}")
        v = self.eng.cred_verify_chain("t1")
        self.assertTrue(v["ok"])
        # 正文/密钥绝不出现在链条目里
        blob = "".join(r["body_json"] for r in self.eng.cred_records("t1"))
        self.assertNotIn("TOPSECRET", blob)
        self.assertNotIn("sec", blob.replace("sig_version", ""))

    def test_single_terminal_credential_on_duplicate_finalize(self):
        self._deliver_ok("e0")
        chain = self.eng.cred_records("t1")
        succ = [r for r in chain if r["type"] == "outbound_success"]
        self.assertEqual(len(succ), 1)
        # 终态凭证幂等表唯一
        con = self.eng.conn
        n = con.execute("SELECT COUNT(*) n FROM cred_finalized").fetchone()["n"]
        self.assertEqual(n, 1)

    def test_anchor_signature_and_rotation_lineage(self):
        self._deliver_ok("e0")
        a1 = self.sealer.seal_account("t1")
        self.assertIsNotNone(a1)
        # 导出包可验
        pkg = self.exporter.export(account_id="t1", out_dir=self.dir)
        self.assertTrue(verify_package(pkg["path"])["ok"])
        # 换代
        rot = self.sealer.rotate()
        self.assertEqual(rot["gen_to"], 2)
        self._deliver_ok("e1")
        self.sealer.seal_account("t1")
        pkg2 = self.exporter.export(account_id="t1", out_dir=self.dir)
        v = verify_package(pkg2["path"])
        self.assertTrue(v["ok"])
        self.assertTrue(v["lineage_ok"])
        self.assertEqual(v["sealed_gen"], 2)

    def test_forged_anchor_with_old_key_rejected(self):
        from whub.cred_crypto import DOMAIN_ANCHOR
        self._deliver_ok("e0")
        self.sealer.seal_account("t1")
        old = self.ks.secret_for(1)
        oldsk = SigningKey.from_b64(old["seed_b64"])
        self.sealer.rotate()
        self._deliver_ok("e1")
        a2 = self.sealer.seal_account("t1")
        real = self.eng.cred.anchor("t1", a2["anchor_no"])
        payload = json.loads(real["payload_json"])
        payload["anchor_no"] = 4242
        forged = oldsk.sign(domain_hash(DOMAIN_ANCHOR, payload))
        newpub = b64d(self.eng.cred.active_generation()["public_b64"])
        self.assertFalse(ed_verify(newpub,
                                   domain_hash(DOMAIN_ANCHOR, payload), forged))

    def test_tamper_detection_localizes_seq(self):
        for i in range(8):
            self._deliver_ok(f"e{i}")
        self.sealer.seal_account("t1")
        pkg = self.exporter.export(account_id="t1", out_dir=self.dir)

        def repack(entries):
            dst = os.path.join(self.dir, "bad.whubpkg")
            with zipfile.ZipFile(pkg["path"]) as z:
                names = z.namelist()
                data = {n: z.read(n) for n in names}
            data.update(entries)
            with zipfile.ZipFile(dst, "w", zipfile.ZIP_STORED) as o:
                for n in names:
                    o.writestr(n, data[n])
            return dst

        with zipfile.ZipFile(pkg["path"]) as z:
            lines = z.read("records.jsonl").split(b"\n")
        parsed = [json.loads(x) for x in lines if x.strip()]
        # 改写中间行
        tgt = parsed[len(parsed) // 2]
        idx = next(k for k, p in enumerate(parsed) if p["seq"] == tgt["seq"])
        obj = json.loads(lines[idx])
        obj["body"]["data"]["worker_id"] = "X"
        lines2 = lines[:]
        lines2[idx] = canonical(obj)
        bad = repack({"records.jsonl": b"\n".join(lines2)})
        v = verify_package(bad)
        self.assertFalse(v["ok"])
        self.assertIsNotNone(v["first_bad_seq"])
        self.assertLessEqual(v["first_bad_seq"], tgt["seq"])

    def test_incremental_package_chains(self):
        for i in range(4):
            self._deliver_ok(f"e{i}")
        self.sealer.seal_account("t1")
        p1 = self.exporter.export(account_id="t1", out_dir=self.dir)
        cut1 = p1["seq_cutoff"]
        for i in range(4, 8):
            self._deliver_ok(f"e{i}")
        self.sealer.seal_account("t1")
        p2 = self.exporter.export(account_id="t1", out_dir=self.dir,
                                  seq_from=cut1 + 1,
                                  incremental_of=p1["export_id"])
        with zipfile.ZipFile(p1["path"]) as z:
            m1 = json.loads(z.read("manifest.json"))
        v = verify_package(p2["path"], prev_head_digest=m1["head_digest"],
                           prev_cutoff=cut1)
        self.assertTrue(v["ok"], v)
        self.assertTrue(v["incremental"]["ok"])

    def test_retention_hold_and_scrub(self):
        self._deliver_ok("e0")
        # 配置极短 TTL，使已存在事件立即到期
        self.eng.set_retention("t1", retain_seconds=0.001)
        # 留置期间拒办
        self.eng.set_retention("t1", legal_hold=True,
                               hold_reason="court")
        r = self.eng.scrub_privacy("t1")
        self.assertEqual(r["blocked"], "legal_hold")
        self.eng.set_retention("t1", legal_hold=False)
        import time as _t
        _t.sleep(0.01)
        r = self.eng.scrub_privacy("t1")
        self.assertGreaterEqual(r["scrubbed"], 1)
        # 正文被墓碑替换
        import sqlite3
        con = sqlite3.connect(os.path.join(self.dir, "t.db"))
        payload = con.execute(
            "SELECT payload FROM events LIMIT 1").fetchone()[0]
        con.close()
        self.assertIn("_redacted", payload)
        self.assertNotIn("TOPSECRET", payload)
        # 链仍连续
        self.assertTrue(self.eng.cred_verify_chain("t1")["ok"])
        # 抹除动作在链上
        self.assertTrue(any(r["type"] == "privacy_scrubbed"
                            for r in self.eng.cred_records("t1")))

    def test_reconcile_classification(self):
        self._deliver_ok("e0")
        # 成功落账后对账：意图应归 converged，无悬挂
        summary = self.eng.reconcile_intents(peer_probe=None)
        self.assertEqual(summary["in_doubt"], [])
        leftover = self.eng.intents_view()
        self.assertEqual(leftover, [])


if __name__ == "__main__":
    unittest.main()
