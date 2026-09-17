"""一致性导出：在主账持续写入时冻结截止序号，产出可离线核验的导出包。

包格式（.whubpkg，本质为无压缩 ZIP + 清单签名）
================================================
* ``material.json`` 公开校验材料：哈希/签名方案、域标签、封存密钥各代公钥、
  换代证书；
* ``records.jsonl`` 从 seq_from 到 seq_cutoff 的链条目，每行一条规范 JSON；
* ``anchors.jsonl`` 截止位置**之前**已封存的锚点（payload+signature）；
* ``manifest.json`` 清单（账户、起止序号、链头、文件 SHA256、前代接续点）；
* ``manifest.sig`` 当前代次私钥对 DOMAIN_MANCHAIN|canonical(manifest) 的签名。

条目文件用 ZIP **STORED（不压缩）** 存放：任意字节损坏可定位到具体
ZIP 条目内字节偏移，进而映射到首个失信序号；核验器不依赖 ZIP 中央
目录的健壮性（中央目录损坏时退化为按本地头顺序扫描）。
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import secrets
import zipfile
from typing import Optional

from .cred_crypto import (
    DOMAIN_MANIFEST, SigningKey, b64e, canonical, domain_hash,
)

log = logging.getLogger("whub.cred_export")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class Exporter:
    def __init__(self, ledger, keystore, sealer):
        self.ledger = ledger
        self.keystore = keystore
        self.sealer = sealer

    @staticmethod
    def _first_record_seq(c, account_id: str, seq_from: int) -> int:
        """增量包纳入的锚点，其链上记录序号必须 >= 起始条目的记录序号。"""
        row = c.execute(
            "SELECT seq FROM cred_records WHERE account_id=? AND seq>=? "
            "ORDER BY seq LIMIT 1", (account_id, seq_from)).fetchone()
        return row["seq"] if row else seq_from

    def export(self, *, account_id: str, out_dir: str,
               seq_from: int = 1, incremental_of: Optional[str] = None,
               prev_head_digest: Optional[str] = None) -> dict:
        """冻结截止序号并打包。主账可同时继续写入（只影响 cutoff 之后）。"""
        os.makedirs(out_dir, exist_ok=True)
        export_id = "exp_" + secrets.token_hex(10)

        # 单事务内读取一致快照并冻结 cutoff（之后的写入绝不混入本包）
        def snapshot(c, now):
            head = c.execute(
                "SELECT head_seq, head_digest FROM cred_accounts "
                "WHERE account_id=?", (account_id,)).fetchone()
            cutoff = head["head_seq"] if head else 0
            if seq_from > cutoff + 1:
                return {"error": "bad_start", "seq_from": seq_from,
                        "cutoff": cutoff}
            first_row = c.execute(
                "SELECT seq FROM cred_records WHERE account_id=? AND seq>=? "
                "ORDER BY seq LIMIT 1", (account_id, seq_from)).fetchone()
            first_rec_row = first_row["seq"] if first_row else seq_from
            rec_rows = [dict(r) for r in c.execute(
                "SELECT * FROM cred_records WHERE account_id=? AND seq>=? "
                "AND seq<=? ORDER BY seq",
                (account_id, seq_from, cutoff)).fetchall()]
            anchor_rows = [dict(a) for a in c.execute(
                "SELECT * FROM cred_anchors WHERE account_id=? "
                "AND record_seq>=? AND seq_upto<=? ORDER BY anchor_no",
                (account_id, first_rec_row, cutoff)).fetchall()]
            return {"cutoff": cutoff,
                    "head_digest": head["head_digest"] if head else None,
                    "records": rec_rows, "anchors": anchor_rows, "now": now}

        snap = self.ledger.transact(snapshot)
        if snap.get("error"):
            return snap
        cutoff = snap["cutoff"]

        # 增量包紧密切入点：默认从作业记录取上一 cutoff 的链头
        if seq_from > 1 and prev_head_digest is None:
            prev_rec = self.ledger.get_record(account_id, seq_from - 1)
            if prev_rec:
                prev_head_digest = prev_rec["digest"]

        material = self.sealer.public_material()
        active_gen = self.ledger.active_generation()
        secret = self.keystore.secret_for(active_gen["gen"])
        sk = SigningKey.from_b64(secret["seed_b64"])

        records_buf = io.BytesIO()
        for r in snap["records"]:
            obj = {"seq": r["seq"], "type": r["type"],
                   "action_id": r["action_id"], "anchor_no": r["anchor_no"],
                   "at": round(r["at"], 6),
                   "body": json.loads(r["body_json"]),
                   "digest": r["digest"], "prev_digest": r["prev_digest"]}
            records_buf.write(canonical(obj) + b"\n")
        records_bytes = records_buf.getvalue()

        anchors_buf = io.BytesIO()
        for a in snap["anchors"]:
            anchors_buf.write(canonical({
                "account": account_id, "anchor_no": a["anchor_no"],
                "gen": a["gen"], "seq_from": a["seq_from"],
                "seq_upto": a["seq_upto"], "digest_upto": a["digest_upto"],
                "record_seq": a["record_seq"], "at": round(a["at"], 6),
                "payload": json.loads(a["payload_json"]),
                "signature": a["signature"]}) + b"\n")
        anchors_bytes = anchors_buf.getvalue()
        material_bytes = canonical(material)

        manifest = {
            "v": 1,
            "export_id": export_id,
            "account": account_id,
            "seq_from": seq_from,
            "seq_cutoff": cutoff,
            "incremental_of": incremental_of,
            "prev_head_digest": prev_head_digest if seq_from > 1 else None,
            "head_digest": snap["head_digest"],
            "record_count": len(snap["records"]),
            "anchor_count": len(snap["anchors"]),
            "files": {
                "records.jsonl": {"sha256": _sha256_bytes(records_bytes),
                                  "bytes": len(records_bytes)},
                "anchors.jsonl": {"sha256": _sha256_bytes(anchors_bytes),
                                  "bytes": len(anchors_bytes)},
                "material.json": {"sha256": _sha256_bytes(material_bytes),
                                  "bytes": len(material_bytes)},
            },
            "sealed_gen": active_gen["gen"],
            "sealed_kid": active_gen["kid"],
            "created_at": round(snap["now"], 6),
        }
        manifest_bytes = canonical(manifest)
        signature = sk.sign(domain_hash(DOMAIN_MANIFEST, manifest))

        path = os.path.join(out_dir, f"{export_id}.whubpkg")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as z:
            z.writestr("records.jsonl", records_bytes)
            z.writestr("anchors.jsonl", anchors_bytes)
            z.writestr("material.json", material_bytes)
            z.writestr("manifest.json", manifest_bytes)
            z.writestr("manifest.sig", signature)

        def record_job(c, now):
            self.ledger.record_export(
                c, now, export_id=export_id, account_id=account_id,
                seq_from=seq_from, seq_cutoff=cutoff,
                incremental_of=incremental_of, path=path, status="complete")
        self.ledger.transact(record_job)
        log.info("export %s account=%s %d..%d records=%d anchors=%d -> %s",
                 export_id, account_id, seq_from, cutoff,
                 len(snap["records"]), len(snap["anchors"]), path)
        return {"export_id": export_id, "path": path, "account": account_id,
                "seq_from": seq_from, "seq_cutoff": cutoff,
                "record_count": len(snap["records"]),
                "anchor_count": len(snap["anchors"]),
                "head_digest": snap["head_digest"],
                "sealed_gen": active_gen["gen"]}
