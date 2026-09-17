"""封存器：周期锚点与封存私钥换代。

锚点（anchor）
==============
每个客户账户周期性封存一次：签名者取账户自上一锚点之后的全部链条目，
把它们的摘要列表与链头收进 payload，用**当前代次**的封存私钥做
Ed25519 签名（域 ``DOMAIN_ANCHOR``），锚点本身作为一条 ``anchor`` 记录
追加进同一条链，并写 ``cred_anchors`` 行——全部在一个写事务内。

锚点签名覆盖的不是正文（正文从未进链），而是条目摘要序列，因此它向
离线核验者证明：截至某序号，链头被某个私钥代次亲眼封存过。

换代（rotation）
================
新代次由 keystore 生成；**旧代次私钥**对一张证书签名
（域 ``DOMAIN_ROTATION``，含两代公钥与 nonce）。证书落库、
旧代次 active->0、新代次 active=1、链上 ``key_rotation`` 记录在
同一事务内。规则：

* 旧锚点永远可用旧公钥核验（公钥随导出包公开）；
* 换代后新锚点只认当前代次（旧私钥签出的“新锚点”验签必败）；
* 合法沿革（旧私钥签的换代证书）证明两代之间的分界。
"""
from __future__ import annotations

import logging
import secrets
from typing import Optional

from .cred_crypto import (
    DOMAIN_ANCHOR, DOMAIN_ROTATION, SigningKey, b64d, b64e, canonical,
    domain_hash, verify,
)
from .cred import (
    METRIC_ANCHOR, RECORD_ANCHOR, RECORD_ROTATION, Ledger, LedgerError,
)

log = logging.getLogger("whub.cred_seal")

# 换代证书作为系统账户链上的一条记录（同时冗余进每账户包的公开材料）
SYSTEM_ACCOUNT = "__keylineage__"


class Sealer:
    def __init__(self, ledger: Ledger, keystore):
        self.ledger = ledger
        self.keystore = keystore

    # ---- 启动引导 / 对账 ---------------------------------------------

    def bootstrap(self) -> int:
        """确保库与 keystore 至少有一个对齐的当前代次。返回当前代号。"""
        active = self.ledger.active_generation()
        if active is None:
            secret = self.keystore.active()
            sk = SigningKey.from_b64(secret["seed_b64"])
            self.ledger.ensure_genesis_generation(sk)
            active = self.ledger.active_generation()
            log.info("cred sealing genesis generation gen=%s kid=%s",
                     active["gen"], active["kid"])
        else:
            self._reconcile(active)
        return active["gen"]

    def _reconcile(self, active: dict) -> None:
        """库内已有代次：确保 keystore 至少持有库当前代次私钥。

        以**库**为权威（库是多节点共享状态；keystore 是节点本地文件）。
        若本节点 keystore 缺当前代次私钥（例如另一节点完成了换代），
        本节点不能封存新锚点——封存操作会在取私钥时显式失败，而不是
        误用旧代次签出新锚点。
        """
        try:
            self.keystore.secret_for(active["gen"])
        except KeyError:
            log.warning("local keystore lacks sealing gen %s; this node "
                        "cannot seal new anchors until key material arrives",
                        active["gen"])

    # ---- 周期锚点 -----------------------------------------------------

    def seal_account(self, account_id: str, *, force: bool = False) -> Optional[dict]:
        """为单个账户封存一个锚点。无新增条目时返回 None（force 可覆盖）。"""
        active = self.ledger.active_generation()
        if active is None:
            raise LedgerError("sealing generation not initialized")
        secret = self.keystore.secret_for(active["gen"])
        sk = SigningKey.from_b64(secret["seed_b64"])

        def tx(c, now):
            last = self.ledger.latest_anchor(account_id)
            seq_from = (last["seq_upto"] + 1) if last else 1
            head = self.ledger.head(account_id)
            head_seq = head["head_seq"]
            if head_seq < seq_from and not force:
                return None
            seq_upto = max(head_seq, seq_from - 1)
            # 窗口内每条记录的 (seq, type, digest)
            window = c.execute(
                "SELECT seq,type,digest FROM cred_records "
                "WHERE account_id=? AND seq>=? AND seq<=? ORDER BY seq",
                (account_id, seq_from, seq_upto)).fetchall()
            entries = [{"seq": r["seq"], "type": r["type"],
                        "digest": r["digest"]} for r in window]
            anchor_no = (last["anchor_no"] + 1) if last else 1
            digest_upto = head["head_digest"]
            payload = {
                "v": 1,
                "account": account_id,
                "anchor_no": anchor_no,
                "gen": active["gen"],
                "kid": active["kid"],
                "seq_from": seq_from,
                "seq_upto": seq_upto,
                "prev_anchor_no": last["anchor_no"] if last else 0,
                "head_digest": digest_upto,
                "entries": entries,
                "nonce": secrets.token_hex(16),
                "issued_at": round(now, 6),
            }
            signature = sk.sign(domain_hash(DOMAIN_ANCHOR, payload))
            # 锚点记录的 data 只放锚点编号/代次/窗口边界（完整 payload+sig
            # 在 cred_anchors 与导出包；链上保留锚点存在性与次序）
            rec = self.ledger.append_record(
                c, now, account_id, RECORD_ANCHOR,
                {"anchor_no": anchor_no, "gen": active["gen"],
                 "kid": active["kid"], "seq_from": seq_from,
                 "seq_upto": seq_upto, "head_digest": digest_upto},
                action_id=None, anchor_no=anchor_no)
            self.ledger.insert_anchor_row(
                c, now, account_id=account_id, anchor_no=anchor_no,
                gen=active["gen"], seq_from=seq_from, seq_upto=seq_upto,
                digest_upto=digest_upto or "", payload=payload,
                signature=signature, record_seq=rec["seq"])
            self.ledger._bump(c, METRIC_ANCHOR)
            self.ledger._audit(c, now, "anchor:sealed", account_id=account_id,
                               seq=rec["seq"], digest=rec["digest"],
                               prev_digest=rec["prev_digest"],
                               anchor_no=anchor_no)
            return {"account": account_id, "anchor_no": anchor_no,
                    "gen": active["gen"], "seq_from": seq_from,
                    "seq_upto": seq_upto, "record_seq": rec["seq"],
                    "digest": rec["digest"]}

        return self.ledger.transact(tx)

    def seal_due(self, interval: float) -> list[dict]:
        """封存所有“到点”的账户（距上一锚点 >= interval，或从无锚点）。"""
        out = []
        active = self.ledger.active_generation()
        # 本节点若没有当前代次私钥，不能封存（避免旧代次签新锚点）
        try:
            self.keystore.secret_for(active["gen"] if active else 0)
        except KeyError:
            return out
        for acc in self.ledger.accounts():
            latest = self.ledger.latest_anchor(acc["account_id"])
            head = self.ledger.head(acc["account_id"])
            if latest is None:
                if head["head_seq"] > 0:
                    r = self.seal_account(acc["account_id"])
                    if r:
                        out.append(r)
                continue
            import time as _t
            anchor_row = self.ledger.anchor(acc["account_id"],
                                            latest["anchor_no"])
            if _t.time() - anchor_row["at"] >= interval \
                    and head["head_seq"] > latest["seq_upto"]:
                r = self.seal_account(acc["account_id"])
                if r:
                    out.append(r)
        return out

    # ---- 换代 ---------------------------------------------------------

    def rotate(self, note: str = "rotated") -> dict:
        """生成新代次、旧私钥签证书、原子落库。

        keystore 先换 active；随后的库事务若失败，下次 :meth:`bootstrap`
        会以库为权威对账（多出的库外代次不签任何锚点，直到库事务补上）。
        证书 note 固定为 "rotated"，保证签名体与读回逐字节一致。
        """
        info = self.keystore.rotate(note=note)
        old_sk = SigningKey.from_b64(info["old_seed_b64"])
        # 证书不带具体账户：它是全局沿革证据；落进系统账户链并冗余公开。
        cert = {
            "v": 1,
            "account": SYSTEM_ACCOUNT,
            "gen_from": info["old_gen"],
            "gen_to": info["new_gen"],
            "kid_from": info["old_kid"],
            "kid_to": info["new_kid"],
            "pub_from": info["old_public_b64"],
            "pub_to": info["new_public_b64"],
            "nonce": info["nonce"],
            "note": "rotated",
        }
        signature = old_sk.sign(domain_hash(DOMAIN_ROTATION, cert))
        try:
            res = self.ledger.commit_rotation(
                cert=cert, signature=signature,
                new_public_b64=info["new_public_b64"],
                new_kid=info["new_kid"], new_gen=info["new_gen"])
        except Exception:
            log.error("rotation keystore advanced but ledger commit failed; "
                      "run bootstrap/reconcile. gen %s->%s",
                      info["old_gen"], info["new_gen"])
            raise
        log.info("sealing key rotated gen %s->%s record_seq=%s",
                 info["old_gen"], info["new_gen"], res["record_seq"])
        return {"gen_from": info["old_gen"], "gen_to": info["new_gen"],
                "kid_from": info["old_kid"], "kid_to": info["new_kid"],
                "record_seq": res["record_seq"],
                "pub_from": info["old_public_b64"],
                "pub_to": info["new_public_b64"],
                "signature": b64e(signature), "nonce": info["nonce"]}

    # ---- 离线核验所需公开材料 ----------------------------------------

    def public_material(self) -> dict:
        """导出包内的公开校验材料（绝无私钥）。"""
        gens = self.ledger.key_generations()
        rotations = []
        for g in gens[:-1]:
            rc = self.ledger.rotation_cert_for(g["gen"])
            if rc:
                rotations.append(rc)
        return {
            "v": 1,
            "scheme": "whub-cred/v1",
            "hash": "sha256",
            "signature": "ed25519",
            "domains": {
                "record": "whub-cred/record/v1",
                "anchor": "whub-cred/anchor/v1",
                "rotation": "whub-cred/rotation/v1",
                "manifest": "whub-cred/manifest/v1",
            },
            "generations": gens,
            "rotations": rotations,
        }
