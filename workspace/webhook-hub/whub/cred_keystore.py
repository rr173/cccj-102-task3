"""封存私钥 keystore：代次化 Ed25519 签名密钥的本地安全保管。

* 文件为 0600 JSON，fcntl 串行化跨进程换代；
* 私钥**只**存在这里（与主账库分离），绝不进入凭证/审计/导出包；
* 导出包只携带各代次的**公钥**与换代证书，离线核验据此验证沿革；
* 换代时旧私钥保留在 keystore（用于旧锚点的离线材料，不再签任何新锚点）。
"""
from __future__ import annotations

import fcntl
import json
import os
import secrets

from .cred_crypto import SigningKey, b64e


class KeyStore:
    def __init__(self, path: str):
        self.path = path

    # ---- 内部：加锁读 / 锁内改写 -------------------------------------

    def _locked(self, fn):
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        # 用独立锁文件，避免读写进程互相截断
        lockpath = self.path + ".lock"
        with open(lockpath, "a+") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                doc = self._read_unlocked()
                return fn(doc)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def _read_unlocked(self) -> dict:
        try:
            with open(self.path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"generations": [], "active": 0}

    def _write_unlocked(self, doc: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # ---- 初始化 / 查询 -----------------------------------------------

    def ensure(self) -> int:
        """确保至少存在一个签名代次；返回当前（最新）代号。"""
        def fn(doc):
            if not doc["generations"]:
                self._mint(doc, note="genesis")
                self._write_unlocked(doc)
            return doc["active"]
        return self._locked(fn)

    def _mint(self, doc: dict, note: str) -> dict:
        gen = len(doc["generations"]) + 1
        sk = SigningKey.generate()
        entry = {
            "gen": gen,
            "kid": f"seal-{gen:x}",
            "public_b64": sk.public_b64(),
            "seed_b64": sk.seed_b64(),
            "created_nonce": secrets.token_hex(8),
            "note": note,
        }
        doc["generations"].append(entry)
        doc["active"] = gen
        return entry

    def active(self) -> dict:
        """当前代次（含私钥，仅封存/换代路径使用）。"""
        def fn(doc):
            if not doc["generations"]:
                self._mint(doc, note="genesis")
                self._write_unlocked(doc)
            return self._secret_view(doc, doc["active"])
        return self._locked(fn)

    def public_map(self) -> dict[int, str]:
        def fn(doc):
            return {g["gen"]: g["public_b64"] for g in doc["generations"]}
        return self._locked(fn)

    def generations_public(self) -> list[dict]:
        """公开材料视图：只有代次、kid、公钥（无私钥）。"""
        def fn(doc):
            return [{"gen": g["gen"], "kid": g["kid"],
                     "public_b64": g["public_b64"]}
                    for g in doc["generations"]]
        return self._locked(fn)

    def secret_for(self, gen: int) -> dict:
        def fn(doc):
            return self._secret_view(doc, gen)
        return self._locked(fn)

    @staticmethod
    def _secret_view(doc: dict, gen: int) -> dict:
        for g in doc["generations"]:
            if g["gen"] == gen:
                return dict(g)
        raise KeyError(f"sealing generation {gen} not found")

    # ---- 换代：返回（旧私钥, 新代次公开信息, 待签证书体） --------------

    def rotate(self, note: str = "rotated") -> dict:
        """生成新代次。跨证书签名需要的旧私钥一并返回给调用方。

        调用方必须：
          1. 用旧私钥签 rotation 证书（旧 gen -> 新 gen）；
          2. 把证书追加进**主账链**并与 key_gens 行同一事务；
          3. 成功后本 keystore 已把 active 指向新代次（本方法内完成）。
        """
        def fn(doc):
            if not doc["generations"]:
                self._mint(doc, note="genesis")
            old = self._secret_view(doc, doc["active"])
            new = self._mint(doc, note=note)
            self._write_unlocked(doc)
            return {
                "old_gen": old["gen"], "old_kid": old["kid"],
                "old_seed_b64": old["seed_b64"],
                "old_public_b64": old["public_b64"],
                "new_gen": new["gen"], "new_kid": new["kid"],
                "new_public_b64": new["public_b64"],
                "nonce": secrets.token_hex(16),
            }
        return self._locked(fn)
