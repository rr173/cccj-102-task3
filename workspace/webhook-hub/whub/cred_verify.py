"""离线核验器：只凭导出包 + 包内公开材料 + 约定规范编码即可判定真伪。

不连接任何服务、不读主账库、不需要私钥。输出：

  {
    ok, account, seq_from, seq_cutoff, head_digest,
    chain: {ok, first_bad_seq, reason},
    anchors_checked, anchors_ok,
    lineage_ok,
    incremental: {ok, ...} | null,
    tamper: {file, byte_offset, seq} | null,
    privacy_scan: {leaks_found, hits},
    files_ok: {records.jsonl, anchors.jsonl, material.json}
  }

破坏定位策略
============
1. 先按 ZIP 本地头顺序抽取条目字节（不依赖可能被一并破坏的中央目录）；
2. 对每个文件做 manifest 中 SHA256 比对，找出首个物理损坏的文件与
   条目行：records.jsonl 一行对应一个 seq，故字节偏移可映射回 seq；
3. 再重算摘要链，报出第一个摘要/前指针/编号不连续的序号；
4. 锚点签名与换代证书独立验签；任何伪造都定位到具体 anchor_no / gen。
"""
from __future__ import annotations

import hashlib
import json
import struct
import zipfile
from typing import Optional

from .cred_crypto import (
    DOMAIN_ANCHOR, DOMAIN_MANIFEST, DOMAIN_ROTATION, ZERO, b64d, b64e,
    canonical, chain_digest, domain_hash, verify,
)

# 秘密/正文扫描：导出包绝不应出现这些高危模式（演示密钥、私钥种子、口令）
_SECRET_PATTERNS = (
    b"whsec_", b"whk_", b"whsec2_", b"BEGIN PRIVATE", b"seed_b64",
    b'"secret"', b"'secret'", b"api_key", b"password", b"passwd",
    b"Authorization: Bearer",
)


class PackageError(Exception):
    pass


# ----------------------------------------------------------- ZIP 容错读取

def _read_local_entries(raw: bytes) -> dict[str, bytes]:
    """按本地文件头顺序读取 ZIP 条目（中央目录损坏时仍可用）。

    数据可能被增删字节：用下一个 ``PK\\x03\\x04`` 本地头或中央目录头
    ``PK\\x01\\x02`` 来界定当前条目数据的真实结尾，而非盲信长度字段。
    """
    out: dict[str, bytes] = {}
    positions = []
    i = 0
    lf = b"PK\x03\x04"
    cd = b"PK\x01\x02"
    while True:
        a = raw.find(lf, i)
        b = raw.find(cd, i)
        if a < 0:
            break
        if 0 <= b < a:
            break  # 进入中央目录
        positions.append(a)
        i = a + 4
    for idx, j in enumerate(positions):
        try:
            (_sig, _ver, flags, method, _mtime, _mdate, _crc, comp_size,
             uncomp_size, name_len, extra_len) = struct.unpack_from(
                "<IHHHHHIIIHH", raw, j)
            name = raw[j + 30:j + 30 + name_len].decode("utf-8", "replace")
            data_start = j + 30 + name_len + extra_len
            if idx + 1 < len(positions):
                data_end = positions[idx + 1]
            else:
                cdpos = raw.find(cd, data_start)
                data_end = cdpos if cdpos >= 0 else len(raw)
            if method == 0:
                out[name] = raw[data_start:data_end]
        except Exception:
            continue
    return out


def _load_package(path: str) -> tuple[dict, dict[str, bytes]]:
    with open(path, "rb") as f:
        raw = f.read()
    entries: dict[str, bytes] = {}
    # 先按本地文件头顺序读取（STORED 数据，CRC 不匹配也照常取出，
    # 以便把物理损坏映射到具体序号；验真在后续 sha256 步骤完成）。
    entries.update(_read_local_entries(raw))
    # 中央目录完好时用标准 ZIP 读取作交叉确认（不覆盖本地头字节）。
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.compress_type == zipfile.ZIP_STORED:
                    entries.setdefault(info.filename, z.read(info.filename))
    except Exception:
        pass
    required = {"manifest.json", "records.jsonl", "anchors.jsonl",
                "material.json", "manifest.sig"}
    missing = required - set(entries)
    if missing:
        raise PackageError(f"package missing entries: {sorted(missing)}")
    try:
        manifest = json.loads(entries["manifest.json"].decode("utf-8"))
    except Exception as e:
        raise PackageError(f"manifest unreadable: {e}")
    return manifest, entries


# ----------------------------------------------------------- 主核验

def verify_package(path: str, *, expected_account: Optional[str] = None,
                   prev_head_digest: Optional[str] = None,
                   prev_cutoff: Optional[int] = None) -> dict:
    result = {"path": path, "ok": False, "first_bad_seq": None}
    try:
        manifest, entries = _load_package(path)
    except PackageError as e:
        result.update({"error": str(e),
                        "tamper": {"file": "package", "reason": str(e)}})
        return result

    material_raw = entries["material.json"]
    records_raw = entries["records.jsonl"]
    anchors_raw = entries["anchors.jsonl"]
    sig_raw = entries["manifest.sig"]

    account = manifest.get("account")
    seq_from = manifest.get("seq_from")
    cutoff = manifest.get("seq_cutoff")
    result.update({"account": account, "seq_from": seq_from,
                   "seq_cutoff": cutoff, "head_digest": manifest.get("head_digest"),
                   "export_id": manifest.get("export_id")})

    if expected_account and account != expected_account:
        result["tamper"] = {"file": "manifest.json",
                            "reason": f"account mismatch {account}"}
        return result

    # ---- 1) 文件级哈希（物理损坏定位）----
    files_ok = {}
    first_file_damage = None
    for name in ("records.jsonl", "anchors.jsonl", "material.json"):
        want = manifest["files"][name]["sha256"]
        got = hashlib.sha256(entries[name]).hexdigest()
        files_ok[name] = (want == got)
        if not files_ok[name] and first_file_damage is None:
            first_file_damage = name

    # ---- 2) 清单签名（必须当前代次私钥）----
    material = json.loads(material_raw.decode("utf-8"))
    gens = {g["gen"]: g for g in material["generations"]}
    gen = manifest.get("sealed_gen")
    manifest_ok = False
    if gen in gens:
        pub = b64d(gens[gen]["public_b64"])
        manifest_ok = verify(pub, domain_hash(DOMAIN_MANIFEST, manifest),
                             sig_raw)
    result["manifest_signature_ok"] = manifest_ok
    result["sealed_gen"] = gen

    # ---- 3) 解析记录行（容错：坏行也映射到序号）----
    line_map = _map_lines(records_raw)
    records: list[dict] = []
    parse_first_bad = None
    for ln, rawline in line_map:
        try:
            records.append(json.loads(rawline.decode("utf-8")))
        except Exception:
            if parse_first_bad is None:
                parse_first_bad = (ln, rawline)

    # ---- 4) 摘要链 + 编号连续性（增量包用外部前链头）----
    external_prev = b64d(prev_head_digest) if prev_head_digest else None
    chain = _verify_chain(records, seq_from, account, external_prev)
    result["chain"] = chain

    # ---- 5) 物理损坏映射到序号 ----
    tamper: Optional[dict] = None
    if first_file_damage == "records.jsonl":
        seq = _damage_seq(records_raw, records, seq_from)
        tamper = {"file": "records.jsonl", "byte_offset": seq[1],
                  "seq": seq[0], "reason": "sha256 mismatch in records file"}
    elif first_file_damage:
        tamper = {"file": first_file_damage,
                  "reason": f"sha256 mismatch in {first_file_damage}"}
    if tamper is None and parse_first_bad is not None:
        ln, rawline = parse_first_bad
        tamper = {"file": "records.jsonl", "line": ln,
                  "reason": "record line not parseable"}
    result["tamper"] = tamper

    # 若物理哈希完好但链断（语义级改写：重写后重算了文件？——重写者无
    # 锚点私钥，无法重封；而链重算导致与锚点不一致），以链首坏序号为准
    semantic_bad = None if chain["ok"] else chain["first_bad_seq"]

    # ---- 6) 锚点验签 + 与链一致性 ----
    anchors = []
    anchors_bad = []
    try:
        for line in anchors_raw.decode("utf-8").splitlines():
            if line.strip():
                anchors.append(json.loads(line))
    except Exception:
        anchors_bad.append({"anchor_no": None, "reason": "anchors unparseable"})

    anchors_checked = anchors_ok = 0
    first_anchor_bad = None
    by_seq = {r["seq"]: r for r in records}
    for a in anchors:
        anchors_checked += 1
        ano = a.get("anchor_no")
        g = a.get("gen")
        pub = b64d(gens[g]["public_b64"]) if g in gens else None
        sig_ok = bool(pub) and verify(
            pub, domain_hash(DOMAIN_ANCHOR, a["payload"]),
            b64d(a["signature"]))
        # 锚点条目必须真的在链上、类型为 anchor、编号一致
        rec = by_seq.get(a["record_seq"])
        rec_anchor_no = None
        if rec is not None:
            rec_anchor_no = rec.get("body", {}).get("data", {}) \
                .get("anchor_no", rec.get("anchor_no"))
        chain_ok = (rec is not None and rec.get("type") == "anchor"
                    and rec_anchor_no == ano)
        # 锚点窗口末摘要 == 该序号链条目摘要
        upto_rec = by_seq.get(a["seq_upto"])
        upto_ok = upto_rec is not None and upto_rec["digest"] == a["digest_upto"]
        if sig_ok and chain_ok and upto_ok:
            anchors_ok += 1
        elif first_anchor_bad is None:
            first_anchor_bad = {"anchor_no": ano, "gen": g,
                                "sig_ok": sig_ok, "chain_ok": chain_ok,
                                "upto_ok": upto_ok}
    result["anchors_checked"] = anchors_checked
    result["anchors_ok"] = anchors_ok
    if first_anchor_bad:
        result["anchor_failure"] = first_anchor_bad

    # ---- 7) 密钥沿革：genesis 起每个分界都由旧私钥签证书，链可验 ----
    lineage = _verify_lineage(material)
    result["lineage_ok"] = lineage["ok"]
    result["lineage"] = lineage

    # ---- 8) 增量包接续 ----
    incremental = None
    if seq_from > 1:
        mp = manifest.get("prev_head_digest")
        head_link_ok = bool(mp) and (
            prev_head_digest is None or mp == prev_head_digest)
        start_ok = prev_cutoff is None or seq_from == prev_cutoff + 1
        incremental = {
            "ok": head_link_ok and start_ok,
            "prev_head_digest": mp,
            "expected_prev_head_digest": prev_head_digest,
            "expected_start": (prev_cutoff + 1) if prev_cutoff else None,
        }
    result["incremental"] = incremental

    # ---- 9) 链头与清单一致 ----
    last = records[-1] if records else None
    head_ok = True
    if cutoff and cutoff >= seq_from:
        head_ok = last is not None and last["seq"] == cutoff \
            and last["digest"] == manifest["head_digest"]
    result["head_ok"] = head_ok

    # ---- 10) 隐私泄漏扫描（导出字节内不得含秘密/正文）----
    result["privacy_scan"] = _scan_secrets(entries)

    # ---- 汇总结论 ----
    result["files_ok"] = files_ok
    ok = (all(files_ok.values()) and manifest_ok and chain["ok"] and head_ok
          and lineage["ok"] and result["privacy_scan"]["leaks_found"] == 0
          and anchors_checked == anchors_ok
          and not first_anchor_bad
          and (incremental is None or incremental["ok"]))
    result["ok"] = ok

    # 统一的“首个损坏序号”字段。
    # 优先级：语义链断裂点（最精确，能定位到被改/删/乱序的具体序号）
    #        > 锚点断裂点 > 物理文件哈希粗定位。
    first_bad = None
    if semantic_bad is not None:
        first_bad = semantic_bad
    elif first_anchor_bad:
        upto = None
        for a in anchors:
            if a["anchor_no"] == first_anchor_bad["anchor_no"]:
                upto = a["record_seq"]
        first_bad = upto
    elif tamper is not None and tamper.get("seq"):
        first_bad = tamper["seq"]
    result["first_bad_seq"] = first_bad
    return result


def _map_lines(raw: bytes) -> list[tuple[int, bytes]]:
    out = []
    start = 0
    n = 1
    for i, ch in enumerate(raw):
        if ch == 0x0A:
            out.append((n, raw[start:i]))
            start = i + 1
            n += 1
    if start < len(raw):
        out.append((n, raw[start:]))
    return out


def _verify_chain(records: list[dict], seq_from: int, account,
                  external_prev: bytes | None = None) -> dict:
    """重算（可能是增量的）链。

    增量包首条记录的 prev_digest 指向包外的前一包链头：用
    ``external_prev`` 作为起始摘要验证，而不是要求它为 None。
    """
    prev = external_prev
    expected = seq_from
    for r in records:
        if r.get("seq") != expected:
            return {"ok": False, "first_bad_seq": expected,
                    "reason": f"gap/dup: expected seq {expected}, "
                              f"got {r.get('seq')}"}
        body = r.get("body")
        want_prev = b64e(prev) if prev else None
        if r.get("prev_digest") != want_prev:
            return {"ok": False, "first_bad_seq": expected,
                    "reason": "prev_digest link mismatch"}
        calc = chain_digest(prev, body)
        if r.get("digest") != b64e(calc):
            return {"ok": False, "first_bad_seq": expected,
                    "reason": "digest mismatch (content altered)"}
        if body.get("account") != account:
            return {"ok": False, "first_bad_seq": expected,
                    "reason": "account field mismatch"}
        prev = calc
        expected += 1
    return {"ok": True, "first_bad_seq": None, "last_seq": expected - 1}


def _damage_seq(records_raw: bytes, parsed: list[dict],
                seq_from: int) -> tuple[Optional[int], Optional[int]]:
    """把 records.jsonl 的物理损坏字节偏移映射到 (seq, byte_offset)。"""
    valid_seqs = {r.get("seq") for r in parsed}
    offset = 0
    n = 0
    for line in records_raw.split(b"\n"):
        line_start = offset
        n += 1
        try:
            obj = json.loads(line.decode()) if line else None
        except Exception:
            obj = None
        if line and obj is None:
            # 损坏行：序号约为 seq_from + 行序
            return (seq_from + n - 2, line_start)
        offset += len(line) + 1
    # 文件哈希变了但逐行仍可解析（如末尾被追加/截断）：报期望的下一序号
    expected_last = seq_from + max(n - 2, 0)
    return (expected_last, len(records_raw))


def _verify_lineage(material: dict) -> dict:
    gens = sorted(material["generations"], key=lambda g: g["gen"])
    if not gens:
        return {"ok": False, "reason": "no sealing generations"}
    pub_by_gen = {g["gen"]: g["public_b64"] for g in gens}
    active = [g for g in gens if g.get("active")]
    if len(active) != 1:
        return {"ok": False, "reason": "exactly one active generation required"}
    rots = {r["cert"]["gen_from"]: r for r in material["rotations"]}
    chain_gens = [g["gen"] for g in gens]
    for i in range(1, len(chain_gens)):
        gf = chain_gens[i - 1]
        gt = chain_gens[i]
        rc = rots.get(gf)
        if not rc:
            return {"ok": False, "first_bad_gen": gf,
                    "reason": f"missing rotation cert {gf}->{gt}"}
        cert, sig = rc["cert"], b64d(rc["signature"])
        if cert["gen_to"] != gt or cert["pub_from"] != pub_by_gen.get(gf) \
                or cert["pub_to"] != pub_by_gen.get(gt):
            return {"ok": False, "first_bad_gen": gf,
                    "reason": "rotation cert does not bind the two public keys"}
        if not verify(b64d(pub_by_gen[gf]),
                      domain_hash(DOMAIN_ROTATION, cert), sig):
            return {"ok": False, "first_bad_gen": gf,
                    "reason": "rotation cert signature invalid (forged)"}
    return {"ok": True, "generations": chain_gens,
            "active_gen": active[0]["gen"]}


def _scan_secrets(entries: dict[str, bytes]) -> dict:
    hits = []
    for name in ("records.jsonl", "anchors.jsonl", "material.json"):
        data = entries.get(name, b"")
        for pat in _SECRET_PATTERNS:
            idx = data.find(pat)
            if idx >= 0:
                hits.append({"file": name, "pattern": pat.decode("utf-8",
                                                                  "replace"),
                             "byte_offset": idx})
    return {"leaks_found": len(hits), "hits": hits}
