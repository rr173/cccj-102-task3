"""Offline evidence bundle verifier (bundle + public material only)."""
from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any

from . import anchor_crypto
from . import evidence_pack

DOMAIN_ENTRY = "whub/evidence-entry/v1"
DOMAIN_ANCHOR = "whub/evidence-anchor/v1"
DOMAIN_ROTATION = "whub/sealing-key-rotation/v1"
DOMAIN_EXPORT = "whub/evidence-export/v1"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(domain: str, body: Any) -> str:
    return hashlib.sha256(
        canonical({"domain": domain, "body": body})).hexdigest()


def verify_file(path: str, scan_secret: str | None = None) -> dict:
    result = {"ok": False, "path": path, "first_bad_seq": None,
              "damage": None, "entry_count": 0, "head_seq": None,
              "head_digest": None, "cutoff_seq": None,
              "key_generations": 0, "privacy_leak": False}
    try:
        files = evidence_pack.read_pack(path)
    except Exception as e:
        result["damage"] = {"file": path, "offset": 0, "seq": None,
                            "reason": f"unreadable pack: {e}"}
        return result
    try:
        entries = json.loads(files["entries.json"])
        anchors = json.loads(files["anchors.json"])
        rotations = json.loads(files["rotations.json"])
        keys = json.loads(files["keys.json"])
        manifest = json.loads(files["manifest.json"])
        proof = json.loads(files["proof.json"])
    except KeyError as e:
        result["damage"] = {"file": "pack", "seq": None,
                            "reason": f"missing {e}"}
        return result
    except Exception as e:
        result["damage"] = {"file": "pack", "seq": None,
                            "reason": f"invalid JSON: {e}"}
        return result

    key_by_gen = {int(k["generation"]): k["public_key"] for k in keys}
    result["key_generations"] = len(key_by_gen)
    struct_check = evidence_pack.verify_pack_structure(path, manifest)
    if not struct_check["ok"]:
        reason = struct_check.get("reason", "")
        if ("entries.json" in reason) or ("anchors.json" in reason and
                                          reason.startswith("chunk hash")):
            result["byte_damage"] = struct_check
        else:
            result["damage"] = struct_check
            result["first_bad_seq"] = struct_check.get("seq")
            return result
    if set(files) != {"entries.json", "anchors.json", "rotations.json",
                      "keys.json", "manifest.json", "proof.json"}:
        result["damage"] = {"file": "pack", "seq": None,
                            "reason": "unexpected file set"}
        return result

    signed = proof.get("signed", {})
    try:
        sig = bytes.fromhex(proof.get("signature", ""))
        gen = int(signed.get("generation", -1))
        proof_ok = gen in key_by_gen and anchor_crypto.verify(
            bytes.fromhex(key_by_gen[gen]), canonical(signed), sig)
    except Exception:
        proof_ok = False
    if not proof_ok:
        result["damage"] = {"file": "proof.json", "offset": 0, "seq": None,
                            "reason": "export proof signature invalid"}
        return result
    if signed.get("manifest_digest") != hashlib.sha256(
            evidence_pack.canonical(manifest)).hexdigest():
        result["damage"] = {"file": "manifest.json", "offset": 0, "seq": None,
                            "reason": "manifest digest not covered by proof"}
        return result

    start_seq = int(manifest["start_seq"])
    cutoff = int(manifest["cutoff_seq"])
    if signed.get("start_seq") != start_seq or signed.get("cutoff_seq") != cutoff:
        result["damage"] = {"file": "manifest.json", "seq": None,
                            "reason": "proof/manifest cutoff mismatch"}
        return result
    result["cutoff_seq"] = cutoff

    for rot in rotations:
        fg = int(rot["from_generation"])
        statement = {k: v for k, v in rot.items() if k != "signature"}
        try:
            ok = fg in key_by_gen and anchor_crypto.verify(
                bytes.fromhex(key_by_gen[fg]), canonical(statement),
                bytes.fromhex(rot["signature"]))
        except Exception:
            ok = False
        if not ok:
            result["damage"] = {"file": "rotations.json",
                                "seq": rot.get("boundary_seq"),
                                "reason": "rotation signature invalid"}
            result["first_bad_seq"] = rot.get("boundary_seq")
            return result

    prev_digest = "GENESIS" if start_seq == 1 else signed.get("start_prev_digest")
    if not prev_digest:
        result["damage"] = {"file": "proof.json", "seq": start_seq,
                            "reason": "incremental bundle lacks prior digest"}
        result["first_bad_seq"] = start_seq
        return result

    expected = start_seq
    last_digest = None
    for wrapper in entries:
        seq = int(wrapper.get("seq", -1))
        body = wrapper.get("body", {})
        if seq != expected:
            bad, reason = expected, "deleted entry"
        elif wrapper.get("prev_digest") != prev_digest:
            bad, reason = seq, "reordered or modified entry link"
        else:
            bad, reason = seq, "entry link failure"
        if seq != expected or wrapper.get("prev_digest") != prev_digest:
            d = {"file": "entries.json", "seq": bad, "reason": reason}
            byte = result.get("byte_damage", {})
            d.update({"offset": byte.get("offset"),
                      "length": byte.get("length", 1),
                      "byte_reason": byte.get("reason")})
            result["damage"] = d
            result["first_bad_seq"] = bad
            return result
        if wrapper.get("digest") != digest(DOMAIN_ENTRY, body):
            d = {"file": "entries.json", "seq": seq,
                 "reason": "modified entry digest"}
            byte = result.get("byte_damage", {})
            d.update({"offset": byte.get("offset"),
                      "length": byte.get("length", 1),
                      "byte_reason": byte.get("reason")})
            result["damage"] = d
            result["first_bad_seq"] = seq
            return result
        prev_digest = wrapper["digest"]
        last_digest = wrapper["digest"]
        expected += 1

    if not entries or entries[-1]["seq"] != cutoff or \
            signed.get("head_digest") != last_digest:
        result["damage"] = {"file": "entries.json", "seq": expected,
                            "reason": "cutoff head missing or not frozen"}
        result["first_bad_seq"] = cutoff
        return result

    prev_anchor_id = None
    for anchor in anchors:
        statement = anchor.get("signed", {})
        seq = int(anchor["seq"])
        if seq > cutoff:
            continue
        g = int(anchor["generation"])
        try:
            ok = g in key_by_gen and anchor_crypto.verify(
                bytes.fromhex(key_by_gen[g]), canonical(statement),
                bytes.fromhex(anchor["signature"]))
        except Exception:
            ok = False
        if not ok:
            d = {"file": "anchors.json", "seq": seq,
                 "reason": "anchor signature invalid or forged"}
            byte = result.get("byte_damage", {})
            d.update({"offset": byte.get("offset"),
                      "length": byte.get("length", 1),
                      "byte_reason": byte.get("reason")})
            result["damage"] = d
            result["first_bad_seq"] = seq
            return result
        if statement.get("anchor_id") != anchor["anchor_id"] or \
                statement.get("prev_anchor_id") != prev_anchor_id or \
                statement.get("generation") != g:
            result["damage"] = {"file": "anchors.json", "seq": seq,
                                "reason": "anchor replaced or link broken"}
            result["first_bad_seq"] = seq
            return result
        target = next((w for w in entries if w["seq"] == seq), None)
        if target is None or statement.get("head_digest") != target["digest"]:
            result["damage"] = {"file": "anchors.json", "seq": seq,
                                "reason": "anchor head digest mismatch"}
            result["first_bad_seq"] = seq
            return result
        prev_anchor_id = anchor["anchor_id"]

    if signed.get("last_anchor_id") != prev_anchor_id:
        result["damage"] = {"file": "proof.json", "seq": cutoff,
                            "reason": "proof anchor reference mismatch"}
        result["first_bad_seq"] = cutoff
        return result

    leak = False
    if scan_secret:
        needle = scan_secret.encode()
        for name, raw in files.items():
            if needle in raw:
                leak = True
                result["damage"] = {"file": name, "seq": None,
                                    "reason": "protected secret marker found"}
    result.update(ok=not leak, entry_count=len(entries),
                  head_seq=cutoff, head_digest=last_digest, privacy_leak=leak)
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m whub.verifier")
    p.add_argument("bundle")
    p.add_argument("--scan-secret", default=None)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    r = verify_file(args.bundle, args.scan_secret)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("OK" if r["ok"] else "INVALID", r["path"])
        print(f"entries={r['entry_count']} head={r['head_seq']} "
              f"digest={r['head_digest']}")
        if not r["ok"]:
            print("damage=", json.dumps(r["damage"], ensure_ascii=False))
    return 0 if r["ok"] else 1
