"""Periodic chain-head sealing scheduler for the durable store process."""
from __future__ import annotations

import logging
import threading

log = logging.getLogger("whub.anchors")


class AnchorScheduler:
    def __init__(self, store, interval: float):
        self.store = store
        self.interval = interval
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.interval <= 0:
            return
        self.thread = threading.Thread(target=self._run, name="anchor-seal",
                                       daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.wait(self.interval):
            try:
                # Tenant list is intentionally derived from existing chains;
                # an empty account has no head to seal.
                heads = self.store.rpc("evidence_verify_local")
                for row in heads:
                    if row.get("head_seq"):
                        self.store.rpc("seal_anchor", tenant_id=row["tenant_id"],
                                       reason="periodic", force=False)
            except Exception:
                log.exception("periodic anchor sweep failed")

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
