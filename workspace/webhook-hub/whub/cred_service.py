"""store 进程内的周期封存服务（后台线程）。

只在 durable store 进程运行：周期性对所有有新增条目的账户封存锚点。
worker / hub 进程不持有封存私钥，不能签锚点——这保证了“新锚点只认
当前代次私钥的持有者”。
"""
from __future__ import annotations

import logging
import threading

log = logging.getLogger("whub.cred_sealer_service")


class AnchorService:
    def __init__(self, sealer, exporter, interval: float):
        self.sealer = sealer
        self.exporter = exporter
        self.interval = interval
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._thread = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="cred-anchor",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._pause.set()
        if self._thread:
            self._thread.join(timeout=3)

    def set_paused(self, paused: bool) -> None:
        """暂停/恢复周期封存（验收需要精确控制封存时机）。"""
        if paused:
            self._pause.set()
        else:
            self._pause.clear()

    def seal_now(self) -> list[dict]:
        try:
            return self.sealer.seal_due(self.interval)
        except Exception:
            log.exception("periodic anchor sealing failed")
            return []

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            if self._pause.is_set():
                continue
            sealed = self.seal_now()
            for s in sealed:
                log.info("anchor sealed account=%s no=%s upto=%s",
                         s["account"], s["anchor_no"], s["seq_upto"])
