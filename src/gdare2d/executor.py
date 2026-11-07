"""Single-thread Program executor."""

from __future__ import annotations

import logging
import queue
import threading
from concurrent.futures import Future
from typing import Any, Callable

from gdare2.errors import NotReadyError

log = logging.getLogger("gdare2d.executor")


class Executor:
    def __init__(self, runtime) -> None:
        self.runtime = runtime
        self.tasks: queue.Queue = queue.Queue()
        self.thread = threading.Thread(target=self._run, name="gdare2-executor", daemon=True)
        self.ready = threading.Event()
        self.failed = False

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        try:
            self.runtime.open()
        except Exception:
            self.failed = True
            self.ready.set()
            return
        self.ready.set()
        while True:
            item = self.tasks.get()
            if item is None:
                break
            future, function = item
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(function())
            except BaseException as exc:  # propagate to the waiting HTTP thread
                future.set_exception(exc)
        try:
            self.runtime.close()
        except Exception:
            log.exception("error while closing runtime")

    def submit(self, function: Callable[[], Any], *, timeout: float | None = None) -> Any:
        if self.failed:
            raise NotReadyError("daemon failed to open the program; see its log")
        if self.runtime.state != "ready":
            raise NotReadyError(f"daemon is {self.runtime.state}")
        future: Future = Future()
        self.tasks.put((future, function))
        return future.result(timeout=timeout)

    def stop(self, *, timeout: float = 30.0) -> None:
        if not self.thread.is_alive():
            return
        self.tasks.put(None)
        self.thread.join(timeout=timeout)

    def properties(self) -> dict[str, Any]:
        return {"state": self.runtime.state, "failed": self.failed, "thread": self.thread.is_alive()}
