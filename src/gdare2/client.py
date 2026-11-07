"""Loopback HTTP JSON client."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from gdare2 import PROTOCOL_VERSION
from gdare2.errors import ConnectionFailure, RemoteError, TimeoutFailure
from gdare2.protocol import decode_bytes, encode_bytes


class Client:
    def __init__(self, state: dict[str, Any], *, timeout: float = 30.0) -> None:
        self.instance_id = str(state["instance_id"])
        self.port = int(state["port"])
        self.token = str(state["token"])
        self.timeout = timeout
        self._counter = 0

    def call(self, op: str, *, allow_writes: bool = False, **args: Any) -> Any:
        self._counter += 1
        payload = {
            "id": f"{self.instance_id}-{self._counter}",
            "op": op,
            "args": encode_bytes(args),
            "allow_writes": allow_writes,
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/rpc",
            data=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except TimeoutError as exc:
            raise TimeoutFailure("daemon request timed out") from exc
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise ConnectionFailure("daemon rejected the bearer token") from exc
            raise ConnectionFailure(f"daemon HTTP error {exc.code}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ConnectionFailure(f"cannot reach daemon: {exc}") from exc
        except ValueError as exc:
            raise ConnectionFailure("daemon returned invalid JSON") from exc

        if not isinstance(data, dict) or not data.get("ok"):
            error = data.get("error", {}) if isinstance(data, dict) else {}
            raise RemoteError(
                str(error.get("code", "INTERNAL")),
                str(error.get("message", "unknown daemon error")),
                data=error.get("data"),
            )
        return decode_bytes(data.get("result"))

    def info(self) -> dict[str, Any]:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/info",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise ConnectionFailure(f"cannot query daemon: {exc}") from exc

    def shutdown(self, *, save: bool = True) -> None:
        body = json.dumps({"save": save}).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/shutdown",
            data=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response.read()
        except (OSError, ValueError) as exc:
            raise ConnectionFailure(f"cannot shut down daemon: {exc}") from exc


def check_protocol(health: dict[str, Any]) -> None:
    protocol = int(health.get("protocol", 0))
    if protocol != PROTOCOL_VERSION:
        raise ConnectionFailure(
            f"daemon protocol {protocol} is incompatible with client {PROTOCOL_VERSION}; "
            "run `gdare2 --kill <id>` and retry"
        )
