"""Ryu southbound mitigation APIs.

Wrapper around Ryu ofctl_rest flow-entry endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass
class RyuResponse:
    ok: bool
    status_code: int
    detail: str


class RyuBlockAPI:
    def __init__(self, base_url: str = "http://127.0.0.1:8080", timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _post(self, path: str, payload: Dict[str, Any]) -> RyuResponse:
        url = f"{self.base_url}{path}"
        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
            ok = 200 <= resp.status_code < 300
            return RyuResponse(ok=ok, status_code=resp.status_code, detail=resp.text.strip())
        except requests.RequestException as e:
            return RyuResponse(ok=False, status_code=0, detail=str(e))

    @staticmethod
    def _build_match(
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        in_port: Optional[int] = None,
        ip_proto: Optional[int] = None,
    ) -> Dict[str, Any]:
        match: Dict[str, Any] = {"eth_type": 2048}

        if src_ip:
            match["ipv4_src"] = src_ip
        if dst_ip:
            match["ipv4_dst"] = dst_ip
        if in_port is not None:
            match["in_port"] = int(in_port)
        if ip_proto is not None:
            match["ip_proto"] = int(ip_proto)

        return match

    def block_flow(
        self,
        dpid: int,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        in_port: Optional[int] = None,
        priority: int = 200,
        ip_proto: Optional[int] = None,
    ) -> RyuResponse:
        """Install a drop rule on one switch for a specific flow match."""
        payload = {
            "dpid": int(dpid),
            "table_id": 0,
            "priority": int(priority),
            "match": self._build_match(src_ip=src_ip, dst_ip=dst_ip, in_port=in_port, ip_proto=ip_proto),
            "actions": [],
        }
        return self._post("/stats/flowentry/add", payload)

    def unblock_flow(
        self,
        dpid: int,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        in_port: Optional[int] = None,
        priority: int = 200,
        ip_proto: Optional[int] = None,
    ) -> RyuResponse:
        """Delete a previously installed drop rule."""
        payload = {
            "dpid": int(dpid),
            "table_id": 0,
            "priority": int(priority),
            "match": self._build_match(src_ip=src_ip, dst_ip=dst_ip, in_port=in_port, ip_proto=ip_proto),
        }
        return self._post("/stats/flowentry/delete_strict", payload)

    def block_all_malicious(self, dpid: int, priority: int = 150) -> RyuResponse:
        """One-click mitigation: block all IPv4 traffic on a switch.

        NOTE: this is aggressive and should normally be used with care or during demo mode.
        """
        payload = {
            "dpid": int(dpid),
            "table_id": 0,
            "priority": int(priority),
            "match": {"eth_type": 2048},
            "actions": [],
        }
        return self._post("/stats/flowentry/add", payload)
