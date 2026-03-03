"""Aegis HTTP client for sending events to aegisd."""

from __future__ import annotations

from typing import Optional
import urllib.request
import urllib.error
import json

from aegis_sdk.envelope import Envelope


class AegisClient:
    """Thin HTTP client that sends Aegis events to a running aegisd instance."""

    def __init__(self, base_url: str = "http://localhost:8080") -> None:
        self.base_url = base_url.rstrip("/")

    def append_event(self, envelope: Envelope) -> dict:
        """POST a sealed envelope to aegisd. Returns the server response dict."""
        body = json.dumps(envelope.to_dict()).encode()
        req = urllib.request.Request(
            url=f"{self.base_url}/v1/events",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"aegis client: HTTP {e.code}: {e.read().decode()}") from e

    def list_events(
        self,
        tenant_id: str,
        session_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> dict:
        params = f"tenant_id={tenant_id}"
        if session_id:
            params += f"&session_id={session_id}"
        if event_type:
            params += f"&event_type={event_type}"
        params += f"&limit={limit}"
        req = urllib.request.Request(
            url=f"{self.base_url}/v1/events?{params}",
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def get_snapshot(self, tenant_id: str, session_id: str) -> dict:
        req = urllib.request.Request(
            url=f"{self.base_url}/v1/sessions/{session_id}/snapshot?tenant_id={tenant_id}",
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def verify_chain(self, tenant_id: str, session_id: str) -> dict:
        req = urllib.request.Request(
            url=f"{self.base_url}/v1/sessions/{session_id}/verify?tenant_id={tenant_id}",
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
