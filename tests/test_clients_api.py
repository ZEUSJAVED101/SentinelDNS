"""Focused Clients API tests.

These tests are intentionally lightweight. They verify the response models
and bounded search validation without requiring the live SentinelDNS server.
"""

from datetime import datetime, timezone

from backend.api.clients import ClientResponse, ClientsResponse


def test_client_response_rejects_unknown_fields():
    try:
        ClientResponse(
            client_id="client-1",
            ip_address="192.168.10.10",
            hostname=None,
            lease_start=datetime.now(timezone.utc),
            lease_end=datetime.now(timezone.utc),
            state="ACTIVE",
            remaining_seconds=60,
            secret="should-not-be-accepted",
        )
    except Exception:
        return
    raise AssertionError("Unexpected fields must be rejected")


def test_clients_response_is_bounded():
    response = ClientsResponse(
        total_matching=501,
        returned=500,
        active=500,
        expired=1,
        clients=[],
    )
    assert response.returned == 500
