from fastapi.testclient import TestClient

from main import app


client = TestClient(
    app,
    raise_server_exceptions=True,
)


def test_dhcp_page_requires_authentication():
    response = client.get("/dhcp")
    assert response.status_code == 401


def test_dhcp_api_requires_authentication():
    response = client.get("/api/dhcp")
    assert response.status_code == 401
