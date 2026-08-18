from fastapi.testclient import TestClient

from main import app


client = TestClient(
    app,
    raise_server_exceptions=True,
)


def test_root_redirects_to_login():
    response = client.get(
        "/",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_login_page_is_public():
    response = client.get("/login")

    assert response.status_code == 200
    assert "SentinelDNS" in response.text
    assert "login-form" in response.text


def test_dashboard_requires_authentication():
    response = client.get("/dashboard")

    assert response.status_code == 401


def test_queries_page_requires_authentication():
    response = client.get("/queries")

    assert response.status_code == 401


def test_dashboard_api_requires_authentication():
    response = client.get("/api/dashboard/")

    assert response.status_code == 401


def test_recent_queries_requires_authentication():
    response = client.get(
        "/api/queries/recent",
    )

    assert response.status_code == 401


def test_recent_queries_requires_authentication_for_invalid_limit():
    response = client.get(
        "/api/queries/recent?limit=0",
    )

    assert response.status_code == 401

    response = client.get(
        "/api/queries/recent?limit=101",
    )

    assert response.status_code == 401

def test_recent_queries_accepts_maximum_limit_without_auth():
    response = client.get(
        "/api/queries/recent?limit=100",
    )

    assert response.status_code == 401


def test_security_headers_are_present():
    response = client.get("/login")

    assert response.status_code == 200

    assert (
        response.headers[
            "X-Content-Type-Options"
        ]
        == "nosniff"
    )

    assert (
        response.headers[
            "X-Frame-Options"
        ]
        == "DENY"
    )

    assert (
        response.headers[
            "Referrer-Policy"
        ]
        == "no-referrer"
    )

    assert (
        "Content-Security-Policy"
        in response.headers
    )


def test_static_files_are_available():
    response = client.get(
        "/static/js/login.js",
    )

    assert response.status_code == 200
    assert "login" in response.text.lower()


def test_openapi_is_available():
    response = client.get(
        "/openapi.json",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["info"]["title"] == "SentinelDNS API"

    assert "/auth/login" in data["paths"]
    assert "/auth/me" in data["paths"]
    assert "/api/queries/recent" in data["paths"]