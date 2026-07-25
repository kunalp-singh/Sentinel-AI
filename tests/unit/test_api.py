from fastapi.testclient import TestClient

from sentinel.api import app

client = TestClient(app)


def test_root_endpoint() -> None:
    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "SentinelAI"
    assert data["version"] == "0.1.0"


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data == {
        "status": "healthy",
        "service": "SentinelAI",
        "version": "0.1.0",
    }


def test_openapi_schema_is_available() -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    schema = response.json()

    assert schema["info"]["title"] == "SentinelAI"


def test_swagger_docs_are_available() -> None:
    response = client.get("/docs")

    assert response.status_code == 200