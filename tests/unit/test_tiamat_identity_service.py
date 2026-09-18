from fastapi.testclient import TestClient

from lucy.tiamat_identity_service import app


def test_identity_service_is_content_free_and_dispatch_disabled() -> None:
    response = TestClient(app).get("/healthz")

    assert response.status_code == 503
    assert response.json() == {"status": "disabled", "provider_dispatch": False}
    assert response.headers["cache-control"] == "no-store"
    assert TestClient(app).post("/execution/v1/inference").status_code == 404
    assert TestClient(app).get("/docs").status_code == 404
