from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_api_status():
    response = client.get("/status")
    assert response.status_code == 200
    data = response.json()
    assert "security_mode" in data
    assert "brute_force_threshold" in data

def test_api_login_success():
    response = client.post("/login", json={"username": "admin", "password": "SuperAdminPass2026!"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["user"] == "admin"

def test_api_login_failure():
    response = client.post("/login", json={"username": "admin", "password": "SenhaCompletamenteIncorreta!"})
    assert response.status_code == 401
    assert "Credenciais inválidas" in response.json()["detail"]

def test_api_logs_view():
    response = client.get("/logs")
    assert response.status_code == 200
    data = response.json()
    assert "entries" in data
