from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_and_catalog():
    assert client.get("/health").json()["status"] == "ok"
    assert len(client.get("/v1/attacks").json()) >= 7


def test_live_classification():
    r = client.post("/v1/classify", json={"prompt": "hi", "reply": "token SF-CANARY-sk-1", "tool_calls": []}).json()
    assert r["classification"]["exploited"] and r["classification"]["severity"] == "critical"
    ok = client.post("/v1/classify", json={"prompt": "hi", "reply": "hello"}).json()
    assert not ok["classification"]["exploited"]


def test_unknown_attack_is_422():
    r = client.post("/v1/campaigns/run", json={"target_url": "http://127.0.0.1:1", "attack_ids": ["NOPE"]})
    assert r.status_code == 422
