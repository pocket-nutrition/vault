from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

PATH = "/.well-known/apple-app-site-association"


def make(apple_app_ids: str) -> TestClient:
    return TestClient(create_app(Settings(database_url="sqlite:///:memory:", apple_app_ids=apple_app_ids)))


def test_lists_the_configured_apps_for_webcredentials():
    resp = make(" TEAM.org.example.app , TEAM.org.example.beta ").get(PATH)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json() == {"webcredentials": {"apps": ["TEAM.org.example.app", "TEAM.org.example.beta"]}}


def test_is_not_served_until_an_app_is_configured():
    assert make("").get(PATH).status_code == 404
