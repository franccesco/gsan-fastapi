import pytest
from os import environ
from fastapi.testclient import TestClient
from gsan import app

client = TestClient(app)


def test_get_homepage():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["version"] == "0.1.0"


def test_get_ssl_domains():
    domain = "self-signed.badssl.com"
    response = client.get(f"/ssl_domains/{domain}")
    assert response.json() == {domain: ["badssl.com"]}
    assert response.status_code == 200
