import pytest
from os import environ
from fastapi.testclient import TestClient
from gsan import app

client = TestClient(app)


def test_read_main():
    response = client.get("/")
    assert response.status_code == 404


def test_get_ssl_domains():
    domain = "self-signed.badssl.com"
    response = client.get(f"/ssl_domains/{domain}")
    assert response.json() == {domain: ["badssl.com"]}
    assert response.status_code == 200
