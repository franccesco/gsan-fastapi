import pytest
from os import environ
from fastapi.testclient import TestClient
from gsan import app

client = TestClient(app)


def test_read_main():
    response = client.get("/")
    assert response.status_code == 404


def test_get_ssl_domains():
    response = client.get("/ssl_domains/self-signed.badssl.com")
    assert response.json() == {"domains": ["badssl.com"]}
    assert response.status_code == 200
