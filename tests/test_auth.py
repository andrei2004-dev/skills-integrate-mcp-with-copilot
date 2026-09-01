import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from app import app


client = TestClient(app)


def test_register_and_login_user():
    email = "newstudent@mergington.edu"
    password = "StrongPass123!"

    register_response = client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )
    assert register_response.status_code == 200
    assert register_response.json()["email"] == email

    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert login_response.status_code == 200
    data = login_response.json()
    assert "token" in data
    assert data["email"] == email


def test_login_fails_with_wrong_password():
    email = "wrongpass@mergington.edu"
    password = "StrongPass123!"

    client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )

    response = client.post(
        "/auth/login",
        json={"email": email, "password": "NotTheRightPassword"},
    )

    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()


def test_duplicate_registration_is_rejected():
    email = "duplicate@mergington.edu"
    password = "StrongPass123!"

    first = client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )
    assert first.status_code == 200

    second = client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )
    assert second.status_code == 409
