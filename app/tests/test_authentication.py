from fastapi.testclient import TestClient
from sqlmodel import Session

from .conftest import client


def test_registration_success(test_session: Session, client: TestClient):
    user_data = {
        "username": "User1",
        "email": "user@example.com",
        "password": "Hithere04#"
    }

    response = client.post(
        "/auth/register/",
        json=user_data
    )

    data = response.json()
    assert response.status_code == 201
    assert data["id"] is not None
    assert data["username"] == user_data["username"]
    assert data["email"] == user_data["email"]
    assert not data.get("password")
    assert data["is_active"] == True
    assert data["is_superuser"] == False
    assert data["updated_at"] is not None
    assert data["created_at"] is not None


def test_registration_invalid_password(test_session: Session, client: TestClient):
    user_data = {
        "username": "User2",
        "email": "user@example.com",
        "password": "Hello"
    }

    response = client.post(
        "/auth/register/",
        json=user_data
    )

    assert response.status_code == 400


def test_registration_duplicate_user(test_session: Session, client: TestClient):
    user_data = {
        "username": "User1",
        "email": "user@example.com",
        "password": "Hithere04#"
    }

    response = client.post(
        "/auth/register/",
        json=user_data
    )

    assert response.status_code == 409
