import pytest

from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine, Session
from sqlmodel.pool import StaticPool

from app.main import app
from app.db.session import get_session
from app.models.user_models import User

TEST_DATABASE_URL = "sqlite://"
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)


@pytest.fixture(scope="session")
def setup_database():
    # Create all tables in the test database
    SQLModel.metadata.create_all(test_engine)
    yield
    # Optionally drop tables after tests
    SQLModel.metadata.drop_all(test_engine)


@pytest.fixture(scope="function")
def test_session(setup_database):
    with Session(test_engine) as session:
        yield session


@pytest.fixture(scope="function")
def client(test_session, monkeypatch):
    # Override the database dependency
    def override_get_session():
        yield test_session

    app.dependency_overrides[get_session] = override_get_session
    return TestClient(app)
