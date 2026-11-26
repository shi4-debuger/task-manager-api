import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import Base, app, get_db

# --- Isolated Test Database Setup ---
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test_tasks.db"
engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_and_teardown_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# --- Helper Function ---
def get_auth_headers(username: str, password: str = "secret123"):
    client.post("/signup", json={"username": username, "password": password})
    response = client.post(
        "/login", data={"username": username, "password": password}
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# --- Automated Tests ---
def test_signup_and_duplicate_prevention():
    res1 = client.post("/signup", json={"username": "alice", "password": "secret123"})
    assert res1.status_code == 201
    assert res1.json()["username"] == "alice"

    res2 = client.post("/signup", json={"username": "alice", "password": "secret123"})
    assert res2.status_code == 400


def test_login_invalid_credentials():
    client.post("/signup", json={"username": "alice", "password": "secret123"})
    res = client.post("/login", data={"username": "alice", "password": "wrongpassword"})
    assert res.status_code == 401


def test_unauthenticated_access_blocked():
    res = client.get("/tasks/")
    assert res.status_code == 401


def test_crud_and_user_isolation():
    alice_headers = get_auth_headers("alice")
    bob_headers = get_auth_headers("bob")

    # 1. Alice creates a task
    create_res = client.post(
        "/tasks/",
        json={"title": "Alice Secret Task", "description": "Private", "completed": False},
        headers=alice_headers,
    )
    assert create_res.status_code == 201
    task_id = create_res.json()["id"]

    # 2. Bob fetches tasks -> should see an empty list
    bob_tasks = client.get("/tasks/", headers=bob_headers)
    assert bob_tasks.status_code == 200
    assert bob_tasks.json() == []

    # 3. Bob tries to delete Alice's task -> should get 404
    bob_delete = client.delete(f"/tasks/{task_id}", headers=bob_headers)
    assert bob_delete.status_code == 404

    # 4. Alice updates her own task
    update_res = client.put(
        f"/tasks/{task_id}",
        json={"title": "Alice Updated Task", "description": "Done", "completed": True},
        headers=alice_headers,
    )
    assert update_res.status_code == 200
    assert update_res.json()["completed"] is True

    # 5. Alice deletes her own task
    del_res = client.delete(f"/tasks/{task_id}", headers=alice_headers)
    assert del_res.status_code == 204