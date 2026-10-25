import pytest
from main import app
from database import init_db, SessionLocal
import db_models
from modules.auth_module import get_current_user

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    init_db()

@pytest.fixture(autouse=True)
def default_auth_override():
    mock_user = db_models.User(
        id=1,
        name="Test Investigator",
        email="test@investigator.local",
        password_hash="hashed",
        role="admin",
        is_active=True
    )
    app.dependency_overrides[get_current_user] = lambda: mock_user
    yield
    app.dependency_overrides.pop(get_current_user, None)
