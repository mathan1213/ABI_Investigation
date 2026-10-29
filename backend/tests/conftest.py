import json
import pytest
from main import app
from database import init_db, SessionLocal
import db_models
from modules.auth_module import get_current_user, ALL_PERMISSIONS, _login_attempts, _username_checks

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    init_db()

@pytest.fixture(autouse=True)
def reset_rate_limits():
    _login_attempts.clear()
    _username_checks.clear()
    yield
    _login_attempts.clear()
    _username_checks.clear()

@pytest.fixture(autouse=True)
def default_auth_override():
    mock_user = db_models.User(
        id=1,
        name="Test Investigator",
        username="test_investigator",
        username_lower="test_investigator",
        email="test@investigator.local",
        password_hash="hashed",
        role="super_admin",
        is_active=True,
        is_email_verified=True,
        token_version=1,
        permissions=json.dumps(ALL_PERMISSIONS),
    )
    app.dependency_overrides[get_current_user] = lambda: mock_user
    yield
    app.dependency_overrides.pop(get_current_user, None)
