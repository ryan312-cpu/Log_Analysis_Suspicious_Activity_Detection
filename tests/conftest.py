import os

os.environ["APP_ENV"] = "test"
os.environ["API_KEY"] = "test-analyst-key"
os.environ["ADMIN_API_KEY"] = "test-admin-key"
os.environ["RATE_LIMIT_DISABLED"] = "1"
os.environ["ALLOW_ORIGINS"] = "http://localhost:5173"

from src.api.security.config import clear_api_key_cache  # noqa: E402

clear_api_key_cache()

ANALYST_HEADERS = {"X-API-Key": os.environ["API_KEY"]}
ADMIN_HEADERS = {"X-API-Key": os.environ["ADMIN_API_KEY"]}
