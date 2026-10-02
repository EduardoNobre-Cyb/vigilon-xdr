#!/bin/sh
set -e

echo "[entrypoint] Waiting for PostgreSQL..."
python - <<'PY'
import os
import time
from sqlalchemy import create_engine, text

url = os.environ["DATABASE_URL"]
engine = create_engine(url)

for attempt in range(1, 61):
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("[entrypoint] PostgreSQL is ready")
        break
    except Exception as exc:
        if attempt == 60:
            raise RuntimeError(f"PostgreSQL not ready after {attempt} attempts: {exc}")
        time.sleep(2)
PY

echo "[entrypoint] Initializing database schema..."
PYTHONPATH=/app python scripts/init_database.py

echo "[entrypoint] Ensuring NLTK corpora are available..."
python - <<'PY'
import nltk
nltk.download("punkt", quiet=True)
nltk.download("wordnet", quiet=True)
nltk.download("omw-1.4", quiet=True)
PY

echo "[entrypoint] Starting dashboard"
exec python -m dashboard.app
