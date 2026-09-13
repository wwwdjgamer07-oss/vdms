import os


def _positive_int_from_env(name: str, default: int) -> int:
    """Read an optional positive integer without making startup fragile.

    Hosting dashboards can retain a variable with an empty value.  Treat that
    the same as an unset optional setting so a deployment can still import.
    """
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        return default
    return value if value > 0 else default


raw_database_url = os.getenv("DATABASE_URL")
# Vercel/Neon commonly supply postgres:// or postgresql://.  The project uses
# psycopg v3, so normalize those URLs to the installed SQLAlchemy dialect.
if raw_database_url and raw_database_url.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + raw_database_url.removeprefix("postgres://")
elif raw_database_url and raw_database_url.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + raw_database_url.removeprefix("postgresql://")
elif raw_database_url:
    DATABASE_URL = raw_database_url
else:
    # Vercel's deployed source bundle is read-only. This fallback keeps a
    # preview alive, but production must set DATABASE_URL to hosted Postgres.
    DATABASE_URL = "sqlite:////tmp/tavdb.db" if os.getenv("VERCEL") else "sqlite:///./tavdb.db"
JWT_SECRET = os.getenv("JWT_SECRET", "development-secret-change-me")
ACCESS_TOKEN_MINUTES = _positive_int_from_env("ACCESS_TOKEN_MINUTES", 60)
