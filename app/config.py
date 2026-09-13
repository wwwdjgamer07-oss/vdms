import os
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./tavdb.db")
JWT_SECRET = os.getenv("JWT_SECRET", "development-secret-change-me")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
