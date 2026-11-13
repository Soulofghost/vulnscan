import os
from pydantic import BaseModel

class Settings(BaseModel):
    PORT: int = int(os.getenv("PORT", "8000"))
    VULNSCAN_DB: str = os.getenv("VULNSCAN_DB", "vulnscan.db")

settings = Settings()
