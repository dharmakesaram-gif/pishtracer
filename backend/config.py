import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "./data/GeoLite2-City.mmdb")

# Automatically switch to async sqlite driver if using sqlite
_raw_db_url = os.getenv("DATABASE_URL", "sqlite:///./phishtrace.db")
if _raw_db_url.startswith("sqlite://") and not _raw_db_url.startswith("sqlite+aiosqlite://"):
    _raw_db_url = _raw_db_url.replace("sqlite://", "sqlite+aiosqlite://")

DATABASE_URL = _raw_db_url
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
