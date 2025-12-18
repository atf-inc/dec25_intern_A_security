from slowapi import Limiter
from slowapi.util import get_remote_address
from config import settings

# Create rate limiter instance
# Key function determines how to identify unique clients (by IP address)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"]
)
