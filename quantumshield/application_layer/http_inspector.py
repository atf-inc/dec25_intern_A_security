"""HTTP/HTTPS inspection."""

from typing import Dict, Any, Optional
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class HTTPInspector:
    """Inspect HTTP/HTTPS traffic."""
    
    def __init__(self):
        """Initialize HTTP inspector."""
        pass
    
    def inspect(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Inspect HTTP packet."""
        payload = packet.get("payload", b"")
        
        if not payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ")):
            return None
        
        try:
            # Parse HTTP request
            request_line = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")
            method, path, version = request_line.split(" ", 2)
            
            return {
                "method": method,
                "path": path,
                "version": version,
                "is_http": True,
            }
        except Exception:
            return None

