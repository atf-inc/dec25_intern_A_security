"""Base class for security tool integrations."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import structlog
from ...config.logging_config import get_logger

logger = get_logger(__name__)


class BaseIntegration(ABC):
    """Base class for all security tool integrations."""
    
    def __init__(self, tool_path: str, config_path: Optional[str] = None):
        """
        Initialize integration.
        
        Args:
            tool_path: Path to the security tool executable
            config_path: Path to tool configuration file
        """
        self.tool_path = tool_path
        self.config_path = config_path
        self.enabled = False
        self.process = None
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the integration."""
        pass
    
    @abstractmethod
    async def start(self) -> None:
        """Start the security tool."""
        pass
    
    @abstractmethod
    async def stop(self) -> None:
        """Stop the security tool."""
        pass
    
    @abstractmethod
    async def analyze(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze packet using the security tool.
        
        Returns:
            Analysis results or None
        """
        pass
    
    async def health_check(self) -> bool:
        """Check if the tool is healthy."""
        return self.enabled and self.process is not None
    
    async def get_status(self) -> Dict[str, Any]:
        """Get integration status."""
        return {
            "enabled": self.enabled,
            "tool_path": self.tool_path,
            "healthy": await self.health_check(),
        }

