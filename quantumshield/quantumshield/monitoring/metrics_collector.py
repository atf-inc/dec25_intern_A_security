"""Metrics collection for monitoring."""

from typing import Dict, Any
from collections import defaultdict
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class MetricsCollector:
    """Collect system and security metrics."""
    
    def __init__(self):
        """Initialize metrics collector."""
        self.metrics: Dict[str, Any] = defaultdict(int)
    
    def increment(self, metric_name: str, value: int = 1) -> None:
        """Increment a metric."""
        self.metrics[metric_name] += value
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics."""
        return dict(self.metrics)

