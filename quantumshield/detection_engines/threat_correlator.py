"""Threat correlation across multiple detection engines."""

from typing import Dict, Any, List
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class ThreatCorrelator:
    """Correlate threats across multiple detection engines."""
    
    def __init__(self):
        """Initialize threat correlator."""
        self.correlation_rules = []
    
    async def initialize(self) -> None:
        """Initialize threat correlator."""
        logger.info("Initializing threat correlator")
    
    def correlate(
        self, analysis_results: Dict[str, Any], time_window: int = 300
    ) -> Dict[str, Any]:
        """
        Correlate analysis results from multiple engines.
        
        Args:
            analysis_results: Results from all detection engines
            time_window: Time window for correlation in seconds
        
        Returns:
            Correlated threat assessment
        """
        # Aggregate threat scores
        scores = []
        for engine, result in analysis_results.items():
            if result and isinstance(result, dict):
                score = result.get("threat_score", 0.0)
                if score > 0:
                    scores.append(score)
        
        # Calculate correlated threat score
        if not scores:
            return {"correlated_threat_score": 0.0, "confidence": 0.0}
        
        # Use maximum score as base, but boost if multiple engines agree
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        
        # Boost score if multiple engines detected threat
        if len(scores) > 1:
            correlated_score = min(1.0, max_score + (avg_score * 0.2))
        else:
            correlated_score = max_score
        
        # Calculate confidence based on agreement
        confidence = min(1.0, len(scores) / 4.0)  # Max confidence with 4+ engines
        
        return {
            "correlated_threat_score": correlated_score,
            "confidence": confidence,
            "engine_count": len(scores),
        }

