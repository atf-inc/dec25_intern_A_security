"""ML model lifecycle management."""

import asyncio
from typing import Dict, Any, Optional
import structlog
from pathlib import Path
import torch
from ..config.settings import get_settings
from ..config.logging_config import get_logger
from .traffic_classifier.model import TrafficClassifier
from .anomaly_detector.autoencoder import AnomalyDetector

logger = get_logger(__name__)


class ModelManager:
    """Manage ML models lifecycle and inference."""
    
    def __init__(self):
        """Initialize model manager."""
        self.settings = get_settings()
        self.models: Dict[str, Any] = {}
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() and self.settings.ml_enable_gpu
            else "cpu"
        )
        logger.info("Model manager device", device=str(self.device))
    
    async def initialize(self) -> None:
        """Initialize and load all ML models."""
        logger.info("Initializing ML models")
        
        try:
            # Load traffic classifier
            self.models["traffic_classifier"] = TrafficClassifier()
            await self.models["traffic_classifier"].load_model()
            
            # Load anomaly detector
            self.models["anomaly_detector"] = AnomalyDetector()
            await self.models["anomaly_detector"].load_model()
            
            logger.info("ML models loaded", count=len(self.models))
        
        except Exception as e:
            logger.error("Failed to load ML models", error=str(e), exc_info=True)
            # Continue with limited functionality
    
    async def infer(
        self, packet: Dict[str, Any], flow: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Run inference on packet/flow using all models.
        
        Returns:
            Aggregated ML inference results
        """
        results = {}
        
        # Run traffic classifier
        if "traffic_classifier" in self.models:
            try:
                classifier_result = await self.models["traffic_classifier"].infer(packet, flow)
                results["traffic_classifier"] = classifier_result
            except Exception as e:
                logger.error("Traffic classifier inference failed", error=str(e))
        
        # Run anomaly detector
        if "anomaly_detector" in self.models:
            try:
                anomaly_result = await self.models["anomaly_detector"].infer(packet, flow)
                results["anomaly_detector"] = anomaly_result
            except Exception as e:
                logger.error("Anomaly detector inference failed", error=str(e))
        
        # Aggregate results
        if results:
            threat_score = self._aggregate_threat_score(results)
            return {
                "threat_score": threat_score,
                "model_results": results,
                "engine": "ml",
                "reason": self._get_reason(results),
            }
        
        return None
    
    def _aggregate_threat_score(self, results: Dict[str, Any]) -> float:
        """Aggregate threat scores from multiple models."""
        scores = []
        
        for model_name, result in results.items():
            if isinstance(result, dict):
                score = result.get("threat_score", 0.0)
                if isinstance(score, (int, float)):
                    scores.append(score)
        
        if not scores:
            return 0.0
        
        # Use weighted average (can be customized)
        return min(1.0, sum(scores) / len(scores))
    
    def _get_reason(self, results: Dict[str, Any]) -> str:
        """Get human-readable reason from ML results."""
        reasons = []
        
        for model_name, result in results.items():
            if isinstance(result, dict):
                reason = result.get("reason", "")
                if reason:
                    reasons.append(f"{model_name}: {reason}")
        
        return "; ".join(reasons) if reasons else "ML analysis completed"
    
    async def cleanup(self) -> None:
        """Cleanup model resources."""
        logger.info("Cleaning up ML models")
        self.models.clear()

