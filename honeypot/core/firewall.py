"""
Firewall Model - Attack Detection Module

This module provides the main interface for detecting malicious traffic.
It uses pre-trained ML models (DistilBERT for SQLi, XGBoost for network traffic)
via the unified ml_classifier module.

The predict() interface remains unchanged for backward compatibility.
"""

import logging
from core.ml_classifier import ml_classifier

logger = logging.getLogger("firewall")


class FirewallModel:
    """
    Firewall model that uses pre-trained ML classifiers for attack detection.
    
    This replaces the previous TF-IDF + RandomForest approach with:
    - DistilBERT for SQL injection detection
    - XGBoost for network traffic analysis
    - Regex heuristics as a fast-path fallback
    """

    def __init__(self):
        self.is_trained = True  # Pre-trained models are always "trained"
        self._classifier = ml_classifier
        
        if self._classifier.models_loaded:
            logger.info("Firewall initialized with pre-trained ML classifiers")
        else:
            logger.warning("Firewall initialized with heuristics only (ML models not loaded)")

    def _train_model(self):
        """
        No-op for compatibility. Pre-trained models don't need training.
        This method is kept for backward compatibility with main.py lifespan.
        """
        logger.info("Firewall using pre-trained models (no training needed)")
        pass

    def predict(self, text: str, packet_data: dict = None) -> bool:
        """
        Analyze input for malicious content.
        
        Args:
            text: The request text to analyze (method, path, query params, body)
            packet_data: Optional network packet features for XGBoost analysis
            
        Returns:
            True if malicious (should be blocked/trapped), False if safe
        """
        if not text:
            return False
            
        # Delegate to the unified ML classifier
        return self._classifier.predict(text, packet_data)

    def predict_detailed(self, text: str, packet_data: dict = None) -> dict:
        """
        Get detailed prediction results from all models.
        
        Returns:
            dict with 'is_malicious', 'sqli_result', 'network_result'
        """
        sqli_result = self._classifier.predict_sqli(text)
        network_result = None
        
        if packet_data:
            network_result = self._classifier.predict_network(packet_data)
        
        # Check heuristics
        heuristic_match = self._classifier._check_heuristics(text)
        
        is_malicious = (
            heuristic_match or 
            sqli_result.get("is_malicious", False) or
            (network_result and network_result.get("is_malicious", False))
        )
        
        return {
            "is_malicious": is_malicious,
            "heuristic_match": heuristic_match,
            "sqli_result": sqli_result,
            "network_result": network_result
        }

    def predict_with_confidence(self, text: str, packet_data: dict = None) -> dict:
        """
        Returns verdict and confidence score for ML analysis.
        
        Args:
            text: The request text to analyze
            packet_data: Optional network packet features
            
        Returns: {"is_malicious": bool, "verdict": str, "confidence": float}
        """
        if not text or len(text) < 2:
            return {"is_malicious": False, "verdict": "SAFE", "confidence": 0.0}
        
        # Get detailed prediction from classifier
        sqli_result = self._classifier.predict_sqli(text)
        
        # Check heuristics first (high confidence)
        if self._classifier._check_heuristics(text):
            return {"is_malicious": True, "verdict": "MALICIOUS", "confidence": 0.95}
        
        # Get confidence from SQLi model
        confidence = sqli_result.get("confidence", 0.0)
        is_malicious = sqli_result.get("is_malicious", False)
        
        # Determine verdict based on confidence thresholds
        if confidence > 0.80 or is_malicious:
            verdict = "MALICIOUS"
        elif confidence > 0.40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        
        return {
            "is_malicious": is_malicious,
            "verdict": verdict,
            "confidence": float(confidence)
        }


# Singleton instance - maintains same interface as before
firewall_model = FirewallModel()
