"""
Unified ML Classifier Module

This module provides a unified interface for the pre-trained ML models:
- SQLiDetector (DistilBERT) for SQL injection detection
- NetworkTrafficClassifier (XGBoost) for network traffic analysis

Both SUSPICIOUS and MALICIOUS verdicts are treated as malicious (blocked).
"""

import os
import sys
import logging
import re

logger = logging.getLogger("ml_classifier")

# Add ml-classifier to Python path
# Path: honeypot/core/ml_classifier.py -> honeypot/core -> honeypot -> aitf -> aitf/ml-classifier
ML_CLASSIFIER_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "ml-classifier")
)
if ML_CLASSIFIER_PATH not in sys.path:
    sys.path.insert(0, ML_CLASSIFIER_PATH)


class UnifiedMLClassifier:
    """
    Unified interface for all ML-based attack detection models.
    """

    def __init__(self):
        self.sqli_detector = None
        self.network_classifier = None
        self.models_loaded = False
        self._load_models()

    def _load_models(self):
        """Load the pre-trained ML models."""
        # Load SQL Injection Detector
        try:
            from sql_injection.inference_sqli import SQLiDetector
            self.sqli_detector = SQLiDetector()
            logger.info("SQLi Detector (DistilBERT) loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load SQLi Detector: {e}")
            self.sqli_detector = None

        # Load Network Traffic Classifier
        try:
            from network_traffic.inference_xgboost import NetworkTrafficClassifier
            self.network_classifier = NetworkTrafficClassifier()
            logger.info("Network Traffic Classifier (XGBoost) loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load Network Traffic Classifier: {e}")
            self.network_classifier = None

        self.models_loaded = (self.sqli_detector is not None) or (self.network_classifier is not None)
        
        if not self.models_loaded:
            logger.error("No ML models could be loaded! Falling back to heuristics only.")

    def predict_sqli(self, text: str) -> dict:
        """
        Analyze text for SQL injection using DistilBERT model.
        
        Returns:
            dict with 'is_malicious', 'verdict', 'confidence'
        """
        if not self.sqli_detector or not text or len(text) < 2:
            return {"is_malicious": False, "verdict": "SKIPPED", "confidence": 0.0}

        try:
            result = self.sqli_detector.predict(text)
            verdict = result.get("verdict", "SAFE")
            confidence = result.get("confidence_score", 0.0)
            
            # SUSPICIOUS and MALICIOUS are treated as malicious (block)
            is_malicious = verdict in ("SUSPICIOUS", "MALICIOUS")
            
            return {
                "is_malicious": is_malicious,
                "verdict": verdict,
                "confidence": confidence
            }
        except Exception as e:
            logger.error(f"SQLi prediction error: {e}")
            return {"is_malicious": False, "verdict": "ERROR", "confidence": 0.0}

    def predict_network(self, packet_data: dict) -> dict:
        """
        Analyze network packet features using XGBoost model.
        
        Args:
            packet_data: Dictionary of network features (dur, proto, sbytes, etc.)
            
        Returns:
            dict with 'is_malicious', 'verdict', 'confidence'
        """
        if not self.network_classifier or not packet_data:
            return {"is_malicious": False, "verdict": "SKIPPED", "confidence": 0.0}

        try:
            result = self.network_classifier.predict_packet(packet_data)
            
            if "error" in result:
                return {"is_malicious": False, "verdict": "ERROR", "confidence": 0.0}
            
            verdict = result.get("verdict", "SAFE")
            confidence = result.get("confidence", 0.0)
            
            # SUSPICIOUS and MALICIOUS are treated as malicious (block)
            is_malicious = verdict in ("SUSPICIOUS", "MALICIOUS")
            
            return {
                "is_malicious": is_malicious,
                "verdict": verdict,
                "confidence": confidence
            }
        except Exception as e:
            logger.error(f"Network traffic prediction error: {e}")
            return {"is_malicious": False, "verdict": "ERROR", "confidence": 0.0}

    def _extract_payloads(self, text: str) -> list:
        """
        Extract potentially dangerous payloads from HTTP request text.
        
        The SQLi model was trained on raw payloads, not full HTTP requests.
        We extract: query parameter values, form body values, and any 
        suspicious-looking fragments.
        """
        payloads = []
        
        # Split into lines (first line is usually "METHOD /path query", rest is body)
        lines = text.strip().split('\n')
        
        # Extract query parameters from first line (e.g., "GET /search?q=test&id=1")
        if lines:
            first_line = lines[0]
            # Look for query string after ?
            if '?' in first_line:
                after_question = first_line.split('?', 1)[1]
                # Get query part (before any whitespace that might follow)
                query_parts = after_question.split()
                query_part = query_parts[0] if query_parts else ""
                # Parse key=value pairs
                for param in query_part.split('&'):
                    if '=' in param:
                        value = param.split('=', 1)[1]
                        if value:
                            payloads.append(value)
        
        # Extract body content (everything after first line)
        if len(lines) > 1:
            body = '\n'.join(lines[1:]).strip()
            if body:
                # For form data (key=value&key2=value2)
                if '=' in body and not body.startswith('{'):
                    for param in body.split('&'):
                        if '=' in param:
                            value = param.split('=', 1)[1]
                            if value:
                                payloads.append(value)
                else:
                    # For JSON or raw body, analyze the whole thing
                    payloads.append(body)
        
        return payloads

    def predict(self, text: str, packet_data: dict = None) -> bool:
        """
        Unified prediction interface - returns True if malicious.
        
        This is the main entry point that checks:
        1. Regex heuristics (fast path) on full text
        2. SQLi detector on extracted payloads (query params, body values)
        3. Network classifier on packet data (if provided)
        
        Args:
            text: The request text to analyze (method, path, query, body)
            packet_data: Optional network packet features for XGBoost
            
        Returns:
            True if malicious (should be blocked), False if safe
        """
        if not text or len(text) < 2:
            return False

        # 1. Fast-path: Regex heuristics on full text
        if self._check_heuristics(text):
            logger.warning(f"ML Classifier HEURISTIC BLOCK: '{text[:100]}...'")
            return True

        # 2. SQLi Detection on extracted payloads only
        # The model was trained on raw payloads, not full HTTP requests
        payloads = self._extract_payloads(text)
        
        for payload in payloads:
            if len(payload) < 2:
                continue
            sqli_result = self.predict_sqli(payload)
            if sqli_result["is_malicious"]:
                logger.warning(
                    f"ML Classifier SQLi BLOCK: payload='{payload[:50]}...' "
                    f"(verdict={sqli_result['verdict']}, confidence={sqli_result['confidence']:.2f})"
                )
                return True

        # 3. Network Traffic Analysis (if packet data available)
        if packet_data:
            net_result = self.predict_network(packet_data)
            if net_result["is_malicious"]:
                logger.warning(
                    f"ML Classifier Network BLOCK: "
                    f"(verdict={net_result['verdict']}, confidence={net_result['confidence']:.2f})"
                )
                return True

        # Safe
        logger.info(f"ML Classifier ALLOWED: '{text[:80]}...'")
        return False

    def _check_heuristics(self, text: str) -> bool:
        """
        Fast regex-based heuristics for common attack patterns.
        These provide a safety net even if ML models fail to load.
        """
        patterns = [
            # SQL Injection patterns
            r"(?i)(\bOR\b|\bUNION\b|\bSELECT\b).{0,10}(\bFROM\b|\bWHERE\b|\d=)",
            r"(?i)'\s*OR\s*\d=\d",
            r"(?i)'\s*OR\s*'[^']*'\s*=\s*'",
            r"(?i)--\s*$",
            r"(?i);\s*DROP\s+TABLE",
            # XSS patterns
            r"(?i)<script",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=",
            # Command Injection
            r"(?i);\s*(cat|ls|whoami|id|pwd|wget|curl)\b",
            r"\$\([^)]+\)",
            r"`[^`]+`",
        ]
        
        for pattern in patterns:
            if re.search(pattern, text):
                return True
        return False


# Singleton instance
ml_classifier = UnifiedMLClassifier()

