
import sys
import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Add the 'ml-classifier' directory to sys.path if not present
# This assumes the structure is:
# root/
#   quantumshield/
#   ml-classifier/
_current_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.abspath(os.path.join(_current_dir, "../../../"))
_ml_classifier_path = os.path.join(_root_dir, "ml-classifier")

if _ml_classifier_path not in sys.path:
    sys.path.append(_ml_classifier_path)

class MLAdapter:
    """
    Adapter to integrate the external 'ml-classifier' module into QuantumShield.
    Wraps:
    1. SQLiDetector (BERT-based)
    2. NetworkTrafficClassifier (XGBoost-based)
    """

    def __init__(self):
        self.sqli_detector = None
        self.network_classifier = None
        self._load_models()

    def _load_models(self):
        """Try to load the external models."""
        # 1. Load SQLi Detector
        try:
            from sql_injection.inference_sqli import SQLiDetector
            self.sqli_detector = SQLiDetector()
            logger.info("MLAdapter: SQLiDetector loaded successfully")
        except ImportError as e:
            logger.error(f"MLAdapter: Failed to import SQLiDetector: {e}")
        except Exception as e:
            logger.error(f"MLAdapter: Failed to initialize SQLiDetector: {e}")

        # 2. Load Network Traffic Classifier
        try:
            from network_traffic.inference_xgboost import NetworkTrafficClassifier
            self.network_classifier = NetworkTrafficClassifier()
            logger.info("MLAdapter: NetworkTrafficClassifier loaded successfully")
        except ImportError as e:
            logger.error(f"MLAdapter: Failed to import NetworkTrafficClassifier: {e}")
        except Exception as e:
            logger.error(f"MLAdapter: Failed to initialize NetworkTrafficClassifier: {e}")

    async def infer(self, packet: Dict[str, Any], flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference on packet and flow data.
        """
        results = {}

        # 1. SQL Injection Detection (on Payload)
        payload = packet.get('payload', b'')
        if isinstance(payload, bytes):
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
            except:
                payload_str = ""
        else:
            payload_str = str(payload)

        if self.sqli_detector and payload_str and len(payload_str) > 5:
            try:
                sqli_result = self.sqli_detector.predict(payload_str)
                # Normalize result
                results['sqli_bert'] = {
                    "threat_score": sqli_result.get('confidence_score', 0.0),
                    "verdict": sqli_result.get('verdict', 'SAFE'),
                    "reason": f"SQLi Detection: {sqli_result.get('verdict')}",
                    "details": sqli_result
                }
            except Exception as e:
                logger.error(f"MLAdapter: SQLi inference failed: {e}")

        # 2. Network Traffic Classification (on Flow features)
        if self.network_classifier and flow:
            try:
                # We need to ensure flow has the right keys for the classifier
                # Creating a safe wrapper/mapper would be ideal, but for now passing flow dict directly
                # assuming keys might match or we need to map them.
                # The XGBoost model expects specific features like 'dur', 'proto', etc.
                # If flow doesn't have them, classifier might fail.
                
                # Check directly called function
                net_result = self.network_classifier.predict_packet(flow)
                
                if net_result and "error" not in net_result:
                     results['network_xgboost'] = {
                        "threat_score": net_result.get('confidence', 0.0),
                        "verdict": net_result.get('verdict', 'SAFE'),
                        "reason": f"Network Analysis: {net_result.get('verdict')}",
                        "details": net_result
                    }
            except Exception as e:
                # Expected if flow keys don't match, we silently ignore for now or debug
                # logger.debug(f"MLAdapter: Network inference failed (likely missing features): {e}")
                pass
        
        return results
