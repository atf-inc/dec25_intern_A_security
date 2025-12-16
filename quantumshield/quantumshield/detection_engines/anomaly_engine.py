"""Anomaly-based detection engine."""

import statistics
from typing import Dict, Any, Optional
from collections import defaultdict
import structlog
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class AnomalyEngine:
    """Statistical anomaly detection engine."""
    
    def __init__(self):
        """Initialize anomaly engine."""
        self.baselines: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.stats: Dict[str, list] = defaultdict(list)
        self.threshold_multiplier = 3.0  # 3-sigma rule
    
    async def initialize(self) -> None:
        """Initialize anomaly engine."""
        logger.info("Initializing anomaly engine")
        # Load baselines or start learning phase
    
    async def analyze(
        self, packet: Dict[str, Any], flow: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze packet/flow for anomalies.
        
        Returns:
            Dict with threat_score, is_anomaly, and anomaly_details
        """
        src_ip = packet.get("src_ip", "unknown")
        
        # Extract features
        features = {
            "packet_size": packet.get("length", 0),
            "payload_size": packet.get("payload_length", 0),
            "port": packet.get("dst_port", 0),
        }
        
        # Check for anomalies
        anomalies = []
        threat_score = 0.0
        
        for feature_name, value in features.items():
            if value is None:
                continue
            
            # Get baseline stats
            baseline_key = f"{src_ip}_{feature_name}"
            if baseline_key in self.baselines:
                baseline = self.baselines[baseline_key]
                mean = baseline.get("mean", 0)
                std = baseline.get("std", 1)
                
                if std > 0:
                    z_score = abs((value - mean) / std)
                    if z_score > self.threshold_multiplier:
                        anomalies.append({
                            "feature": feature_name,
                            "value": value,
                            "baseline_mean": mean,
                            "z_score": z_score,
                        })
                        threat_score = max(threat_score, min(1.0, z_score / 5.0))
            
            # Update statistics
            self.stats[baseline_key].append(value)
            if len(self.stats[baseline_key]) > 1000:
                self.stats[baseline_key] = self.stats[baseline_key][-1000:]
            
            # Update baseline periodically
            if len(self.stats[baseline_key]) % 100 == 0:
                self._update_baseline(baseline_key)
        
        if anomalies:
            logger.warning(
                "Anomaly detected",
                anomalies=len(anomalies),
                src_ip=src_ip,
            )
            
            return {
                "threat_score": threat_score,
                "is_anomaly": True,
                "anomaly_details": anomalies,
                "engine": "anomaly",
            }
        
        return {
            "threat_score": 0.0,
            "is_anomaly": False,
            "engine": "anomaly",
        }
    
    def _update_baseline(self, key: str) -> None:
        """Update baseline statistics."""
        if key not in self.stats or len(self.stats[key]) < 10:
            return
        
        values = self.stats[key]
        mean = statistics.mean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        
        self.baselines[key] = {
            "mean": mean,
            "std": std,
        }

