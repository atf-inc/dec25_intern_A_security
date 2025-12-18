"""
State Encoder for Reinforcement Learning
Converts threat context and traffic data into state vectors for RL agent
"""

import numpy as np
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

from ..core.decision_maker import ThreatContext, ThreatIndicator, ThreatLevel

logger = logging.getLogger(__name__)


class StateEncoder:
    """Encodes threat context into numerical state vectors for RL."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.state_size = self.config.get('state_size', 128)
        self.feature_scaling = self.config.get('feature_scaling', True)
        
        # Feature dimensions
        self.feature_dims = {
            'network': 20,      # IP, port, protocol features
            'indicators': 30,   # Threat indicator features
            'behavioral': 25,  # Behavioral pattern features
            'temporal': 15,    # Time-based features
            'ml_scores': 10,   # ML model scores
            'reputation': 8,   # Reputation scores
            'flow_stats': 20   # Flow statistics
        }
        
        # Normalization parameters (learned from data)
        self.normalization_stats = {
            'packet_count': {'mean': 100, 'std': 50},
            'byte_count': {'mean': 10000, 'std': 5000},
            'duration': {'mean': 60, 'std': 30},
            'threat_score': {'mean': 0.5, 'std': 0.3}
        }
    
    def encode(self, context: ThreatContext, 
               flow_data: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """
        Encode threat context into state vector.
        
        Args:
            context: ThreatContext object
            flow_data: Optional flow data dictionary
            
        Returns:
            State vector as numpy array
        """
        features = []
        
        # Network features
        features.extend(self._encode_network_features(context))
        
        # Threat indicator features
        features.extend(self._encode_indicator_features(context))
        
        # Behavioral features
        features.extend(self._encode_behavioral_features(context, flow_data))
        
        # Temporal features
        features.extend(self._encode_temporal_features(context))
        
        # ML scores
        features.extend(self._encode_ml_scores(context))
        
        # Reputation scores
        features.extend(self._encode_reputation_features(context))
        
        # Flow statistics
        features.extend(self._encode_flow_stats(context, flow_data))
        
        # Pad or truncate to desired state size
        state = np.array(features, dtype=np.float32)
        
        if len(state) < self.state_size:
            # Pad with zeros
            padding = np.zeros(self.state_size - len(state), dtype=np.float32)
            state = np.concatenate([state, padding])
        elif len(state) > self.state_size:
            # Truncate
            state = state[:self.state_size]
        
        # Normalize if enabled
        if self.feature_scaling:
            state = self._normalize_state(state)
        
        return state
    
    def _encode_network_features(self, context: ThreatContext) -> List[float]:
        """Encode network-level features."""
        features = []
        
        # IP address encoding (hash-based)
        src_ip_hash = hash(context.source_ip) % 1000 / 1000.0
        dst_ip_hash = hash(context.destination_ip) % 1000 / 1000.0
        features.extend([src_ip_hash, dst_ip_hash])
        
        # Port encoding (normalized)
        src_port_norm = context.source_port / 65535.0
        dst_port_norm = context.destination_port / 65535.0
        features.extend([src_port_norm, dst_port_norm])
        
        # Protocol encoding (one-hot like)
        protocol_map = {
            'TCP': [1, 0, 0, 0],
            'UDP': [0, 1, 0, 0],
            'ICMP': [0, 0, 1, 0],
            'HTTP': [1, 0, 0, 1],
            'HTTPS': [1, 0, 0, 1]
        }
        protocol_features = protocol_map.get(context.protocol.upper(), [0, 0, 0, 0])
        features.extend(protocol_features)
        
        # Well-known port indicators
        well_known_ports = [80, 443, 22, 21, 25, 53, 3306, 5432, 27017]
        is_well_known_src = 1.0 if context.source_port in well_known_ports else 0.0
        is_well_known_dst = 1.0 if context.destination_port in well_known_ports else 0.0
        features.extend([is_well_known_src, is_well_known_dst])
        
        # Port ranges
        is_ephemeral_src = 1.0 if 49152 <= context.source_port <= 65535 else 0.0
        is_ephemeral_dst = 1.0 if 49152 <= context.destination_port <= 65535 else 0.0
        features.extend([is_ephemeral_src, is_ephemeral_dst])
        
        # Internal IP indicators
        is_internal_src = self._is_internal_ip(context.source_ip)
        is_internal_dst = self._is_internal_ip(context.destination_ip)
        features.extend([float(is_internal_src), float(is_internal_dst)])
        
        # Additional network features
        features.extend([0.0] * (self.feature_dims['network'] - len(features)))
        
        return features[:self.feature_dims['network']]
    
    def _encode_indicator_features(self, context: ThreatContext) -> List[float]:
        """Encode threat indicator features."""
        features = []
        
        if not context.indicators:
            return [0.0] * self.feature_dims['indicators']
        
        # Aggregate indicator statistics
        severities = [ind.severity.value for ind in context.indicators]
        confidences = [ind.confidence for ind in context.indicators]
        indicator_types = set(ind.indicator_type for ind in context.indicators)
        
        # Max severity (normalized)
        max_severity = max(severities) / 5.0 if severities else 0.0
        features.append(max_severity)
        
        # Average severity
        avg_severity = sum(severities) / len(severities) / 5.0 if severities else 0.0
        features.append(avg_severity)
        
        # Max confidence
        max_confidence = max(confidences) if confidences else 0.0
        features.append(max_confidence)
        
        # Average confidence
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        features.append(avg_confidence)
        
        # Indicator count (normalized)
        indicator_count = min(len(context.indicators) / 10.0, 1.0)
        features.append(indicator_count)
        
        # Indicator type encoding (one-hot for common types)
        common_types = [
            'signature', 'anomaly', 'behavioral', 'ml', 'correlation',
            'sql_injection', 'xss', 'command_injection', 'ddos', 'malware'
        ]
        for ind_type in common_types:
            features.append(1.0 if ind_type in indicator_types else 0.0)
        
        # Time since first indicator
        if context.indicators:
            first_indicator_time = min(ind.timestamp for ind in context.indicators)
            time_since_first = (context.last_seen - first_indicator_time) / 3600.0  # hours
            features.append(min(time_since_first, 24.0) / 24.0)
        else:
            features.append(0.0)
        
        # Indicator diversity (number of unique types)
        diversity = len(indicator_types) / 10.0
        features.append(min(diversity, 1.0))
        
        # Pad to required size
        features.extend([0.0] * (self.feature_dims['indicators'] - len(features)))
        
        return features[:self.feature_dims['indicators']]
    
    def _encode_behavioral_features(self, context: ThreatContext,
                                   flow_data: Optional[Dict[str, Any]]) -> List[float]:
        """Encode behavioral pattern features."""
        features = []
        
        # Packet count (normalized)
        packet_count = context.packet_count
        norm_packet_count = min(packet_count / 1000.0, 1.0)
        features.append(norm_packet_count)
        
        # Byte count (normalized)
        byte_count = context.byte_count
        norm_byte_count = min(byte_count / 1000000.0, 1.0)  # 1MB
        features.append(norm_byte_count)
        
        # Flow duration
        duration = context.last_seen - context.start_time
        norm_duration = min(duration / 3600.0, 1.0)  # 1 hour
        features.append(norm_duration)
        
        # Packet rate
        if duration > 0:
            packet_rate = packet_count / duration
            norm_packet_rate = min(packet_rate / 100.0, 1.0)  # 100 pps
            features.append(norm_packet_rate)
        else:
            features.append(0.0)
        
        # Byte rate
        if duration > 0:
            byte_rate = byte_count / duration
            norm_byte_rate = min(byte_rate / 1000000.0, 1.0)  # 1MB/s
            features.append(norm_byte_rate)
        else:
            features.append(0.0)
        
        # Additional behavioral features from flow_data
        if flow_data:
            # Connection state
            conn_state = flow_data.get('connection_state', 'unknown')
            state_map = {
                'new': [1, 0, 0, 0],
                'established': [0, 1, 0, 0],
                'closing': [0, 0, 1, 0],
                'closed': [0, 0, 0, 1]
            }
            state_features = state_map.get(conn_state.lower(), [0, 0, 0, 0])
            features.extend(state_features)
            
            # Retransmission rate
            retrans_rate = flow_data.get('retransmission_rate', 0.0)
            features.append(min(retrans_rate, 1.0))
            
            # Window size (normalized)
            window_size = flow_data.get('window_size', 0)
            norm_window = min(window_size / 65535.0, 1.0)
            features.append(norm_window)
        else:
            features.extend([0.0] * 6)
        
        # Pad to required size
        features.extend([0.0] * (self.feature_dims['behavioral'] - len(features)))
        
        return features[:self.feature_dims['behavioral']]
    
    def _encode_temporal_features(self, context: ThreatContext) -> List[float]:
        """Encode temporal/time-based features."""
        features = []
        
        # Time of day (sine/cosine encoding for cyclical nature)
        now = datetime.fromtimestamp(context.last_seen)
        hour = now.hour
        hour_sin = np.sin(2 * np.pi * hour / 24)
        hour_cos = np.cos(2 * np.pi * hour / 24)
        features.extend([hour_sin, hour_cos])
        
        # Day of week
        day_of_week = now.weekday()
        day_sin = np.sin(2 * np.pi * day_of_week / 7)
        day_cos = np.cos(2 * np.pi * day_of_week / 7)
        features.extend([day_sin, day_cos])
        
        # Is weekend
        is_weekend = 1.0 if day_of_week >= 5 else 0.0
        features.append(is_weekend)
        
        # Is business hours (8 AM - 6 PM)
        is_business_hours = 1.0 if 8 <= hour < 18 else 0.0
        features.append(is_business_hours)
        
        # Time since start of flow
        time_since_start = context.last_seen - context.start_time
        norm_time_since_start = min(time_since_start / 3600.0, 1.0)
        features.append(norm_time_since_start)
        
        # Time since last indicator
        if context.indicators:
            last_indicator_time = max(ind.timestamp for ind in context.indicators)
            time_since_indicator = (context.last_seen - last_indicator_time) / 60.0  # minutes
            norm_time_since_indicator = min(time_since_indicator / 60.0, 1.0)
            features.append(norm_time_since_indicator)
        else:
            features.append(0.0)
        
        # Pad to required size
        features.extend([0.0] * (self.feature_dims['temporal'] - len(features)))
        
        return features[:self.feature_dims['temporal']]
    
    def _encode_ml_scores(self, context: ThreatContext) -> List[float]:
        """Encode ML model scores."""
        features = []
        
        if not context.ml_scores:
            return [0.0] * self.feature_dims['ml_scores']
        
        # Common ML model scores
        ml_models = [
            'traffic_classifier', 'anomaly_detector', 'ddos_predictor',
            'malware_detector', 'zero_day_detector'
        ]
        
        for model_name in ml_models:
            score = context.ml_scores.get(model_name, 0.0)
            features.append(score)
        
        # Aggregate statistics
        if context.ml_scores:
            scores = list(context.ml_scores.values())
            features.append(max(scores))
            features.append(sum(scores) / len(scores))
            features.append(np.std(scores) if len(scores) > 1 else 0.0)
        else:
            features.extend([0.0] * 3)
        
        # Pad to required size
        features.extend([0.0] * (self.feature_dims['ml_scores'] - len(features)))
        
        return features[:self.feature_dims['ml_scores']]
    
    def _encode_reputation_features(self, context: ThreatContext) -> List[float]:
        """Encode reputation scores."""
        features = []
        
        if not context.reputation_scores:
            return [0.0] * self.feature_dims['reputation']
        
        # Common reputation types
        rep_types = [
            'ip_reputation', 'domain_reputation', 'url_reputation',
            'asn_reputation', 'geo_reputation'
        ]
        
        for rep_type in rep_types:
            score = context.reputation_scores.get(rep_type, 50.0)  # Default neutral
            # Normalize to 0-1 (0 = bad, 1 = good)
            norm_score = score / 100.0
            features.append(norm_score)
        
        # Average reputation
        if context.reputation_scores:
            avg_rep = sum(context.reputation_scores.values()) / len(context.reputation_scores)
            features.append(avg_rep / 100.0)
        else:
            features.append(0.5)  # Neutral
        
        # Min reputation (worst)
        if context.reputation_scores:
            min_rep = min(context.reputation_scores.values())
            features.append(min_rep / 100.0)
        else:
            features.append(0.5)
        
        # Reputation count
        rep_count = len(context.reputation_scores) / 5.0
        features.append(min(rep_count, 1.0))
        
        # Pad to required size
        features.extend([0.0] * (self.feature_dims['reputation'] - len(features)))
        
        return features[:self.feature_dims['reputation']]
    
    def _encode_flow_stats(self, context: ThreatContext,
                          flow_data: Optional[Dict[str, Any]]) -> List[float]:
        """Encode flow statistics."""
        features = []
        
        # Basic flow stats
        features.append(context.packet_count / 1000.0)
        features.append(context.byte_count / 1000000.0)
        
        # Flow duration
        duration = context.last_seen - context.start_time
        features.append(min(duration / 3600.0, 1.0))
        
        # Additional stats from flow_data
        if flow_data:
            # Packet size statistics
            avg_packet_size = flow_data.get('avg_packet_size', 0)
            features.append(min(avg_packet_size / 1500.0, 1.0))
            
            # Inter-arrival time
            avg_iat = flow_data.get('avg_inter_arrival_time', 0)
            features.append(min(avg_iat / 1.0, 1.0))  # 1 second
            
            # Flags
            syn_count = flow_data.get('syn_count', 0)
            fin_count = flow_data.get('fin_count', 0)
            rst_count = flow_data.get('rst_count', 0)
            features.extend([
                min(syn_count / 10.0, 1.0),
                min(fin_count / 10.0, 1.0),
                min(rst_count / 10.0, 1.0)
            ])
        else:
            features.extend([0.0] * 5)
        
        # Pad to required size
        features.extend([0.0] * (self.feature_dims['flow_stats'] - len(features)))
        
        return features[:self.feature_dims['flow_stats']]
    
    def _normalize_state(self, state: np.ndarray) -> np.ndarray:
        """Normalize state vector."""
        # Simple min-max normalization
        state_min = state.min()
        state_max = state.max()
        
        if state_max - state_min > 1e-6:
            state = (state - state_min) / (state_max - state_min)
        
        return state
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except Exception:
            return False
    
    def get_state_size(self) -> int:
        """Get the size of state vectors."""
        return self.state_size

