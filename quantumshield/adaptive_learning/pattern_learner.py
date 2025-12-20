"""
Pattern Learner for Attack Pattern Recognition and Storage
Learns and stores attack patterns for future recognition
"""

import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict, deque
from datetime import datetime
import logging
from pathlib import Path
import numpy as np

from ..core.decision_maker import ThreatContext, ThreatIndicator, ActionType, Decision

logger = logging.getLogger(__name__)


class AttackPattern:
    """Represents a learned attack pattern."""
    
    def __init__(self,
                 pattern_id: str,
                 pattern_type: str,
                 features: Dict[str, Any],
                 indicators: List[str],
                 first_seen: float,
                 last_seen: float,
                 count: int = 1):
        self.pattern_id = pattern_id
        self.pattern_type = pattern_type
        self.features = features
        self.indicators = indicators
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.count = count
        self.confidence = 0.5  # Initial confidence
        self.recommended_action: Optional[ActionType] = None
        self.success_rate = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'pattern_id': self.pattern_id,
            'pattern_type': self.pattern_type,
            'features': self.features,
            'indicators': self.indicators,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'count': self.count,
            'confidence': self.confidence,
            'recommended_action': self.recommended_action.name if self.recommended_action else None,
            'success_rate': self.success_rate
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttackPattern':
        """Create from dictionary."""
        pattern = cls(
            pattern_id=data['pattern_id'],
            pattern_type=data['pattern_type'],
            features=data['features'],
            indicators=data['indicators'],
            first_seen=data['first_seen'],
            last_seen=data['last_seen'],
            count=data.get('count', 1)
        )
        pattern.confidence = data.get('confidence', 0.5)
        pattern.recommended_action = (
            ActionType[data['recommended_action']] 
            if data.get('recommended_action') else None
        )
        pattern.success_rate = data.get('success_rate', 0.0)
        return pattern


class PatternLearner:
    """Learns and stores attack patterns."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Pattern storage
        self.patterns: Dict[str, AttackPattern] = {}
        self.pattern_index: Dict[str, List[str]] = defaultdict(list)  # type -> pattern_ids
        
        # Pattern matching
        self.similarity_threshold = self.config.get('similarity_threshold', 0.7)
        self.min_pattern_count = self.config.get('min_pattern_count', 3)
        
        # Feature extraction
        self.feature_weights = self.config.get('feature_weights', {
            'indicators': 0.4,
            'network': 0.3,
            'behavioral': 0.2,
            'temporal': 0.1
        })
        
        # Pattern statistics
        self.stats = {
            'total_patterns': 0,
            'patterns_recognized': 0,
            'new_patterns_learned': 0,
            'pattern_updates': 0
        }
        
        # Storage path
        self.storage_path = Path(self.config.get('storage_path', 'patterns'))
        self.storage_path.mkdir(parents=True, exist_ok=True)
    
    def extract_pattern_features(self, context: ThreatContext) -> Dict[str, Any]:
        """Extract features that define an attack pattern."""
        features = {
            'indicators': [],
            'network': {},
            'behavioral': {},
            'temporal': {}
        }
        
        # Indicator features
        if context.indicators:
            indicator_types = [ind.indicator_type for ind in context.indicators]
            indicator_severities = [ind.severity.name for ind in context.indicators]
            features['indicators'] = {
                'types': sorted(set(indicator_types)),
                'severities': sorted(set(indicator_severities)),
                'count': len(context.indicators),
                'max_severity': max(ind.severity.value for ind in context.indicators)
            }
        
        # Network features
        features['network'] = {
            'protocol': context.protocol,
            'dst_port': context.destination_port,
            'is_internal': self._is_internal_ip(context.source_ip)
        }
        
        # Behavioral features
        features['behavioral'] = {
            'packet_count': context.packet_count,
            'byte_count': context.byte_count,
            'duration': context.last_seen - context.start_time
        }
        
        # Temporal features
        now = datetime.fromtimestamp(context.last_seen)
        features['temporal'] = {
            'hour': now.hour,
            'day_of_week': now.weekday()
        }
        
        return features
    
    def generate_pattern_id(self, features: Dict[str, Any]) -> str:
        """Generate a unique pattern ID from features."""
        # Create a hash from key features
        key_features = {
            'indicators': features.get('indicators', {}).get('types', []),
            'protocol': features.get('network', {}).get('protocol', ''),
            'dst_port': features.get('network', {}).get('dst_port', 0)
        }
        
        pattern_str = json.dumps(key_features, sort_keys=True)
        pattern_id = hashlib.md5(pattern_str.encode()).hexdigest()[:16]
        
        return pattern_id
    
    def calculate_similarity(self,
                            pattern1: Dict[str, Any],
                            pattern2: Dict[str, Any]) -> float:
        """Calculate similarity between two patterns."""
        similarity = 0.0
        total_weight = 0.0
        
        # Indicator similarity
        if 'indicators' in pattern1 and 'indicators' in pattern2:
            ind1_types = set(pattern1['indicators'].get('types', []))
            ind2_types = set(pattern2['indicators'].get('types', []))
            
            if ind1_types or ind2_types:
                intersection = len(ind1_types & ind2_types)
                union = len(ind1_types | ind2_types)
                ind_similarity = intersection / union if union > 0 else 0.0
                
                weight = self.feature_weights['indicators']
                similarity += ind_similarity * weight
                total_weight += weight
        
        # Network similarity
        if 'network' in pattern1 and 'network' in pattern2:
            net1 = pattern1['network']
            net2 = pattern2['network']
            
            net_similarity = 0.0
            if net1.get('protocol') == net2.get('protocol'):
                net_similarity += 0.5
            if net1.get('dst_port') == net2.get('dst_port'):
                net_similarity += 0.3
            if net1.get('is_internal') == net2.get('is_internal'):
                net_similarity += 0.2
            
            weight = self.feature_weights['network']
            similarity += net_similarity * weight
            total_weight += weight
        
        # Behavioral similarity (normalized)
        if 'behavioral' in pattern1 and 'behavioral' in pattern2:
            beh1 = pattern1['behavioral']
            beh2 = pattern2['behavioral']
            
            # Normalize differences
            packet_diff = abs(beh1.get('packet_count', 0) - beh2.get('packet_count', 0))
            packet_sim = 1.0 / (1.0 + packet_diff / 100.0)
            
            byte_diff = abs(beh1.get('byte_count', 0) - beh2.get('byte_count', 0))
            byte_sim = 1.0 / (1.0 + byte_diff / 10000.0)
            
            beh_similarity = (packet_sim + byte_sim) / 2.0
            
            weight = self.feature_weights['behavioral']
            similarity += beh_similarity * weight
            total_weight += weight
        
        # Normalize by total weight
        if total_weight > 0:
            similarity /= total_weight
        
        return similarity
    
    def find_similar_pattern(self, features: Dict[str, Any]) -> Optional[Tuple[str, float]]:
        """
        Find a similar existing pattern.
        
        Returns:
            Tuple of (pattern_id, similarity) or None
        """
        best_match = None
        best_similarity = 0.0
        
        for pattern_id, pattern in self.patterns.items():
            similarity = self.calculate_similarity(features, pattern.features)
            
            if similarity > best_similarity and similarity >= self.similarity_threshold:
                best_similarity = similarity
                best_match = pattern_id
        
        if best_match:
            return (best_match, best_similarity)
        return None
    
    def learn_pattern(self,
                     context: ThreatContext,
                     decision: Decision,
                     outcome: Optional[Dict[str, Any]] = None) -> str:
        """
        Learn a new pattern or update existing one.
        
        Returns:
            Pattern ID
        """
        # Extract features
        features = self.extract_pattern_features(context)
        
        # Check for similar pattern
        similar = self.find_similar_pattern(features)
        
        if similar:
            pattern_id, similarity = similar
            # Update existing pattern
            pattern = self.patterns[pattern_id]
            pattern.last_seen = time.time()
            pattern.count += 1
            
            # Update confidence based on similarity and count
            pattern.confidence = min(1.0, similarity * (1.0 + pattern.count / 10.0))
            
            # Update recommended action if outcome is positive
            if outcome and outcome.get('attack_prevented', False):
                if decision.action in [ActionType.BLOCK_PERMANENT, ActionType.BLOCK_TEMPORARY]:
                    pattern.recommended_action = decision.action
                    pattern.success_rate = (
                        (pattern.success_rate * (pattern.count - 1) + 1.0) / pattern.count
                    )
            
            self.stats['pattern_updates'] += 1
            logger.debug(f"Updated pattern {pattern_id} (similarity={similarity:.2f}, count={pattern.count})")
            
            return pattern_id
        else:
            # Create new pattern
            pattern_id = self.generate_pattern_id(features)
            
            indicator_types = [ind.indicator_type for ind in context.indicators]
            
            pattern = AttackPattern(
                pattern_id=pattern_id,
                pattern_type=self._classify_pattern_type(features),
                features=features,
                indicators=indicator_types,
                first_seen=time.time(),
                last_seen=time.time(),
                count=1
            )
            
            # Set initial recommended action
            if decision.threat_level.value >= 3:  # HIGH or above
                pattern.recommended_action = decision.action
            
            # Update outcome if available
            if outcome:
                if outcome.get('attack_prevented', False):
                    pattern.success_rate = 1.0
                elif outcome.get('false_positive', False):
                    pattern.success_rate = 0.0
            
            self.patterns[pattern_id] = pattern
            self.pattern_index[pattern.pattern_type].append(pattern_id)
            
            self.stats['total_patterns'] += 1
            self.stats['new_patterns_learned'] += 1
            
            logger.info(f"Learned new pattern {pattern_id} (type={pattern.pattern_type})")
            
            return pattern_id
    
    def recognize_pattern(self, context: ThreatContext) -> Optional[Dict[str, Any]]:
        """
        Recognize if context matches a known pattern.
        
        Returns:
            Pattern information if recognized, None otherwise
        """
        features = self.extract_pattern_features(context)
        similar = self.find_similar_pattern(features)
        
        if similar:
            pattern_id, similarity = similar
            pattern = self.patterns[pattern_id]
            
            self.stats['patterns_recognized'] += 1
            
            return {
                'pattern_id': pattern_id,
                'pattern_type': pattern.pattern_type,
                'similarity': similarity,
                'confidence': pattern.confidence,
                'count': pattern.count,
                'recommended_action': pattern.recommended_action,
                'success_rate': pattern.success_rate,
                'features': pattern.features
            }
        
        return None
    
    def _classify_pattern_type(self, features: Dict[str, Any]) -> str:
        """Classify the type of attack pattern."""
        indicators = features.get('indicators', {})
        indicator_types = indicators.get('types', [])
        
        # Classify based on indicator types
        if any('sql' in t.lower() for t in indicator_types):
            return 'sql_injection'
        elif any('xss' in t.lower() for t in indicator_types):
            return 'xss'
        elif any('command' in t.lower() for t in indicator_types):
            return 'command_injection'
        elif any('ddos' in t.lower() for t in indicator_types):
            return 'ddos'
        elif any('port_scan' in t.lower() for t in indicator_types):
            return 'port_scan'
        elif any('malware' in t.lower() for t in indicator_types):
            return 'malware'
        elif any('anomaly' in t.lower() for t in indicator_types):
            return 'anomaly'
        else:
            return 'unknown'
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal."""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except Exception:
            return False
    
    def get_pattern(self, pattern_id: str) -> Optional[AttackPattern]:
        """Get a pattern by ID."""
        return self.patterns.get(pattern_id)
    
    def get_patterns_by_type(self, pattern_type: str) -> List[AttackPattern]:
        """Get all patterns of a specific type."""
        pattern_ids = self.pattern_index.get(pattern_type, [])
        return [self.patterns[pid] for pid in pattern_ids if pid in self.patterns]
    
    def get_top_patterns(self, limit: int = 10) -> List[AttackPattern]:
        """Get top patterns by count."""
        sorted_patterns = sorted(
            self.patterns.values(),
            key=lambda p: p.count,
            reverse=True
        )
        return sorted_patterns[:limit]
    
    def save_patterns(self, filepath: Optional[Path] = None) -> None:
        """Save patterns to disk."""
        if filepath is None:
            filepath = self.storage_path / 'patterns.json'
        
        try:
            patterns_data = {
                pattern_id: pattern.to_dict()
                for pattern_id, pattern in self.patterns.items()
            }
            
            with open(filepath, 'w') as f:
                json.dump(patterns_data, f, indent=2)
            
            logger.info(f"Saved {len(self.patterns)} patterns to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save patterns: {e}")
    
    def load_patterns(self, filepath: Optional[Path] = None) -> None:
        """Load patterns from disk."""
        if filepath is None:
            filepath = self.storage_path / 'patterns.json'
        
        if not filepath.exists():
            logger.warning(f"Pattern file not found: {filepath}")
            return
        
        try:
            with open(filepath, 'r') as f:
                patterns_data = json.load(f)
            
            self.patterns = {}
            self.pattern_index = defaultdict(list)
            
            for pattern_id, pattern_data in patterns_data.items():
                pattern = AttackPattern.from_dict(pattern_data)
                self.patterns[pattern_id] = pattern
                self.pattern_index[pattern.pattern_type].append(pattern_id)
            
            self.stats['total_patterns'] = len(self.patterns)
            logger.info(f"Loaded {len(self.patterns)} patterns from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load patterns: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get pattern learner statistics."""
        pattern_types = defaultdict(int)
        for pattern in self.patterns.values():
            pattern_types[pattern.pattern_type] += 1
        
        return {
            **self.stats,
            'patterns_by_type': dict(pattern_types),
            'total_unique_patterns': len(self.patterns),
            'avg_pattern_confidence': (
                np.mean([p.confidence for p in self.patterns.values()])
                if self.patterns else 0.0
            ),
            'avg_pattern_count': (
                np.mean([p.count for p in self.patterns.values()])
                if self.patterns else 0.0
            )
        }

