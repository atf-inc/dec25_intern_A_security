#!/usr/bin/env python3
"""
QuantumShield - Decision Maker Module
Central decision logic for threat evaluation and action determination.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Tuple, Callable
from collections import defaultdict
import hashlib
import json
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor
import numpy as np

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class ActionType(Enum):
    """Types of response actions."""
    ALLOW = auto()
    LOG = auto()
    ALERT = auto()
    RATE_LIMIT = auto()
    THROTTLE = auto()
    BLOCK_TEMPORARY = auto()
    BLOCK_PERMANENT = auto()
    QUARANTINE = auto()
    REDIRECT = auto()
    DROP_SILENT = auto()
    RESET_CONNECTION = auto()
    CHALLENGE = auto()
    HONEYPOT_REDIRECT = auto()


class DecisionConfidence(Enum):
    """Confidence levels for decisions."""
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERY_HIGH = 5


@dataclass
class ThreatIndicator:
    """Represents a single threat indicator from any detection engine."""
    source: str  # Which engine detected this
    indicator_type: str  # Type of indicator (signature, anomaly, behavioral, etc.)
    severity: ThreatLevel
    confidence: float  # 0.0 to 1.0
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    ttl: int = 300  # Time to live in seconds
    
    def is_expired(self) -> bool:
        """Check if the indicator has expired."""
        return time.time() > self.timestamp + self.ttl
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'source': self.source,
            'indicator_type': self.indicator_type,
            'severity': self.severity.name,
            'confidence': self.confidence,
            'description': self.description,
            'details': self.details,
            'timestamp': self.timestamp,
            'ttl': self.ttl
        }


@dataclass
class ThreatContext:
    """Context information for threat analysis."""
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    indicators: List[ThreatIndicator] = field(default_factory=list)
    flow_id: Optional[str] = None
    session_id: Optional[str] = None
    packet_count: int = 0
    byte_count: int = 0
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    ml_scores: Dict[str, float] = field(default_factory=dict)
    reputation_scores: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_key(self) -> str:
        """Generate unique key for this context."""
        return f"{self.source_ip}:{self.source_port}-{self.destination_ip}:{self.destination_port}-{self.protocol}"
    
    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Add a threat indicator to this context."""
        self.indicators.append(indicator)
        self.last_seen = time.time()
    
    def get_max_severity(self) -> ThreatLevel:
        """Get the maximum severity from all indicators."""
        if not self.indicators:
            return ThreatLevel.NONE
        return max(ind.severity for ind in self.indicators)
    
    def get_aggregate_confidence(self) -> float:
        """Calculate aggregate confidence score."""
        if not self.indicators:
            return 0.0
        # Weighted average based on severity
        total_weight = 0
        weighted_sum = 0
        for ind in self.indicators:
            weight = ind.severity.value + 1
            weighted_sum += ind.confidence * weight
            total_weight += weight
        return weighted_sum / total_weight if total_weight > 0 else 0.0


@dataclass
class Decision:
    """Represents a security decision."""
    action: ActionType
    threat_level: ThreatLevel
    confidence: DecisionConfidence
    reason: str
    context: ThreatContext
    parameters: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    decision_id: str = field(default_factory=lambda: hashlib.md5(
        f"{time.time()}{id(object())}".encode()).hexdigest()[:16])
    expires_at: Optional[float] = None
    requires_human_review: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to dictionary."""
        return {
            'decision_id': self.decision_id,
            'action': self.action.name,
            'threat_level': self.threat_level.name,
            'confidence': self.confidence.name,
            'reason': self.reason,
            'parameters': self.parameters,
            'timestamp': self.timestamp,
            'expires_at': self.expires_at,
            'requires_human_review': self.requires_human_review,
            'context_key': self.context.get_key()
        }


@dataclass
class Policy:
    """Security policy definition."""
    policy_id: str
    name: str
    description: str
    priority: int
    enabled: bool
    conditions: Dict[str, Any]
    actions: List[ActionType]
    parameters: Dict[str, Any] = field(default_factory=dict)
    schedule: Optional[Dict[str, Any]] = None
    exceptions: List[str] = field(default_factory=list)
    
    def matches(self, context: ThreatContext) -> bool:
        """Check if this policy matches the given context."""
        if not self.enabled:
            return False
        
        for condition_type, condition_value in self.conditions.items():
            if not self._check_condition(condition_type, condition_value, context):
                return False
        return True
    
    def _check_condition(self, cond_type: str, cond_value: Any, 
                         context: ThreatContext) -> bool:
        """Check a single condition."""
        if cond_type == 'source_ip':
            return self._match_ip(context.source_ip, cond_value)
        elif cond_type == 'destination_ip':
            return self._match_ip(context.destination_ip, cond_value)
        elif cond_type == 'source_port':
            return self._match_port(context.source_port, cond_value)
        elif cond_type == 'destination_port':
            return self._match_port(context.destination_port, cond_value)
        elif cond_type == 'protocol':
            return context.protocol.lower() in [p.lower() for p in cond_value]
        elif cond_type == 'min_threat_level':
            return context.get_max_severity().value >= ThreatLevel[cond_value].value
        elif cond_type == 'indicator_types':
            return any(ind.indicator_type in cond_value for ind in context.indicators)
        return True
    
    def _match_ip(self, ip: str, pattern: Any) -> bool:
        """Match IP against pattern (string, list, or CIDR)."""
        if isinstance(pattern, str):
            return ip == pattern or self._match_cidr(ip, pattern)
        elif isinstance(pattern, list):
            return any(self._match_ip(ip, p) for p in pattern)
        return False
    
    def _match_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP matches CIDR notation."""
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            return ipaddress.ip_address(ip) in network
        except (ValueError, AttributeError):
            return ip == cidr
    
    def _match_port(self, port: int, pattern: Any) -> bool:
        """Match port against pattern."""
        if isinstance(pattern, int):
            return port == pattern
        elif isinstance(pattern, list):
            return port in pattern
        elif isinstance(pattern, str) and '-' in pattern:
            start, end = map(int, pattern.split('-'))
            return start <= port <= end
        return False


class ThreatScorer:
    """Calculates comprehensive threat scores."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.weights = self.config.get('weights', {
            'signature': 1.0,
            'anomaly': 0.8,
            'behavioral': 0.9,
            'ml': 0.85,
            'reputation': 0.7
        })
        self.thresholds = self.config.get('thresholds', {
            'low': 0.2,
            'medium': 0.4,
            'high': 0.6,
            'critical': 0.8,
            'emergency': 0.95
        })
    
    def calculate_score(self, context: ThreatContext) -> Tuple[float, ThreatLevel]:
        """Calculate overall threat score and level."""
        scores = []
        
        # Score from indicators
        for indicator in context.indicators:
            if not indicator.is_expired():
                weight = self.weights.get(indicator.indicator_type, 0.5)
                score = (indicator.severity.value / 5) * indicator.confidence * weight
                scores.append(score)
        
        # Score from ML models
        for model_name, ml_score in context.ml_scores.items():
            weight = self.weights.get('ml', 0.85)
            scores.append(ml_score * weight)
        
        # Score from reputation
        for rep_type, rep_score in context.reputation_scores.items():
            weight = self.weights.get('reputation', 0.7)
            # Reputation is usually 0-100, normalize to 0-1
            # Higher reputation = lower threat
            threat_from_rep = (100 - rep_score) / 100
            scores.append(threat_from_rep * weight)
        
        if not scores:
            return 0.0, ThreatLevel.NONE
        
        # Use maximum score with some influence from average
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        final_score = 0.7 * max_score + 0.3 * avg_score
        
        # Apply temporal decay if attack is sustained
        duration = time.time() - context.start_time
        if duration > 60:  # Attack lasting more than 1 minute
            final_score = min(1.0, final_score * 1.1)
        
        # Determine threat level
        threat_level = self._score_to_level(final_score)
        
        return final_score, threat_level
    
    def _score_to_level(self, score: float) -> ThreatLevel:
        """Convert numeric score to threat level."""
        if score >= self.thresholds['emergency']:
            return ThreatLevel.EMERGENCY
        elif score >= self.thresholds['critical']:
            return ThreatLevel.CRITICAL
        elif score >= self.thresholds['high']:
            return ThreatLevel.HIGH
        elif score >= self.thresholds['medium']:
            return ThreatLevel.MEDIUM
        elif score >= self.thresholds['low']:
            return ThreatLevel.LOW
        return ThreatLevel.NONE


class PolicyEngine:
    """Manages and evaluates security policies."""
    
    def __init__(self, policies: Optional[List[Policy]] = None):
        self.policies: List[Policy] = policies or []
        self._sorted = False
        self._lock = threading.Lock()
        self._default_policy = Policy(
            policy_id='default',
            name='Default Allow',
            description='Default policy to allow traffic',
            priority=0,
            enabled=True,
            conditions={},
            actions=[ActionType.LOG, ActionType.ALLOW]
        )
    
    def add_policy(self, policy: Policy) -> None:
        """Add a new policy."""
        with self._lock:
            self.policies.append(policy)
            self._sorted = False
    
    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID."""
        with self._lock:
            for i, policy in enumerate(self.policies):
                if policy.policy_id == policy_id:
                    del self.policies[i]
                    return True
            return False
    
    def update_policy(self, policy: Policy) -> bool:
        """Update an existing policy."""
        with self._lock:
            for i, p in enumerate(self.policies):
                if p.policy_id == policy.policy_id:
                    self.policies[i] = policy
                    self._sorted = False
                    return True
            return False
    
    def _ensure_sorted(self) -> None:
        """Ensure policies are sorted by priority."""
        if not self._sorted:
            self.policies.sort(key=lambda p: -p.priority)
            self._sorted = True
    
    def evaluate(self, context: ThreatContext, 
                 threat_level: ThreatLevel) -> Tuple[Policy, List[ActionType]]:
        """Evaluate policies and return matching policy and actions."""
        with self._lock:
            self._ensure_sorted()
            
            for policy in self.policies:
                if policy.matches(context):
                    # Check threat level condition
                    min_threat = policy.conditions.get('min_threat_level')
                    if min_threat and threat_level.value < ThreatLevel[min_threat].value:
                        continue
                    return policy, policy.actions
            
            return self._default_policy, self._default_policy.actions
    
    def load_from_file(self, filepath: str) -> None:
        """Load policies from a JSON file."""
        try:
            with open(filepath, 'r') as f:
                policy_data = json.load(f)
            
            for p_data in policy_data.get('policies', []):
                policy = Policy(
                    policy_id=p_data['policy_id'],
                    name=p_data['name'],
                    description=p_data.get('description', ''),
                    priority=p_data.get('priority', 50),
                    enabled=p_data.get('enabled', True),
                    conditions=p_data.get('conditions', {}),
                    actions=[ActionType[a] for a in p_data.get('actions', ['ALLOW'])],
                    parameters=p_data.get('parameters', {}),
                    exceptions=p_data.get('exceptions', [])
                )
                self.add_policy(policy)
            
            logger.info(f"Loaded {len(policy_data.get('policies', []))} policies from {filepath}")
        except Exception as e:
            logger.error(f"Failed to load policies from {filepath}: {e}")


class CorrelationEngine:
    """Correlates events across multiple sources and time windows."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.event_cache: Dict[str, List[ThreatIndicator]] = defaultdict(list)
        self.correlation_rules: List[Dict[str, Any]] = []
        self.time_windows = self.config.get('time_windows', {
            'short': 60,      # 1 minute
            'medium': 300,    # 5 minutes
            'long': 3600      # 1 hour
        })
        self._lock = threading.Lock()
        self._cleanup_interval = 60
        self._last_cleanup = time.time()
    
    def add_event(self, key: str, indicator: ThreatIndicator) -> None:
        """Add an event to the correlation cache."""
        with self._lock:
            self.event_cache[key].append(indicator)
            self._cleanup_if_needed()
    
    def _cleanup_if_needed(self) -> None:
        """Periodically clean up expired events."""
        if time.time() - self._last_cleanup < self._cleanup_interval:
            return
        
        current_time = time.time()
        max_window = max(self.time_windows.values())
        
        for key in list(self.event_cache.keys()):
            self.event_cache[key] = [
                ind for ind in self.event_cache[key]
                if current_time - ind.timestamp < max_window
            ]
            if not self.event_cache[key]:
                del self.event_cache[key]
        
        self._last_cleanup = current_time
    
    def correlate(self, context: ThreatContext) -> List[ThreatIndicator]:
        """Find correlated events for the given context."""
        correlated = []
        key = context.get_key()
        
        with self._lock:
            # Check events from same source
            source_events = self.event_cache.get(key, [])
            
            # Check events from same source IP across different destinations
            source_ip_pattern = f"{context.source_ip}:*"
            for cache_key, events in self.event_cache.items():
                if cache_key.startswith(f"{context.source_ip}:"):
                    correlated.extend([
                        e for e in events 
                        if not e.is_expired() and 
                        time.time() - e.timestamp < self.time_windows['medium']
                    ])
            
            # Apply correlation rules
            for rule in self.correlation_rules:
                rule_matches = self._apply_correlation_rule(rule, context, correlated)
                if rule_matches:
                    correlated.append(ThreatIndicator(
                        source='correlation_engine',
                        indicator_type='correlated',
                        severity=ThreatLevel.HIGH,
                        confidence=0.85,
                        description=f"Correlated event: {rule.get('name', 'Unknown')}",
                        details={'rule': rule, 'matched_events': len(rule_matches)}
                    ))
        
        return correlated
    
    def _apply_correlation_rule(self, rule: Dict[str, Any], 
                                context: ThreatContext,
                                events: List[ThreatIndicator]) -> List[ThreatIndicator]:
        """Apply a single correlation rule."""
        rule_type = rule.get('type')
        
        if rule_type == 'threshold':
            # Count events within time window
            window = rule.get('window', 60)
            threshold = rule.get('threshold', 10)
            current_time = time.time()
            recent_events = [
                e for e in events 
                if current_time - e.timestamp < window
            ]
            if len(recent_events) >= threshold:
                return recent_events
        
        elif rule_type == 'sequence':
            # Check for specific sequence of event types
            sequence = rule.get('sequence', [])
            window = rule.get('window', 300)
            return self._check_sequence(events, sequence, window)
        
        elif rule_type == 'unique_targets':
            # Count unique destinations from same source
            targets = set()
            for e in events:
                if 'destination' in e.details:
                    targets.add(e.details['destination'])
            if len(targets) >= rule.get('threshold', 5):
                return events
        
        return []
    
    def _check_sequence(self, events: List[ThreatIndicator], 
                       sequence: List[str], window: int) -> List[ThreatIndicator]:
        """Check if events match a specific sequence."""
        if not sequence or not events:
            return []
        
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        current_time = time.time()
        
        seq_idx = 0
        matched_events = []
        
        for event in sorted_events:
            if current_time - event.timestamp > window:
                continue
            
            if event.indicator_type == sequence[seq_idx]:
                matched_events.append(event)
                seq_idx += 1
                
                if seq_idx >= len(sequence):
                    return matched_events
        
        return []
    
    def add_correlation_rule(self, rule: Dict[str, Any]) -> None:
        """Add a correlation rule."""
        with self._lock:
            self.correlation_rules.append(rule)


class RateLimitTracker:
    """Tracks rate limits for IPs, sessions, etc."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.counters: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.limits = self.config.get('limits', {
            'requests_per_second': 100,
            'requests_per_minute': 1000,
            'connections_per_second': 50,
            'bytes_per_second': 10_000_000  # 10 MB/s
        })
    
    def check_and_update(self, key: str, count: int = 1) -> Tuple[bool, Optional[str]]:
        """Check if rate limit is exceeded and update counter."""
        with self._lock:
            current_time = time.time()
            
            if key not in self.counters:
                self.counters[key] = {
                    'second': {'count': 0, 'window_start': current_time},
                    'minute': {'count': 0, 'window_start': current_time}
                }
            
            counter = self.counters[key]
            
            # Check and update per-second limit
            if current_time - counter['second']['window_start'] >= 1:
                counter['second'] = {'count': 0, 'window_start': current_time}
            counter['second']['count'] += count
            
            if counter['second']['count'] > self.limits['requests_per_second']:
                return True, 'requests_per_second'
            
            # Check and update per-minute limit
            if current_time - counter['minute']['window_start'] >= 60:
                counter['minute'] = {'count': 0, 'window_start': current_time}
            counter['minute']['count'] += count
            
            if counter['minute']['count'] > self.limits['requests_per_minute']:
                return True, 'requests_per_minute'
            
            return False, None
    
    def get_rate(self, key: str) -> Dict[str, float]:
        """Get current rate for a key."""
        with self._lock:
            if key not in self.counters:
                return {'per_second': 0, 'per_minute': 0}
            
            counter = self.counters[key]
            current_time = time.time()
            
            second_elapsed = max(0.001, current_time - counter['second']['window_start'])
            minute_elapsed = max(0.001, current_time - counter['minute']['window_start'])
            
            return {
                'per_second': counter['second']['count'] / second_elapsed,
                'per_minute': counter['minute']['count'] / (minute_elapsed / 60)
            }


class DecisionCache:
    """Caches recent decisions for fast lookup and consistency."""
    
    def __init__(self, max_size: int = 10000, ttl: int = 300):
        self.max_size = max_size
        self.ttl = ttl
        self.cache: Dict[str, Decision] = {}
        self._lock = threading.Lock()
        self._access_order: List[str] = []
    
    def get(self, key: str) -> Optional[Decision]:
        """Get cached decision."""
        with self._lock:
            if key in self.cache:
                decision = self.cache[key]
                if time.time() < decision.timestamp + self.ttl:
                    # Move to end of access order
                    if key in self._access_order:
                        self._access_order.remove(key)
                    self._access_order.append(key)
                    return decision
                else:
                    # Expired
                    del self.cache[key]
                    self._access_order.remove(key)
            return None
    
    def put(self, key: str, decision: Decision) -> None:
        """Cache a decision."""
        with self._lock:
            if len(self.cache) >= self.max_size:
                # Remove oldest
                oldest_key = self._access_order.pop(0)
                if oldest_key in self.cache:
                    del self.cache[oldest_key]
            
            self.cache[key] = decision
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
    
    def invalidate(self, key: str) -> None:
        """Invalidate a cached decision."""
        with self._lock:
            if key in self.cache:
                del self.cache[key]
                self._access_order.remove(key)
    
    def clear(self) -> None:
        """Clear the entire cache."""
        with self._lock:
            self.cache.clear()
            self._access_order.clear()


class DecisionMaker:
    """
    Central decision-making engine for QuantumShield.
    Aggregates inputs from all detection engines and determines appropriate actions.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Initialize components
        self.threat_scorer = ThreatScorer(config.get('scoring'))
        self.policy_engine = PolicyEngine()
        self.correlation_engine = CorrelationEngine(config.get('correlation'))
        self.rate_limiter = RateLimitTracker(config.get('rate_limiting'))
        self.decision_cache = DecisionCache(
            max_size=config.get('cache_size', 10000),
            ttl=config.get('cache_ttl', 300)
        )
        
        # Callbacks for decision notification
        self._decision_callbacks: List[Callable[[Decision], None]] = []
        
        # Executor for async operations
        self._executor = ThreadPoolExecutor(max_workers=4)
        
        # Statistics
        self.stats = {
            'total_decisions': 0,
            'decisions_by_action': defaultdict(int),
            'decisions_by_threat_level': defaultdict(int),
            'cache_hits': 0,
            'cache_misses': 0,
            'processing_times': []
        }
        self._stats_lock = threading.Lock()
        
        # Load default policies
        self._load_default_policies()
        
        logger.info("DecisionMaker initialized")
    
    def _load_default_policies(self) -> None:
        """Load default security policies."""
        default_policies = [
            Policy(
                policy_id='block_critical',
                name='Block Critical Threats',
                description='Immediately block critical and emergency threats',
                priority=1000,
                enabled=True,
                conditions={'min_threat_level': 'CRITICAL'},
                actions=[ActionType.BLOCK_PERMANENT, ActionType.ALERT, ActionType.LOG]
            ),
            Policy(
                policy_id='rate_limit_high',
                name='Rate Limit High Threats',
                description='Apply rate limiting to high-severity threats',
                priority=800,
                enabled=True,
                conditions={'min_threat_level': 'HIGH'},
                actions=[ActionType.RATE_LIMIT, ActionType.ALERT, ActionType.LOG]
            ),
            Policy(
                policy_id='monitor_medium',
                name='Monitor Medium Threats',
                description='Log and alert on medium threats',
                priority=600,
                enabled=True,
                conditions={'min_threat_level': 'MEDIUM'},
                actions=[ActionType.LOG, ActionType.ALERT]
            ),
            Policy(
                policy_id='log_low',
                name='Log Low Threats',
                description='Log low-severity threats',
                priority=400,
                enabled=True,
                conditions={'min_threat_level': 'LOW'},
                actions=[ActionType.LOG]
            ),
            Policy(
                policy_id='ddos_protection',
                name='DDoS Protection',
                description='Block DDoS attacks',
                priority=950,
                enabled=True,
                conditions={'indicator_types': ['ddos', 'syn_flood', 'amplification']},
                actions=[ActionType.BLOCK_TEMPORARY, ActionType.RATE_LIMIT, ActionType.ALERT]
            ),
            Policy(
                policy_id='malware_block',
                name='Malware Block',
                description='Block detected malware',
                priority=980,
                enabled=True,
                conditions={'indicator_types': ['malware', 'ransomware', 'trojan']},
                actions=[ActionType.BLOCK_PERMANENT, ActionType.QUARANTINE, ActionType.ALERT]
            ),
        ]
        
        for policy in default_policies:
            self.policy_engine.add_policy(policy)
    
    def register_callback(self, callback: Callable[[Decision], None]) -> None:
        """Register a callback to be notified of decisions."""
        self._decision_callbacks.append(callback)
    
    def unregister_callback(self, callback: Callable[[Decision], None]) -> None:
        """Unregister a decision callback."""
        if callback in self._decision_callbacks:
            self._decision_callbacks.remove(callback)
    
    async def make_decision(self, context: ThreatContext) -> Decision:
        """
        Make a security decision for the given threat context.
        This is the main entry point for decision making.
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = context.get_key()
        cached_decision = self.decision_cache.get(cache_key)
        if cached_decision:
            with self._stats_lock:
                self.stats['cache_hits'] += 1
            return cached_decision
        
        with self._stats_lock:
            self.stats['cache_misses'] += 1
        
        try:
            # Step 1: Check rate limiting
            exceeded, limit_type = self.rate_limiter.check_and_update(
                context.source_ip, context.packet_count or 1
            )
            if exceeded:
                decision = self._create_rate_limit_decision(context, limit_type)
                self._finalize_decision(decision, start_time)
                return decision
            
            # Step 2: Correlate events
            correlated_indicators = self.correlation_engine.correlate(context)
            for indicator in correlated_indicators:
                context.add_indicator(indicator)
            
            # Step 3: Calculate threat score
            threat_score, threat_level = self.threat_scorer.calculate_score(context)
            
            # Step 4: Evaluate policies
            policy, actions = self.policy_engine.evaluate(context, threat_level)
            
            # Step 5: Determine confidence
            confidence = self._calculate_confidence(context, threat_score)
            
            # Step 6: Create decision
            decision = self._create_decision(
                context=context,
                threat_level=threat_level,
                threat_score=threat_score,
                policy=policy,
                actions=actions,
                confidence=confidence
            )
            
            # Step 7: Post-processing
            decision = self._post_process_decision(decision)
            
            # Step 8: Cache and finalize
            self.decision_cache.put(cache_key, decision)
            self._finalize_decision(decision, start_time)
            
            return decision
            
        except Exception as e:
            logger.error(f"Error making decision: {e}", exc_info=True)
            # Return safe default decision on error
            return Decision(
                action=ActionType.LOG,
                threat_level=ThreatLevel.LOW,
                confidence=DecisionConfidence.LOW,
                reason=f"Error in decision making: {str(e)}",
                context=context,
                requires_human_review=True
            )
    
    def make_decision_sync(self, context: ThreatContext) -> Decision:
        """Synchronous version of make_decision."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.make_decision(context))
        finally:
            loop.close()
    
    def _create_rate_limit_decision(self, context: ThreatContext, 
                                    limit_type: str) -> Decision:
        """Create a decision for rate limit violations."""
        return Decision(
            action=ActionType.RATE_LIMIT,
            threat_level=ThreatLevel.MEDIUM,
            confidence=DecisionConfidence.HIGH,
            reason=f"Rate limit exceeded: {limit_type}",
            context=context,
            parameters={
                'limit_type': limit_type,
                'block_duration': 60  # seconds
            }
        )
    
    def _calculate_confidence(self, context: ThreatContext, 
                             threat_score: float) -> DecisionConfidence:
        """Calculate confidence level for the decision."""
        # Base confidence from aggregate indicator confidence
        base_confidence = context.get_aggregate_confidence()
        
        # Adjust based on number of indicators
        indicator_count = len(context.indicators)
        if indicator_count >= 5:
            confidence_boost = 0.1
        elif indicator_count >= 3:
            confidence_boost = 0.05
        else:
            confidence_boost = 0
        
        # Adjust based on ML model agreement
        if context.ml_scores:
            ml_values = list(context.ml_scores.values())
            ml_variance = np.var(ml_values) if len(ml_values) > 1 else 0
            # Low variance means models agree
            if ml_variance < 0.1:
                confidence_boost += 0.1
            elif ml_variance > 0.3:
                confidence_boost -= 0.1
        
        final_confidence = base_confidence + confidence_boost
        
        if final_confidence >= 0.9:
            return DecisionConfidence.VERY_HIGH
        elif final_confidence >= 0.7:
            return DecisionConfidence.HIGH
        elif final_confidence >= 0.5:
            return DecisionConfidence.MEDIUM
        elif final_confidence >= 0.3:
            return DecisionConfidence.LOW
        return DecisionConfidence.VERY_LOW
    
    def _create_decision(self, context: ThreatContext, threat_level: ThreatLevel,
                        threat_score: float, policy: Policy, 
                        actions: List[ActionType],
                        confidence: DecisionConfidence) -> Decision:
        """Create a decision based on analysis results."""
        # Select primary action (first action in policy)
        primary_action = actions[0] if actions else ActionType.ALLOW
        
        # Build reason string
        indicator_types = set(ind.indicator_type for ind in context.indicators)
        reason_parts = [f"Threat level: {threat_level.name}"]
        if indicator_types:
            reason_parts.append(f"Indicators: {', '.join(indicator_types)}")
        reason_parts.append(f"Policy: {policy.name}")
        reason = "; ".join(reason_parts)
        
        # Determine parameters based on action
        parameters = dict(policy.parameters)
        parameters['all_actions'] = [a.name for a in actions]
        parameters['threat_score'] = threat_score
        
        # Set expiration for temporary blocks
        expires_at = None
        if primary_action == ActionType.BLOCK_TEMPORARY:
            block_duration = parameters.get('block_duration', 300)
            expires_at = time.time() + block_duration
        
        # Determine if human review is needed
        requires_review = (
            confidence.value <= DecisionConfidence.LOW.value and 
            threat_level.value >= ThreatLevel.HIGH.value
        )
        
        return Decision(
            action=primary_action,
            threat_level=threat_level,
            confidence=confidence,
            reason=reason,
            context=context,
            parameters=parameters,
            expires_at=expires_at,
            requires_human_review=requires_review
        )
    
    def _post_process_decision(self, decision: Decision) -> Decision:
        """Post-process the decision for edge cases and special handling."""
        # Check whitelist
        if self._is_whitelisted(decision.context.source_ip):
            return Decision(
                action=ActionType.ALLOW,
                threat_level=ThreatLevel.NONE,
                confidence=DecisionConfidence.VERY_HIGH,
                reason="Source IP is whitelisted",
                context=decision.context
            )
        
        # Check if this is internal traffic
        if self._is_internal_traffic(decision.context):
            # Reduce severity for internal traffic unless it's critical
            if decision.threat_level.value < ThreatLevel.CRITICAL.value:
                decision.threat_level = ThreatLevel(
                    max(0, decision.threat_level.value - 1)
                )
        
        # Apply business hours policy if configured
        if self.config.get('enforce_business_hours'):
            if not self._is_business_hours():
                # More strict during off-hours
                if decision.threat_level.value >= ThreatLevel.MEDIUM.value:
                    decision.action = ActionType.BLOCK_TEMPORARY
        
        return decision
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted."""
        whitelist = self.config.get('whitelist', [])
        return ip in whitelist
    
    def _is_internal_traffic(self, context: ThreatContext) -> bool:
        """Check if traffic is internal."""
        internal_ranges = self.config.get('internal_ranges', [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8'
        ])
        
        try:
            import ipaddress
            src_ip = ipaddress.ip_address(context.source_ip)
            for range_str in internal_ranges:
                if src_ip in ipaddress.ip_network(range_str, strict=False):
                    return True
        except Exception:
            pass
        return False
    
    def _is_business_hours(self) -> bool:
        """Check if current time is within business hours."""
        business_hours = self.config.get('business_hours', {
            'start': 8,
            'end': 18,
            'days': [0, 1, 2, 3, 4]  # Monday to Friday
        })
        
        now = datetime.now()
        if now.weekday() not in business_hours['days']:
            return False
        if now.hour < business_hours['start'] or now.hour >= business_hours['end']:
            return False
        return True
    
    def _finalize_decision(self, decision: Decision, start_time: float) -> None:
        """Finalize and record the decision."""
        processing_time = time.time() - start_time
        
        # Update statistics
        with self._stats_lock:
            self.stats['total_decisions'] += 1
            self.stats['decisions_by_action'][decision.action.name] += 1
            self.stats['decisions_by_threat_level'][decision.threat_level.name] += 1
            self.stats['processing_times'].append(processing_time)
            
            # Keep only last 1000 processing times
            if len(self.stats['processing_times']) > 1000:
                self.stats['processing_times'] = self.stats['processing_times'][-1000:]
        
        # Notify callbacks
        for callback in self._decision_callbacks:
            try:
                self._executor.submit(callback, decision)
            except Exception as e:
                logger.error(f"Error in decision callback: {e}")
        
        # Log decision
        log_level = logging.WARNING if decision.threat_level.value >= ThreatLevel.HIGH.value else logging.INFO
        logger.log(log_level, 
                   f"Decision: {decision.action.name} for {decision.context.get_key()} "
                   f"(threat_level={decision.threat_level.name}, "
                   f"confidence={decision.confidence.name}, "
                   f"time={processing_time*1000:.2f}ms)")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get decision maker statistics."""
        with self._stats_lock:
            processing_times = self.stats['processing_times']
            return {
                'total_decisions': self.stats['total_decisions'],
                'decisions_by_action': dict(self.stats['decisions_by_action']),
                'decisions_by_threat_level': dict(self.stats['decisions_by_threat_level']),
                'cache_hits': self.stats['cache_hits'],
                'cache_misses': self.stats['cache_misses'],
                'cache_hit_rate': (
                    self.stats['cache_hits'] / 
                    max(1, self.stats['cache_hits'] + self.stats['cache_misses'])
                ),
                'avg_processing_time_ms': (
                    np.mean(processing_times) * 1000 if processing_times else 0
                ),
                'p95_processing_time_ms': (
                    np.percentile(processing_times, 95) * 1000 if processing_times else 0
                ),
                'p99_processing_time_ms': (
                    np.percentile(processing_times, 99) * 1000 if processing_times else 0
                )
            }
    
    def reset_statistics(self) -> None:
        """Reset all statistics."""
        with self._stats_lock:
            self.stats = {
                'total_decisions': 0,
                'decisions_by_action': defaultdict(int),
                'decisions_by_threat_level': defaultdict(int),
                'cache_hits': 0,
                'cache_misses': 0,
                'processing_times': []
            }
    
    def load_policies(self, filepath: str) -> None:
        """Load policies from file."""
        self.policy_engine.load_from_file(filepath)
    
    def add_policy(self, policy: Policy) -> None:
        """Add a new policy."""
        self.policy_engine.add_policy(policy)
    
    def update_config(self, config: Dict[str, Any]) -> None:
        """Update decision maker configuration."""
        self.config.update(config)
        
        if 'scoring' in config:
            self.threat_scorer = ThreatScorer(config['scoring'])
        if 'rate_limiting' in config:
            self.rate_limiter = RateLimitTracker(config['rate_limiting'])
    
    def shutdown(self) -> None:
        """Shutdown the decision maker."""
        logger.info("Shutting down DecisionMaker")
        self._executor.shutdown(wait=True)
        self.decision_cache.clear()


# Convenience function for creating threat contexts
def create_threat_context(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    protocol: str,
    **kwargs
) -> ThreatContext:
    """Create a ThreatContext with the given parameters."""
    return ThreatContext(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        **kwargs
    )


if __name__ == "__main__":
    # Test the decision maker
    import asyncio
    
    logging.basicConfig(level=logging.INFO)
    
    # Create decision maker
    dm = DecisionMaker({
        'whitelist': ['192.168.1.1'],
        'internal_ranges': ['192.168.0.0/16', '10.0.0.0/8']
    })
    
    # Create a test context
    context = create_threat_context(
        source_ip='203.0.113.1',
        destination_ip='192.168.1.100',
        source_port=54321,
        destination_port=80,
        protocol='TCP'
    )
    
    # Add some threat indicators
    context.add_indicator(ThreatIndicator(
        source='signature_engine',
        indicator_type='signature',
        severity=ThreatLevel.HIGH,
        confidence=0.95,
        description='SQL injection attempt detected',
        details={'rule_id': 'SQLi-001', 'pattern': 'UNION SELECT'}
    ))
    
    context.add_indicator(ThreatIndicator(
        source='anomaly_engine',
        indicator_type='anomaly',
        severity=ThreatLevel.MEDIUM,
        confidence=0.75,
        description='Unusual request pattern',
        details={'anomaly_score': 0.82}
    ))
    
    # Add ML scores
    context.ml_scores = {
        'traffic_classifier': 0.85,
        'anomaly_detector': 0.78
    }
    
    # Make decision
    async def test():
        decision = await dm.make_decision(context)
        print(f"\nDecision: {decision.action.name}")
        print(f"Threat Level: {decision.threat_level.name}")
        print(f"Confidence: {decision.confidence.name}")
        print(f"Reason: {decision.reason}")
        print(f"Parameters: {decision.parameters}")
        print(f"Requires Review: {decision.requires_human_review}")
        
        # Print statistics
        stats = dm.get_statistics()
        print(f"\nStatistics: {json.dumps(stats, indent=2)}")
    
    asyncio.run(test())
    dm.shutdown()
