"""
Decision making component for QuantumShield.

This module provides a minimal but fully functional implementation of
the interfaces used by the engine and the adaptive learning system:

- DecisionMaker
- Decision
- ThreatContext
- ThreatIndicator
- ActionType
- ConfidenceLevel
- Policy
- PolicyEngine
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5


class ConfidenceLevel(Enum):
    """Confidence levels for decisions."""
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERY_HIGH = 5


class ActionType(Enum):
    """Available response actions."""
    ALLOW = "ALLOW"
    LOG = "LOG"
    ALERT = "ALERT"
    RATE_LIMIT = "RATE_LIMIT"
    THROTTLE = "THROTTLE"
    CHALLENGE = "CHALLENGE"
    BLOCK_TEMPORARY = "BLOCK_TEMPORARY"
    REDIRECT = "REDIRECT"
    HONEYPOT_REDIRECT = "HONEYPOT_REDIRECT"
    QUARANTINE = "QUARANTINE"
    BLOCK_PERMANENT = "BLOCK_PERMANENT"
    DROP_SILENT = "DROP_SILENT"
    RESET_CONNECTION = "RESET_CONNECTION"


@dataclass
class ThreatIndicator:
    """Single detection signal from an engine or model."""

    confidence: float
    name: str = ""  # Name/identifier of the indicator
    severity: ThreatLevel = ThreatLevel.MEDIUM
    details: Any = ""  # Details can be string or dict
    indicator_type: str = ""
    timestamp: float = field(default_factory=time.time)
    source: str = ""  # Source engine/module that generated this indicator
    description: str = ""  # Human-readable description
    
    def __post_init__(self):
        """Set defaults and handle aliases."""
        # Convert details dict to string if needed
        if isinstance(self.details, dict):
            import json
            self.details = json.dumps(self.details)
        elif not isinstance(self.details, str):
            self.details = str(self.details)
        
        # If description is provided but details is empty, use description for details
        if self.description and not self.details:
            self.details = self.description
        # If source is provided but name is not, use source for name
        if self.source and not self.name:
            self.name = self.source
        # If name is still empty, use indicator_type or a default
        if not self.name:
            self.name = self.indicator_type or "UnknownIndicator"


@dataclass
class ThreatContext:
    """
    Context about the traffic/flow being evaluated.
    
    Includes all fields needed by the engine and adaptive learning modules.
    """

    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    flow_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Fields for adaptive learning
    indicators: List[ThreatIndicator] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    ml_scores: Dict[str, float] = field(default_factory=dict)
    reputation_scores: Dict[str, float] = field(default_factory=dict)
    
    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Add a threat indicator to this context."""
        self.indicators.append(indicator)


@dataclass
class Decision:
    """Final decision produced by the DecisionMaker."""

    action: ActionType
    confidence: ConfidenceLevel
    threat_level: ThreatLevel
    context: ThreatContext
    indicators: List[ThreatIndicator] = field(default_factory=list)
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class Policy:
    """Security policy for automated decision making."""
    
    policy_id: str
    name: str
    description: str = ""
    priority: int = 500  # Lower priority = evaluated first
    enabled: bool = True
    conditions: Dict[str, Any] = field(default_factory=dict)
    actions: List[ActionType] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)


class PolicyEngine:
    """Manages security policies."""
    
    def __init__(self):
        self.policies: List[Policy] = []
    
    def add_policy(self, policy: Policy) -> None:
        """Add a new policy."""
        self.policies.append(policy)
        # Sort by priority (lower priority = higher precedence)
        self.policies.sort(key=lambda p: p.priority)
    
    def update_policy(self, policy: Policy) -> None:
        """Update an existing policy."""
        for i, p in enumerate(self.policies):
            if p.policy_id == policy.policy_id:
                self.policies[i] = policy
                # Re-sort
                self.policies.sort(key=lambda p: p.priority)
                return
        # If not found, add it
        self.add_policy(policy)
    
    def remove_policy(self, policy_id: str) -> None:
        """Remove a policy by ID."""
        self.policies = [p for p in self.policies if p.policy_id != policy_id]
    
    def get_policy(self, policy_id: str) -> Optional[Policy]:
        """Get a policy by ID."""
        for p in self.policies:
            if p.policy_id == policy_id:
                return p
        return None


class DecisionMaker:
    """
    Very simple rule‑based decision maker.

    This can be extended later, but is sufficient for running the engine
    and for integration with the adaptive learning module.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.conf_threshold = float(self.config.get("confidence_threshold", 0.7))
        self.policy_engine = PolicyEngine()
    
    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the policy engine."""
        self.policy_engine.add_policy(policy)
    
    def update_policy(self, policy: Policy) -> None:
        """Update a policy in the policy engine."""
        self.policy_engine.update_policy(policy)
    
    def remove_policy(self, policy_id: str) -> None:
        """Remove a policy from the policy engine."""
        self.policy_engine.remove_policy(policy_id)

    async def make_decision(
        self, context: ThreatContext, indicators: List[ThreatIndicator]
    ) -> Decision:
        """
        Produce a decision based on indicators.

        Current logic:
        - if there are no indicators → ALLOW
        - otherwise, compute max confidence and choose severity from the
          most severe indicator, BLOCK if above threshold, else LOG.
        """
        
        # Update context with indicators
        context.indicators = indicators

        if not indicators:
            return Decision(
                action=ActionType.ALLOW,
                confidence=ConfidenceLevel.VERY_LOW,
                threat_level=ThreatLevel.LOW,
                context=context,
                indicators=[],
            )

        max_conf = max(ind.confidence for ind in indicators)
        # Choose the most severe indicator
        top = max(indicators, key=lambda i: i.severity.value)

        # Map confidence to ConfidenceLevel
        if max_conf >= 0.9:
            conf_level = ConfidenceLevel.VERY_HIGH
        elif max_conf >= 0.7:
            conf_level = ConfidenceLevel.HIGH
        elif max_conf >= 0.5:
            conf_level = ConfidenceLevel.MEDIUM
        elif max_conf >= 0.3:
            conf_level = ConfidenceLevel.LOW
        else:
            conf_level = ConfidenceLevel.VERY_LOW

        # Determine action based on confidence threshold
        if max_conf >= self.conf_threshold:
            if top.severity.value >= ThreatLevel.CRITICAL.value:
                action = ActionType.BLOCK_PERMANENT
            else:
                action = ActionType.BLOCK_TEMPORARY
        else:
            action = ActionType.LOG

        return Decision(
            action=action,
            confidence=conf_level,
            threat_level=top.severity,
            context=context,
            indicators=indicators,
        )

    async def cleanup_cache(self) -> None:
        """
        Placeholder for cache/state cleanup.

        The engine calls this periodically; in this minimal
        implementation there is nothing to clean.
        """

        return None


