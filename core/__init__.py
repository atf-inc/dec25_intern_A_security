#!/usr/bin/env python3
"""
QuantumShield Core Module
Contains the main engine components for the IPS/Firewall system.
"""

from .engine import QuantumShieldEngine
from .packet_capture import PacketCapture
from .traffic_processor import (
    TrafficProcessor,
    AsyncTrafficProcessor,
    PacketParser,
    FlowTracker,
    FeatureExtractor,
    TrafficNormalizer,
    PacketInfo,
    NetworkFlow,
    FlowStatistics,
    ProtocolType,
    FlowState,
    FlowDirection
)
from .decision_maker import (
    DecisionMaker, 
    Decision, 
    ThreatContext,
    ThreatIndicator,
    ThreatLevel,
    ActionType,
    DecisionConfidence,
    Policy,
    create_threat_context
)
from .response_executor import (
    ResponseExecutor,
    ExecutionResult,
    ExecutionStatus,
    BlockEntry,
    RateLimitEntry
)

__all__ = [
    'QuantumShieldEngine',
    'PacketCapture',
    'TrafficProcessor',
    'AsyncTrafficProcessor',
    'PacketParser',
    'FlowTracker',
    'FeatureExtractor',
    'TrafficNormalizer',
    'PacketInfo',
    'NetworkFlow',
    'FlowStatistics',
    'ProtocolType',
    'FlowState',
    'FlowDirection',
    'DecisionMaker',
    'Decision',
    'ThreatContext',
    'ThreatIndicator',
    'ThreatLevel',
    'ActionType',
    'DecisionConfidence',
    'Policy',
    'create_threat_context',
    'ResponseExecutor',
    'ExecutionResult',
    'ExecutionStatus',
    'BlockEntry',
    'RateLimitEntry'
]

__version__ = '1.0.0'
