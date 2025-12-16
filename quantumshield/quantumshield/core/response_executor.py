#!/usr/bin/env python3
"""
QuantumShield - Response Executor Module
Executes response actions based on decisions from the Decision Maker.
"""

import asyncio
import logging
import time
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set
from enum import Enum, auto
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, Future
import json
import hashlib
import os
from datetime import datetime, timedelta

from .decision_maker import Decision, ActionType, ThreatLevel, ThreatContext, DecisionConfidence

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Status of action execution."""
    PENDING = auto()
    RUNNING = auto()
    SUCCESS = auto()
    FAILED = auto()
    PARTIALLY_COMPLETED = auto()
    CANCELLED = auto()
    EXPIRED = auto()


@dataclass
class ExecutionResult:
    """Result of executing an action."""
    action: ActionType
    status: ExecutionStatus
    message: str
    execution_time: float
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'action': self.action.name,
            'status': self.status.name,
            'message': self.message,
            'execution_time': self.execution_time,
            'details': self.details,
            'error': self.error,
            'timestamp': self.timestamp
        }


@dataclass
class BlockEntry:
    """Represents a blocked IP/port entry."""
    ip: str
    port: Optional[int]
    protocol: str
    reason: str
    created_at: float
    expires_at: Optional[float]
    rule_id: str
    block_type: str  # 'temporary' or 'permanent'
    decision_id: str
    
    def is_expired(self) -> bool:
        """Check if the block has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip': self.ip,
            'port': self.port,
            'protocol': self.protocol,
            'reason': self.reason,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'rule_id': self.rule_id,
            'block_type': self.block_type,
            'decision_id': self.decision_id
        }


@dataclass
class RateLimitEntry:
    """Represents a rate limit entry."""
    ip: str
    limit: int  # requests per second
    current_rate: float
    created_at: float
    expires_at: float
    decision_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip': self.ip,
            'limit': self.limit,
            'current_rate': self.current_rate,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'decision_id': self.decision_id
        }


class IPTablesManager:
    """Manages iptables rules for blocking and rate limiting."""
    
    def __init__(self, chain_name: str = "QUANTUMSHIELD"):
        self.chain_name = chain_name
        self._lock = threading.Lock()
        self._initialized = False
        
    def initialize(self) -> bool:
        """Initialize the iptables chain."""
        with self._lock:
            if self._initialized:
                return True
            
            try:
                # Create chain if not exists
                subprocess.run(
                    ['iptables', '-N', self.chain_name],
                    capture_output=True, check=False
                )
                
                # Insert jump to our chain at the beginning of INPUT
                subprocess.run(
                    ['iptables', '-C', 'INPUT', '-j', self.chain_name],
                    capture_output=True, check=False
                )
                result = subprocess.run(
                    ['iptables', '-I', 'INPUT', '1', '-j', self.chain_name],
                    capture_output=True, check=False
                )
                
                # Same for FORWARD chain
                subprocess.run(
                    ['iptables', '-I', 'FORWARD', '1', '-j', self.chain_name],
                    capture_output=True, check=False
                )
                
                self._initialized = True
                logger.info(f"IPTables chain {self.chain_name} initialized")
                return True
                
            except Exception as e:
                logger.error(f"Failed to initialize iptables: {e}")
                return False
    
    def add_block_rule(self, ip: str, port: Optional[int] = None,
                       protocol: str = 'all') -> Optional[str]:
        """Add a block rule for an IP/port."""
        with self._lock:
            rule_id = hashlib.md5(f"{ip}:{port}:{protocol}:{time.time()}".encode()).hexdigest()[:12]
            
            cmd = ['iptables', '-A', self.chain_name, '-s', ip]
            
            if port and protocol.lower() in ['tcp', 'udp']:
                cmd.extend(['-p', protocol.lower(), '--dport', str(port)])
            elif protocol.lower() != 'all':
                cmd.extend(['-p', protocol.lower()])
            
            cmd.extend(['-j', 'DROP', '-m', 'comment', '--comment', f'qs_{rule_id}'])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                logger.info(f"Added block rule {rule_id} for {ip}")
                return rule_id
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to add block rule: {e.stderr}")
                return None
    
    def remove_block_rule(self, rule_id: str) -> bool:
        """Remove a block rule by ID."""
        with self._lock:
            try:
                # Find and remove the rule with matching comment
                result = subprocess.run(
                    ['iptables', '-L', self.chain_name, '-n', '--line-numbers'],
                    capture_output=True, text=True, check=True
                )
                
                for line in result.stdout.split('\n'):
                    if f'qs_{rule_id}' in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            rule_num = parts[0]
                            subprocess.run(
                                ['iptables', '-D', self.chain_name, rule_num],
                                capture_output=True, check=True
                            )
                            logger.info(f"Removed block rule {rule_id}")
                            return True
                
                return False
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to remove block rule {rule_id}: {e.stderr}")
                return False
    
    def add_rate_limit_rule(self, ip: str, limit: int, 
                            burst: int = 10) -> Optional[str]:
        """Add a rate limiting rule for an IP."""
        with self._lock:
            rule_id = hashlib.md5(f"rl_{ip}:{time.time()}".encode()).hexdigest()[:12]
            
            # Using hashlimit for rate limiting
            cmd = [
                'iptables', '-A', self.chain_name,
                '-s', ip,
                '-m', 'hashlimit',
                '--hashlimit-above', f'{limit}/sec',
                '--hashlimit-burst', str(burst),
                '--hashlimit-mode', 'srcip',
                '--hashlimit-name', f'qs_rl_{rule_id}',
                '-j', 'DROP',
                '-m', 'comment', '--comment', f'qs_rl_{rule_id}'
            ]
            
            try:
                subprocess.run(cmd, capture_output=True, text=True, check=True)
                logger.info(f"Added rate limit rule {rule_id} for {ip}: {limit}/sec")
                return rule_id
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to add rate limit rule: {e.stderr}")
                return None
    
    def list_rules(self) -> List[Dict[str, Any]]:
        """List all rules in our chain."""
        with self._lock:
            try:
                result = subprocess.run(
                    ['iptables', '-L', self.chain_name, '-n', '-v', '--line-numbers'],
                    capture_output=True, text=True, check=True
                )
                
                rules = []
                for line in result.stdout.split('\n')[2:]:  # Skip header lines
                    if line.strip():
                        rules.append({'raw': line})
                
                return rules
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to list rules: {e.stderr}")
                return []
    
    def flush_chain(self) -> bool:
        """Flush all rules from our chain."""
        with self._lock:
            try:
                subprocess.run(
                    ['iptables', '-F', self.chain_name],
                    capture_output=True, check=True
                )
                logger.info(f"Flushed chain {self.chain_name}")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to flush chain: {e.stderr}")
                return False
    
    def cleanup(self) -> bool:
        """Remove the chain completely."""
        with self._lock:
            try:
                # Remove jump rules
                subprocess.run(
                    ['iptables', '-D', 'INPUT', '-j', self.chain_name],
                    capture_output=True, check=False
                )
                subprocess.run(
                    ['iptables', '-D', 'FORWARD', '-j', self.chain_name],
                    capture_output=True, check=False
                )
                
                # Flush and delete chain
                subprocess.run(
                    ['iptables', '-F', self.chain_name],
                    capture_output=True, check=False
                )
                subprocess.run(
                    ['iptables', '-X', self.chain_name],
                    capture_output=True, check=False
                )
                
                self._initialized = False
                logger.info(f"Cleaned up chain {self.chain_name}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to cleanup chain: {e}")
                return False


class AlertDispatcher:
    """Dispatches alerts through various channels."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._handlers: Dict[str, Callable] = {}
        self._setup_default_handlers()
    
    def _setup_default_handlers(self) -> None:
        """Setup default alert handlers."""
        self._handlers['log'] = self._log_alert
        self._handlers['file'] = self._file_alert
        
        if self.config.get('email'):
            self._handlers['email'] = self._email_alert
        if self.config.get('webhook'):
            self._handlers['webhook'] = self._webhook_alert
        if self.config.get('syslog'):
            self._handlers['syslog'] = self._syslog_alert
    
    async def dispatch(self, decision: Decision, 
                       channels: Optional[List[str]] = None) -> Dict[str, bool]:
        """Dispatch alert through specified channels."""
        if channels is None:
            channels = list(self._handlers.keys())
        
        results = {}
        for channel in channels:
            if channel in self._handlers:
                try:
                    await self._handlers[channel](decision)
                    results[channel] = True
                except Exception as e:
                    logger.error(f"Failed to dispatch alert to {channel}: {e}")
                    results[channel] = False
        
        return results
    
    async def _log_alert(self, decision: Decision) -> None:
        """Log alert to application logger."""
        level = logging.CRITICAL if decision.threat_level.value >= ThreatLevel.CRITICAL.value \
            else logging.WARNING
        
        logger.log(level, 
            f"SECURITY ALERT: {decision.action.name} | "
            f"Threat: {decision.threat_level.name} | "
            f"Source: {decision.context.source_ip} | "
            f"Reason: {decision.reason}"
        )
    
    async def _file_alert(self, decision: Decision) -> None:
        """Write alert to file."""
        alert_file = self.config.get('alert_file', '/var/log/quantumshield/alerts.json')
        
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'decision_id': decision.decision_id,
            'action': decision.action.name,
            'threat_level': decision.threat_level.name,
            'confidence': decision.confidence.name,
            'source_ip': decision.context.source_ip,
            'destination_ip': decision.context.destination_ip,
            'source_port': decision.context.source_port,
            'destination_port': decision.context.destination_port,
            'protocol': decision.context.protocol,
            'reason': decision.reason,
            'parameters': decision.parameters
        }
        
        os.makedirs(os.path.dirname(alert_file), exist_ok=True)
        
        with open(alert_file, 'a') as f:
            f.write(json.dumps(alert_data) + '\n')
    
    async def _email_alert(self, decision: Decision) -> None:
        """Send email alert."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        email_config = self.config.get('email', {})
        
        msg = MIMEMultipart()
        msg['From'] = email_config.get('from', 'quantumshield@localhost')
        msg['To'] = email_config.get('to', 'admin@localhost')
        msg['Subject'] = f"[QuantumShield] {decision.threat_level.name} Alert: {decision.action.name}"
        
        body = f"""
        Security Alert from QuantumShield
        
        Decision ID: {decision.decision_id}
        Action: {decision.action.name}
        Threat Level: {decision.threat_level.name}
        Confidence: {decision.confidence.name}
        
        Source: {decision.context.source_ip}:{decision.context.source_port}
        Destination: {decision.context.destination_ip}:{decision.context.destination_port}
        Protocol: {decision.context.protocol}
        
        Reason: {decision.reason}
        
        Indicators:
        {json.dumps([ind.to_dict() for ind in decision.context.indicators], indent=2)}
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            server = smtplib.SMTP(
                email_config.get('smtp_host', 'localhost'),
                email_config.get('smtp_port', 25)
            )
            if email_config.get('use_tls'):
                server.starttls()
            if email_config.get('username'):
                server.login(email_config['username'], email_config.get('password', ''))
            server.send_message(msg)
            server.quit()
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            raise
    
    async def _webhook_alert(self, decision: Decision) -> None:
        """Send webhook alert."""
        import aiohttp
        
        webhook_config = self.config.get('webhook', {})
        url = webhook_config.get('url')
        
        if not url:
            return
        
        payload = {
            'timestamp': datetime.now().isoformat(),
            'decision_id': decision.decision_id,
            'action': decision.action.name,
            'threat_level': decision.threat_level.name,
            'source_ip': decision.context.source_ip,
            'destination_ip': decision.context.destination_ip,
            'reason': decision.reason
        }
        
        headers = webhook_config.get('headers', {})
        headers['Content-Type'] = 'application/json'
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as response:
                if response.status >= 400:
                    raise Exception(f"Webhook returned status {response.status}")
    
    async def _syslog_alert(self, decision: Decision) -> None:
        """Send syslog alert."""
        import syslog
        
        priority = syslog.LOG_CRIT if decision.threat_level.value >= ThreatLevel.CRITICAL.value \
            else syslog.LOG_WARNING
        
        message = (f"QuantumShield: action={decision.action.name} "
                   f"threat={decision.threat_level.name} "
                   f"src={decision.context.source_ip} "
                   f"dst={decision.context.destination_ip} "
                   f"reason=\"{decision.reason}\"")
        
        syslog.syslog(priority, message)
    
    def register_handler(self, name: str, handler: Callable) -> None:
        """Register a custom alert handler."""
        self._handlers[name] = handler


class QuarantineManager:
    """Manages quarantine of suspicious traffic and sessions."""
    
    def __init__(self, quarantine_dir: str = '/var/lib/quantumshield/quarantine'):
        self.quarantine_dir = quarantine_dir
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        
        os.makedirs(quarantine_dir, exist_ok=True)
    
    def quarantine(self, decision: Decision, 
                   data: Optional[bytes] = None) -> str:
        """Quarantine traffic associated with a decision."""
        quarantine_id = hashlib.md5(
            f"{decision.decision_id}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        entry = {
            'quarantine_id': quarantine_id,
            'decision_id': decision.decision_id,
            'source_ip': decision.context.source_ip,
            'destination_ip': decision.context.destination_ip,
            'timestamp': time.time(),
            'threat_level': decision.threat_level.name,
            'reason': decision.reason,
            'indicators': [ind.to_dict() for ind in decision.context.indicators]
        }
        
        with self._lock:
            self._entries[quarantine_id] = entry
            
            # Save to file
            entry_file = os.path.join(self.quarantine_dir, f"{quarantine_id}.json")
            with open(entry_file, 'w') as f:
                json.dump(entry, f, indent=2)
            
            # Save captured data if provided
            if data:
                data_file = os.path.join(self.quarantine_dir, f"{quarantine_id}.pcap")
                with open(data_file, 'wb') as f:
                    f.write(data)
        
        logger.info(f"Quarantined traffic: {quarantine_id}")
        return quarantine_id
    
    def release(self, quarantine_id: str) -> bool:
        """Release quarantined traffic."""
        with self._lock:
            if quarantine_id in self._entries:
                del self._entries[quarantine_id]
                
                # Remove files
                for ext in ['.json', '.pcap']:
                    filepath = os.path.join(self.quarantine_dir, f"{quarantine_id}{ext}")
                    if os.path.exists(filepath):
                        os.remove(filepath)
                
                logger.info(f"Released quarantine: {quarantine_id}")
                return True
            return False
    
    def list_entries(self) -> List[Dict[str, Any]]:
        """List all quarantine entries."""
        with self._lock:
            return list(self._entries.values())
    
    def get_entry(self, quarantine_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific quarantine entry."""
        with self._lock:
            return self._entries.get(quarantine_id)


class TrafficShaper:
    """Manages traffic shaping and QoS."""
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
        self._classes: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
    
    def shape_traffic(self, ip: str, rate: str, burst: str = '32k') -> bool:
        """Apply traffic shaping to an IP."""
        with self._lock:
            try:
                # Using tc (traffic control) for shaping
                class_id = len(self._classes) + 10
                
                # Add class
                subprocess.run([
                    'tc', 'class', 'add', 'dev', self.interface,
                    'parent', '1:1', 'classid', f'1:{class_id}',
                    'htb', 'rate', rate, 'burst', burst
                ], capture_output=True, check=True)
                
                # Add filter for IP
                subprocess.run([
                    'tc', 'filter', 'add', 'dev', self.interface,
                    'parent', '1:0', 'protocol', 'ip',
                    'u32', 'match', 'ip', 'src', ip,
                    'flowid', f'1:{class_id}'
                ], capture_output=True, check=True)
                
                self._classes[ip] = {'class_id': class_id, 'rate': rate}
                logger.info(f"Applied traffic shaping to {ip}: {rate}")
                return True
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to apply traffic shaping: {e}")
                return False
    
    def remove_shaping(self, ip: str) -> bool:
        """Remove traffic shaping from an IP."""
        with self._lock:
            if ip not in self._classes:
                return False
            
            try:
                class_id = self._classes[ip]['class_id']
                
                # Remove filter and class
                subprocess.run([
                    'tc', 'filter', 'del', 'dev', self.interface,
                    'parent', '1:0', 'protocol', 'ip',
                    'u32', 'match', 'ip', 'src', ip
                ], capture_output=True, check=False)
                
                subprocess.run([
                    'tc', 'class', 'del', 'dev', self.interface,
                    'parent', '1:1', 'classid', f'1:{class_id}'
                ], capture_output=True, check=False)
                
                del self._classes[ip]
                logger.info(f"Removed traffic shaping from {ip}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to remove traffic shaping: {e}")
                return False


class ActionHandler:
    """Handles individual action types."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.iptables = IPTablesManager()
        self.alert_dispatcher = AlertDispatcher(config.get('alerts'))
        self.quarantine_manager = QuarantineManager()
        self.traffic_shaper = TrafficShaper(config.get('interface', 'eth0'))
        
        # Initialize iptables
        if not config.get('dry_run'):
            self.iptables.initialize()
    
    async def handle_allow(self, decision: Decision) -> ExecutionResult:
        """Handle ALLOW action."""
        return ExecutionResult(
            action=ActionType.ALLOW,
            status=ExecutionStatus.SUCCESS,
            message=f"Traffic allowed from {decision.context.source_ip}",
            execution_time=0.0
        )
    
    async def handle_log(self, decision: Decision) -> ExecutionResult:
        """Handle LOG action."""
        start = time.time()
        
        # Log to file
        await self.alert_dispatcher._file_alert(decision)
        
        return ExecutionResult(
            action=ActionType.LOG,
            status=ExecutionStatus.SUCCESS,
            message=f"Logged traffic from {decision.context.source_ip}",
            execution_time=time.time() - start
        )
    
    async def handle_alert(self, decision: Decision) -> ExecutionResult:
        """Handle ALERT action."""
        start = time.time()
        
        channels = self.config.get('alert_channels', ['log', 'file'])
        results = await self.alert_dispatcher.dispatch(decision, channels)
        
        success_count = sum(1 for v in results.values() if v)
        status = ExecutionStatus.SUCCESS if success_count == len(results) else \
            ExecutionStatus.PARTIALLY_COMPLETED if success_count > 0 else \
            ExecutionStatus.FAILED
        
        return ExecutionResult(
            action=ActionType.ALERT,
            status=status,
            message=f"Alert dispatched to {success_count}/{len(results)} channels",
            execution_time=time.time() - start,
            details={'channel_results': results}
        )
    
    async def handle_rate_limit(self, decision: Decision) -> ExecutionResult:
        """Handle RATE_LIMIT action."""
        start = time.time()
        
        limit = decision.parameters.get('rate_limit', 10)
        burst = decision.parameters.get('burst', 20)
        
        if self.config.get('dry_run'):
            return ExecutionResult(
                action=ActionType.RATE_LIMIT,
                status=ExecutionStatus.SUCCESS,
                message=f"[DRY RUN] Would rate limit {decision.context.source_ip} to {limit}/sec",
                execution_time=time.time() - start
            )
        
        rule_id = self.iptables.add_rate_limit_rule(
            decision.context.source_ip, limit, burst
        )
        
        if rule_id:
            return ExecutionResult(
                action=ActionType.RATE_LIMIT,
                status=ExecutionStatus.SUCCESS,
                message=f"Rate limited {decision.context.source_ip} to {limit}/sec",
                execution_time=time.time() - start,
                details={'rule_id': rule_id, 'limit': limit, 'burst': burst}
            )
        else:
            return ExecutionResult(
                action=ActionType.RATE_LIMIT,
                status=ExecutionStatus.FAILED,
                message=f"Failed to rate limit {decision.context.source_ip}",
                execution_time=time.time() - start,
                error="IPTables rule creation failed"
            )
    
    async def handle_block_temporary(self, decision: Decision) -> ExecutionResult:
        """Handle BLOCK_TEMPORARY action."""
        start = time.time()
        duration = decision.parameters.get('block_duration', 300)
        
        if self.config.get('dry_run'):
            return ExecutionResult(
                action=ActionType.BLOCK_TEMPORARY,
                status=ExecutionStatus.SUCCESS,
                message=f"[DRY RUN] Would temporarily block {decision.context.source_ip} for {duration}s",
                execution_time=time.time() - start
            )
        
        rule_id = self.iptables.add_block_rule(
            decision.context.source_ip,
            decision.context.destination_port,
            decision.context.protocol
        )
        
        if rule_id:
            return ExecutionResult(
                action=ActionType.BLOCK_TEMPORARY,
                status=ExecutionStatus.SUCCESS,
                message=f"Temporarily blocked {decision.context.source_ip} for {duration}s",
                execution_time=time.time() - start,
                details={
                    'rule_id': rule_id,
                    'duration': duration,
                    'expires_at': time.time() + duration
                }
            )
        else:
            return ExecutionResult(
                action=ActionType.BLOCK_TEMPORARY,
                status=ExecutionStatus.FAILED,
                message=f"Failed to block {decision.context.source_ip}",
                execution_time=time.time() - start,
                error="IPTables rule creation failed"
            )
    
    async def handle_block_permanent(self, decision: Decision) -> ExecutionResult:
        """Handle BLOCK_PERMANENT action."""
        start = time.time()
        
        if self.config.get('dry_run'):
            return ExecutionResult(
                action=ActionType.BLOCK_PERMANENT,
                status=ExecutionStatus.SUCCESS,
                message=f"[DRY RUN] Would permanently block {decision.context.source_ip}",
                execution_time=time.time() - start
            )
        
        rule_id = self.iptables.add_block_rule(
            decision.context.source_ip,
            None,  # Block all ports
            'all'
        )
        
        if rule_id:
            return ExecutionResult(
                action=ActionType.BLOCK_PERMANENT,
                status=ExecutionStatus.SUCCESS,
                message=f"Permanently blocked {decision.context.source_ip}",
                execution_time=time.time() - start,
                details={'rule_id': rule_id}
            )
        else:
            return ExecutionResult(
                action=ActionType.BLOCK_PERMANENT,
                status=ExecutionStatus.FAILED,
                message=f"Failed to permanently block {decision.context.source_ip}",
                execution_time=time.time() - start,
                error="IPTables rule creation failed"
            )
    
    async def handle_quarantine(self, decision: Decision) -> ExecutionResult:
        """Handle QUARANTINE action."""
        start = time.time()
        
        quarantine_id = self.quarantine_manager.quarantine(decision)
        
        return ExecutionResult(
            action=ActionType.QUARANTINE,
            status=ExecutionStatus.SUCCESS,
            message=f"Quarantined traffic from {decision.context.source_ip}",
            execution_time=time.time() - start,
            details={'quarantine_id': quarantine_id}
        )
    
    async def handle_throttle(self, decision: Decision) -> ExecutionResult:
        """Handle THROTTLE action."""
        start = time.time()
        rate = decision.parameters.get('throttle_rate', '1mbit')
        
        if self.config.get('dry_run'):
            return ExecutionResult(
                action=ActionType.THROTTLE,
                status=ExecutionStatus.SUCCESS,
                message=f"[DRY RUN] Would throttle {decision.context.source_ip} to {rate}",
                execution_time=time.time() - start
            )
        
        success = self.traffic_shaper.shape_traffic(
            decision.context.source_ip, rate
        )
        
        if success:
            return ExecutionResult(
                action=ActionType.THROTTLE,
                status=ExecutionStatus.SUCCESS,
                message=f"Throttled {decision.context.source_ip} to {rate}",
                execution_time=time.time() - start,
                details={'rate': rate}
            )
        else:
            return ExecutionResult(
                action=ActionType.THROTTLE,
                status=ExecutionStatus.FAILED,
                message=f"Failed to throttle {decision.context.source_ip}",
                execution_time=time.time() - start,
                error="Traffic shaping failed"
            )
    
    async def handle_drop_silent(self, decision: Decision) -> ExecutionResult:
        """Handle DROP_SILENT action (drop without response)."""
        return await self.handle_block_temporary(decision)
    
    async def handle_reset_connection(self, decision: Decision) -> ExecutionResult:
        """Handle RESET_CONNECTION action."""
        start = time.time()
        
        if self.config.get('dry_run'):
            return ExecutionResult(
                action=ActionType.RESET_CONNECTION,
                status=ExecutionStatus.SUCCESS,
                message=f"[DRY RUN] Would reset connection from {decision.context.source_ip}",
                execution_time=time.time() - start
            )
        
        # Add rule to reject with TCP reset
        cmd = [
            'iptables', '-A', self.iptables.chain_name,
            '-s', decision.context.source_ip,
            '-p', 'tcp',
            '--dport', str(decision.context.destination_port),
            '-j', 'REJECT', '--reject-with', 'tcp-reset'
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, check=True)
            return ExecutionResult(
                action=ActionType.RESET_CONNECTION,
                status=ExecutionStatus.SUCCESS,
                message=f"Reset connection from {decision.context.source_ip}",
                execution_time=time.time() - start
            )
        except subprocess.CalledProcessError as e:
            return ExecutionResult(
                action=ActionType.RESET_CONNECTION,
                status=ExecutionStatus.FAILED,
                message=f"Failed to reset connection",
                execution_time=time.time() - start,
                error=str(e)
            )
    
    async def handle_challenge(self, decision: Decision) -> ExecutionResult:
        """Handle CHALLENGE action (e.g., CAPTCHA)."""
        start = time.time()
        
        # This would typically integrate with a web server
        # For now, we just log the challenge requirement
        challenge_token = hashlib.md5(
            f"{decision.context.source_ip}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        return ExecutionResult(
            action=ActionType.CHALLENGE,
            status=ExecutionStatus.SUCCESS,
            message=f"Challenge issued to {decision.context.source_ip}",
            execution_time=time.time() - start,
            details={'challenge_token': challenge_token}
        )
    
    async def handle_honeypot_redirect(self, decision: Decision) -> ExecutionResult:
        """Handle HONEYPOT_REDIRECT action."""
        start = time.time()
        honeypot_ip = self.config.get('honeypot_ip', '10.0.0.254')
        
        if self.config.get('dry_run'):
            return ExecutionResult(
                action=ActionType.HONEYPOT_REDIRECT,
                status=ExecutionStatus.SUCCESS,
                message=f"[DRY RUN] Would redirect {decision.context.source_ip} to honeypot",
                execution_time=time.time() - start
            )
        
        # Add DNAT rule to redirect to honeypot
        cmd = [
            'iptables', '-t', 'nat', '-A', 'PREROUTING',
            '-s', decision.context.source_ip,
            '-j', 'DNAT', '--to-destination', honeypot_ip
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, check=True)
            return ExecutionResult(
                action=ActionType.HONEYPOT_REDIRECT,
                status=ExecutionStatus.SUCCESS,
                message=f"Redirected {decision.context.source_ip} to honeypot {honeypot_ip}",
                execution_time=time.time() - start,
                details={'honeypot_ip': honeypot_ip}
            )
        except subprocess.CalledProcessError as e:
            return ExecutionResult(
                action=ActionType.HONEYPOT_REDIRECT,
                status=ExecutionStatus.FAILED,
                message=f"Failed to redirect to honeypot",
                execution_time=time.time() - start,
                error=str(e)
            )


class ResponseExecutor:
    """
    Main class for executing security response actions.
    Orchestrates various handlers and manages execution flow.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.action_handler = ActionHandler(config)
        
        # Execution queue
        self._queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        
        # Track active blocks
        self._active_blocks: Dict[str, BlockEntry] = {}
        self._active_rate_limits: Dict[str, RateLimitEntry] = {}
        self._lock = threading.Lock()
        
        # Executor for blocking operations
        self._executor = ThreadPoolExecutor(max_workers=8)
        
        # Callbacks
        self._result_callbacks: List[Callable[[ExecutionResult], None]] = []
        
        # Statistics
        self.stats = {
            'total_executions': 0,
            'executions_by_action': defaultdict(int),
            'executions_by_status': defaultdict(int),
            'execution_times': []
        }
        self._stats_lock = threading.Lock()
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        
        logger.info("ResponseExecutor initialized")
    
    def _get_handler(self, action: ActionType) -> Callable:
        """Get the appropriate handler for an action type."""
        handlers = {
            ActionType.ALLOW: self.action_handler.handle_allow,
            ActionType.LOG: self.action_handler.handle_log,
            ActionType.ALERT: self.action_handler.handle_alert,
            ActionType.RATE_LIMIT: self.action_handler.handle_rate_limit,
            ActionType.THROTTLE: self.action_handler.handle_throttle,
            ActionType.BLOCK_TEMPORARY: self.action_handler.handle_block_temporary,
            ActionType.BLOCK_PERMANENT: self.action_handler.handle_block_permanent,
            ActionType.QUARANTINE: self.action_handler.handle_quarantine,
            ActionType.DROP_SILENT: self.action_handler.handle_drop_silent,
            ActionType.RESET_CONNECTION: self.action_handler.handle_reset_connection,
            ActionType.CHALLENGE: self.action_handler.handle_challenge,
            ActionType.HONEYPOT_REDIRECT: self.action_handler.handle_honeypot_redirect
        }
        return handlers.get(action, self.action_handler.handle_log)
    
    async def execute(self, decision: Decision) -> List[ExecutionResult]:
        """
        Execute all actions for a decision.
        Returns a list of execution results.
        """
        results = []
        
        # Get all actions to execute
        actions = [decision.action]
        if 'all_actions' in decision.parameters:
            for action_name in decision.parameters['all_actions']:
                try:
                    action = ActionType[action_name]
                    if action not in actions:
                        actions.append(action)
                except KeyError:
                    pass
        
        # Execute each action
        for action in actions:
            result = await self._execute_single(action, decision)
            results.append(result)
            
            # Track blocks
            if action in [ActionType.BLOCK_TEMPORARY, ActionType.BLOCK_PERMANENT]:
                self._track_block(decision, result)
            elif action == ActionType.RATE_LIMIT:
                self._track_rate_limit(decision, result)
        
        # Update statistics
        self._update_stats(results)
        
        # Notify callbacks
        for callback in self._result_callbacks:
            for result in results:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Error in result callback: {e}")
        
        return results
    
    async def _execute_single(self, action: ActionType, 
                             decision: Decision) -> ExecutionResult:
        """Execute a single action."""
        handler = self._get_handler(action)
        
        try:
            result = await handler(decision)
            return result
        except Exception as e:
            logger.error(f"Error executing action {action.name}: {e}", exc_info=True)
            return ExecutionResult(
                action=action,
                status=ExecutionStatus.FAILED,
                message=f"Exception during execution",
                execution_time=0.0,
                error=str(e)
            )
    
    def _track_block(self, decision: Decision, result: ExecutionResult) -> None:
        """Track an active block."""
        if result.status != ExecutionStatus.SUCCESS:
            return
        
        with self._lock:
            entry = BlockEntry(
                ip=decision.context.source_ip,
                port=decision.context.destination_port,
                protocol=decision.context.protocol,
                reason=decision.reason,
                created_at=time.time(),
                expires_at=result.details.get('expires_at'),
                rule_id=result.details.get('rule_id', ''),
                block_type='temporary' if decision.action == ActionType.BLOCK_TEMPORARY else 'permanent',
                decision_id=decision.decision_id
            )
            self._active_blocks[entry.ip] = entry
    
    def _track_rate_limit(self, decision: Decision, result: ExecutionResult) -> None:
        """Track an active rate limit."""
        if result.status != ExecutionStatus.SUCCESS:
            return
        
        with self._lock:
            entry = RateLimitEntry(
                ip=decision.context.source_ip,
                limit=result.details.get('limit', 10),
                current_rate=0,
                created_at=time.time(),
                expires_at=time.time() + decision.parameters.get('rate_limit_duration', 300),
                decision_id=decision.decision_id
            )
            self._active_rate_limits[entry.ip] = entry
    
    def _update_stats(self, results: List[ExecutionResult]) -> None:
        """Update execution statistics."""
        with self._stats_lock:
            for result in results:
                self.stats['total_executions'] += 1
                self.stats['executions_by_action'][result.action.name] += 1
                self.stats['executions_by_status'][result.status.name] += 1
                self.stats['execution_times'].append(result.execution_time)
                
                # Keep only last 1000 times
                if len(self.stats['execution_times']) > 1000:
                    self.stats['execution_times'] = self.stats['execution_times'][-1000:]
    
    async def start(self) -> None:
        """Start the response executor."""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("ResponseExecutor started")
    
    async def stop(self) -> None:
        """Stop the response executor."""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        self._executor.shutdown(wait=True)
        logger.info("ResponseExecutor stopped")
    
    async def _cleanup_loop(self) -> None:
        """Background loop to clean up expired blocks."""
        while self._running:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    async def _cleanup_expired(self) -> None:
        """Clean up expired blocks and rate limits."""
        current_time = time.time()
        
        with self._lock:
            # Clean up expired blocks
            expired_blocks = [
                ip for ip, entry in self._active_blocks.items()
                if entry.is_expired()
            ]
            
            for ip in expired_blocks:
                entry = self._active_blocks[ip]
                self.action_handler.iptables.remove_block_rule(entry.rule_id)
                del self._active_blocks[ip]
                logger.info(f"Removed expired block for {ip}")
            
            # Clean up expired rate limits
            expired_limits = [
                ip for ip, entry in self._active_rate_limits.items()
                if current_time > entry.expires_at
            ]
            
            for ip in expired_limits:
                # Rate limits are typically removed by iptables hashlimit automatically
                del self._active_rate_limits[ip]
                logger.info(f"Removed expired rate limit for {ip}")
    
    def get_active_blocks(self) -> List[Dict[str, Any]]:
        """Get list of active blocks."""
        with self._lock:
            return [entry.to_dict() for entry in self._active_blocks.values()]
    
    def get_active_rate_limits(self) -> List[Dict[str, Any]]:
        """Get list of active rate limits."""
        with self._lock:
            return [entry.to_dict() for entry in self._active_rate_limits.values()]
    
    def unblock(self, ip: str) -> bool:
        """Manually unblock an IP."""
        with self._lock:
            if ip in self._active_blocks:
                entry = self._active_blocks[ip]
                success = self.action_handler.iptables.remove_block_rule(entry.rule_id)
                if success:
                    del self._active_blocks[ip]
                    logger.info(f"Manually unblocked {ip}")
                return success
            return False
    
    def remove_rate_limit(self, ip: str) -> bool:
        """Manually remove rate limit from an IP."""
        with self._lock:
            if ip in self._active_rate_limits:
                del self._active_rate_limits[ip]
                logger.info(f"Manually removed rate limit for {ip}")
                return True
            return False
    
    def register_callback(self, callback: Callable[[ExecutionResult], None]) -> None:
        """Register a callback for execution results."""
        self._result_callbacks.append(callback)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get executor statistics."""
        with self._stats_lock:
            exec_times = self.stats['execution_times']
            return {
                'total_executions': self.stats['total_executions'],
                'executions_by_action': dict(self.stats['executions_by_action']),
                'executions_by_status': dict(self.stats['executions_by_status']),
                'active_blocks': len(self._active_blocks),
                'active_rate_limits': len(self._active_rate_limits),
                'avg_execution_time_ms': (
                    sum(exec_times) / len(exec_times) * 1000 if exec_times else 0
                ),
                'max_execution_time_ms': max(exec_times) * 1000 if exec_times else 0
            }
    
    def cleanup(self) -> None:
        """Clean up all iptables rules."""
        self.action_handler.iptables.cleanup()
        with self._lock:
            self._active_blocks.clear()
            self._active_rate_limits.clear()


if __name__ == "__main__":
    # Test the response executor
    import asyncio
    from .decision_maker import create_threat_context, ThreatIndicator
    
    logging.basicConfig(level=logging.INFO)
    
    async def test():
        # Create executor in dry-run mode
        executor = ResponseExecutor({'dry_run': True})
        await executor.start()
        
        # Create a test decision
        context = create_threat_context(
            source_ip='192.0.2.100',
            destination_ip='10.0.0.1',
            source_port=54321,
            destination_port=80,
            protocol='TCP'
        )
        
        decision = Decision(
            action=ActionType.BLOCK_TEMPORARY,
            threat_level=ThreatLevel.HIGH,
            confidence=DecisionConfidence.HIGH,
            reason="Test block",
            context=context,
            parameters={
                'all_actions': ['BLOCK_TEMPORARY', 'ALERT', 'LOG'],
                'block_duration': 60
            }
        )
        
        # Execute
        results = await executor.execute(decision)
        
        for result in results:
            print(f"\nAction: {result.action.name}")
            print(f"Status: {result.status.name}")
            print(f"Message: {result.message}")
            print(f"Time: {result.execution_time*1000:.2f}ms")
        
        # Print stats
        stats = executor.get_statistics()
        print(f"\nStatistics: {json.dumps(stats, indent=2)}")
        
        await executor.stop()
    
    asyncio.run(test())
