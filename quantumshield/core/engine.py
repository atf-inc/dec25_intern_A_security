"""
Main Orchestration Engine
Coordinates all system components and manages lifecycle
"""

import asyncio
import logging
import signal
from typing import Dict, List, Optional
from datetime import datetime
import multiprocessing as mp

from .packet_capture import PacketCapture
from .traffic_processor import AsyncTrafficProcessor
from .decision_maker import DecisionMaker, ThreatContext, ThreatIndicator
from .response_executor import ResponseExecutor
try:
    from ..threat_intelligence.threat_manager import ThreatManager
except (ImportError, ValueError):
    try:
        from threat_intelligence.threat_manager import ThreatManager
    except ImportError:
        # Fallback if running from a different context
        import sys
        import os
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
        from threat_intelligence.threat_manager import ThreatManager

try:
    from ..ml_models.model_manager import ModelManager
except (ImportError, ValueError):
    # Fallback/Mock
    ModelManager = None

try:
    from ..adaptive_learning.adaptive_learner import AdaptiveLearner
except (ImportError, ValueError):
    AdaptiveLearner = None

logger = logging.getLogger(__name__)


class QuantumShieldEngine:
    """Main orchestration engine for QuantumShield IPS/Firewall"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.running = False
        self.components = {}
        self._tasks = []
        
        # Initialize core components
        self.packet_capture = PacketCapture(config.get('capture', {}))
        # Use async wrapper so engine can await processing
        self.traffic_processor = AsyncTrafficProcessor(config.get('processor', {}))
        self.decision_maker = DecisionMaker(config.get('decision', {}))
        self.response_executor = ResponseExecutor(config.get('response', {}))
        self.response_executor = ResponseExecutor(config.get('response', {}))
        self.threat_manager = ThreatManager()
        
        # Initialize ML Manager
        self.model_manager = None
        if ModelManager and config.get('ml_models', {}).get('enabled', True):
            self.model_manager = ModelManager()
            
        # Initialize Adaptive Learner
        self.adaptive_learner = None
        if AdaptiveLearner and config.get('adaptive_learning', {}).get('enabled', True):
            self.adaptive_learner = AdaptiveLearner(self.decision_maker, config.get('adaptive_learning', {}))
        
        # Initialize WAF Engine if enabled
        self.waf_engine = None
        if config.get('waf', {}).get('enabled', True):
            try:
                from ..application_layer.waf import WAFEngine
                self.waf_engine = WAFEngine(config.get('waf', {}))
            except Exception as e:
                import traceback
                import sys
                sys.stderr.write(f"CRITICAL ERROR loading WAF Engine: {e}\n")
                traceback.print_exc(file=sys.stderr)
                logger.error(f"Failed to load WAF Engine: {e}")

        # Detection engines (will be imported dynamically)
        self.detection_engines = []
        
        # ML models (will be loaded)
        self.ml_models = {}
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'actions_taken': 0,
            'start_time': None
        }
        
        # Event queues
        self.packet_queue = asyncio.Queue(maxsize=10000)
        self.analysis_queue = asyncio.Queue(maxsize=5000)
        self.decision_queue = asyncio.Queue(maxsize=5000)
        
        logger.info("QuantumShield Engine initialized")
    
    async def start(self):
        """Start the engine and all components"""
        if self.running:
            logger.warning("Engine already running")
            return
        
        logger.info("Starting QuantumShield Engine...")
        self.running = True
        self.stats['start_time'] = datetime.utcnow()
        
        # Load detection engines
        await self._load_detection_engines()
        
        # Load ML models
        if self.model_manager:
            await self.model_manager.initialize()
            
        # Initialize Adaptive Learner
        if self.adaptive_learner:
            await self.adaptive_learner.initialize()
        
        # Start components
        await self.packet_capture.start()
        await self.traffic_processor.start()
        await self.response_executor.start()
        await self.threat_manager.start()
        
        # Start processing pipelines
        tasks = [
            asyncio.create_task(self._packet_capture_loop()),
            asyncio.create_task(self._traffic_processing_loop()),
            asyncio.create_task(self._analysis_loop()),
            asyncio.create_task(self._decision_loop()),
            asyncio.create_task(self._monitoring_loop()),
            asyncio.create_task(self._cleanup_loop())
        ]
        # Keep track of tasks so we can cancel them quickly on shutdown
        self._tasks = tasks
        
        logger.info("QuantumShield Engine started successfully")
        
        # Wait for all tasks
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Engine tasks cancelled")
    
    async def stop(self):
        """Stop the engine gracefully"""
        if not self.running:
            return
        
        logger.info("Stopping QuantumShield Engine...")
        self.running = False

        # Cancel background tasks so they don't have to wait for long sleeps
        for task in list(self._tasks):
            if not task.done():
                task.cancel()
        if self._tasks:
            try:
                await asyncio.gather(*self._tasks, return_exceptions=True)
            except Exception:
                # We deliberately ignore task cancellation errors here
                pass

        # Stop components
        await self.packet_capture.stop()
        await self.traffic_processor.stop()
        await self.response_executor.stop()
        await self.threat_manager.stop()
        
        # Save state if needed
        await self._save_state()
        
        logger.info("QuantumShield Engine stopped")
    
    async def _packet_capture_loop(self):
        """Capture packets and queue for processing"""
        logger.info("Packet capture loop started")
        
        while self.running:
            try:
                # Capture packet batch (may be empty in stub implementation)
                packets = await self.packet_capture.capture_batch(batch_size=100)

                for packet in packets:
                    await self.packet_queue.put(packet)
                    self.stats['packets_processed'] += 1

                # Small delay to prevent CPU spinning when there is no traffic
                await asyncio.sleep(0.01)
                
            except Exception as e:
                logger.error(f"Error in packet capture loop: {e}", exc_info=True)
                await asyncio.sleep(1)
    
    async def _traffic_processing_loop(self):
        """Process captured packets"""
        logger.info("Traffic processing loop started")
        
        while self.running:
            try:
                # Get packet from queue
                packet = await asyncio.wait_for(
                    self.packet_queue.get(),
                    timeout=1.0
                )
                
                # Process packet using async processor wrapper
                result = await self.traffic_processor.process_packet(packet)
                if not result:
                    continue

                _packet_info, flow = result
                flow_data = {
                    'flow_id': flow.flow_id,
                    'src_ip': flow.src_ip,
                    'dst_ip': flow.dst_ip,
                    'src_port': flow.src_port,
                    'src_port': flow.src_port,
                    'dst_port': flow.dst_port,
                    'protocol': flow.protocol.name,
                    # We need payload for SQLi detection. In this simplified engine, 
                    # we assume the processor might have attached it or we grab from packet.
                    # Since we don't have direct access to original packet payload here easily without change,
                    # we will assume the flow object might store a snippet or we accept that SQLi only works if payload is passed.
                    # For this integration, we'll try to get it from the packet object we just processed if possible,
                    # but here we are in a different scope. 
                    # Let's check if the flow has a buffer or last payload.
                    'payload': getattr(flow, 'last_payload', b'') 
                }
                
                if flow_data:
                    await self.analysis_queue.put(flow_data)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in traffic processing: {e}", exc_info=True)
    
    async def _analysis_loop(self):
        """Run detection engines on processed traffic"""
        logger.info("Analysis loop started")
        
        while self.running:
            try:
                # Get flow data
                flow_data = await asyncio.wait_for(
                    self.analysis_queue.get(),
                    timeout=1.0
                )
                
                # Run detection engines in parallel
                indicators = await self._run_detection_engines(flow_data)
                
                # Check Threat Intelligence
                src_ip = flow_data.get('src_ip')
                if src_ip and self.threat_manager.is_malicious(src_ip):
                    from .decision_maker import ThreatLevel
                    indicators.append(ThreatIndicator(
                        name="TiMaliciousIP",
                        confidence=1.0,
                        severity=ThreatLevel.CRITICAL,
                        details=f"Source IP {src_ip} found in threat blocklists",
                        indicator_type="threat_intelligence"
                    ))

                # Run ML models (using ModelManager)
                if self.model_manager:
                    # Enrich packet data for ML
                    # For now, we try to extract payload from flow metadata if stored, or pass generic info
                    packet_data = {'payload': flow_data.get('payload', b'')} 
                    
                    ml_result = await self.model_manager.infer(
                        packet_data,
                        flow_data
                    )
                    
                    if ml_result:
                        from .decision_maker import ThreatLevel
                        indicators.append(ThreatIndicator(
                            name=f"ML:{ml_result.get('reason', 'anomaly')}",
                            confidence=ml_result.get('threat_score', 0.0),
                            severity=ThreatLevel.HIGH if ml_result.get('threat_score', 0) > 0.8 else ThreatLevel.MEDIUM,
                            details=str(ml_result),
                            indicator_type="ml_anomaly"
                        ))
                
                # Create context
                context = self._create_context(flow_data)
                
                # Queue for decision
                await self.decision_queue.put((context, indicators))
                
                if indicators:
                    self.stats['threats_detected'] += 1
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in analysis: {e}", exc_info=True)
    
    async def _decision_loop(self):
        """Make decisions and execute responses"""
        logger.info("Decision loop started")
        
        while self.running:
            try:
                # Get context and indicators
                context, indicators = await asyncio.wait_for(
                    self.decision_queue.get(),
                    timeout=1.0
                )
                
                # Make decision
                decision = await self.decision_maker.make_decision(
                    context, indicators
                )
                
                # Execute response
                await self.response_executor.execute(decision)
                self.stats['actions_taken'] += 1
                
                # Feedback loop for Adaptive Learning
                if self.adaptive_learner:
                    await self.adaptive_learner.process_decision(context, decision)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in decision loop: {e}", exc_info=True)
    
    async def _monitoring_loop(self):
        """Monitor system health and performance"""
        logger.info("Monitoring loop started")
        
        while self.running:
            try:
                # Log statistics every 60 seconds
                await asyncio.sleep(60)
                
                uptime = datetime.utcnow() - self.stats['start_time']
                pps = self.stats['packets_processed'] / uptime.total_seconds()
                
                logger.info(
                    f"Statistics - Packets: {self.stats['packets_processed']}, "
                    f"Threats: {self.stats['threats_detected']}, "
                    f"Actions: {self.stats['actions_taken']}, "
                    f"PPS: {pps:.2f}, "
                    f"Queue sizes: P={self.packet_queue.qsize()}, "
                    f"A={self.analysis_queue.qsize()}, "
                    f"D={self.decision_queue.qsize()}"
                )
                
            except Exception as e:
                logger.error(f"Error in monitoring: {e}", exc_info=True)
    
    async def _cleanup_loop(self):
        """Periodic cleanup tasks"""
        logger.info("Cleanup loop started")
        
        while self.running:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                
                # Cleanup decision cache
                await self.decision_maker.cleanup_cache()
                
                # Cleanup flow tracker (Handled by internal thread in TrafficProcessor)
                # await self.traffic_processor.cleanup_old_flows()
                
                logger.debug("Cleanup completed")
                
            except Exception as e:
                logger.error(f"Error in cleanup: {e}", exc_info=True)
    
    async def _load_detection_engines(self):
        """Load and initialize detection engines"""
        import sys
        sys.stderr.write("DEBUG: _load_detection_engines called\n")
        
        engines_config = self.config.get('detection_engines', {})
        
        # Import detection engines - Use relative imports assuming package context
        try:
            from ..detection_engines.signature_engine import SignatureEngine
            from ..detection_engines.anomaly_engine import AnomalyEngine
            from ..detection_engines.behavioral_engine import BehavioralEngine
            
            sys.stderr.write("DEBUG: Detection engines imported\n")
            
            if engines_config.get('signature', {}).get('enabled', True):
                self.detection_engines.append(
                    SignatureEngine(engines_config.get('signature', {}))
                )
            
            if engines_config.get('anomaly', {}).get('enabled', True):
                self.detection_engines.append(
                    AnomalyEngine(engines_config.get('anomaly', {}))
                )
            
            if engines_config.get('behavioral', {}).get('enabled', True):
                self.detection_engines.append(
                    BehavioralEngine(engines_config.get('behavioral', {}))
                )
            
            sys.stderr.write(f"DEBUG: Loaded {len(self.detection_engines)} detection engines\n")
            
        except Exception as e:
            sys.stderr.write(f"ERROR: Error loading detection engines: {e}\n")
            logger.error(f"Error loading detection engines: {e}", exc_info=True)
    
    async def _load_ml_models(self):
        """Load ML models"""
        logger.info("Loading ML models...")
        
        ml_config = self.config.get('ml_models', {})
        
        try:
            # In production, load actual models
            # For now, just placeholder
            self.ml_models = {
                'traffic_classifier': None,
                'anomaly_detector': None,
                'ddos_predictor': None
            }
            
            logger.info(f"Loaded {len(self.ml_models)} ML models")
            
        except Exception as e:
            logger.error(f"Error loading ML models: {e}", exc_info=True)
    
    async def _run_detection_engines(self, flow_data: Dict) -> List[ThreatIndicator]:
        """Run all detection engines on flow data"""
        indicators = []
        
        tasks = [
            engine.analyze(flow_data)
            for engine in self.detection_engines
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Detection engine error: {result}")
            elif result:
                indicators.extend(result)
        
        return indicators
    
    async def _run_ml_models(self, flow_data: Dict) -> List[ThreatIndicator]:
        """Run ML models on flow data"""
        indicators = []
        
        # ML model inference would go here
        # Placeholder for now
        
        return indicators
    
    def _create_context(self, flow_data: Dict) -> ThreatContext:
        """Create ThreatContext from flow data"""
        from .decision_maker import ThreatContext
        import time
        
        # Extract flow statistics if available
        stats = flow_data.get('statistics', {})
        
        return ThreatContext(
            source_ip=flow_data.get('src_ip', ''),
            destination_ip=flow_data.get('dst_ip', ''),
            source_port=flow_data.get('src_port', 0),
            destination_port=flow_data.get('dst_port', 0),
            protocol=flow_data.get('protocol', ''),
            flow_id=flow_data.get('flow_id', ''),
            metadata=flow_data,
            start_time=stats.get('start_time', time.time()),
            last_seen=stats.get('end_time', time.time()),
            packet_count=stats.get('packet_count', 0),
            byte_count=stats.get('byte_count', 0),
            ml_scores=flow_data.get('ml_scores', {}),
            reputation_scores=flow_data.get('reputation_scores', {})
        )
    
    def _setup_signal_handlers(self):
        """
        Legacy signal handler setup (no longer used).

        Signal handling is managed by the top-level runners like
        `full_run.py` to avoid conflicting handlers, especially on
        Windows. This method is kept only for backward compatibility.
        """
        pass
    
    async def _save_state(self):
        """Save engine state before shutdown"""
        logger.info("Saving engine state...")
        # Implementation would save statistics, cache, etc.
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        return {
            **self.stats,
            'uptime': (datetime.utcnow() - self.stats['start_time']).total_seconds()
            if self.stats['start_time'] else 0,
            'queue_sizes': {
                'packet': self.packet_queue.qsize(),
                'analysis': self.analysis_queue.qsize(),
                'decision': self.decision_queue.qsize()
            },
            'detection_engines': len(self.detection_engines),
            'ml_models': len(self.ml_models)
        }


async def main():
    """Main entry point"""
    # Load configuration
    config = {
        'capture': {'interface': 'eth0'},
        'processor': {},
        'decision': {},
        'response': {},
        'detection_engines': {
            'signature': {'enabled': True},
            'anomaly': {'enabled': True},
            'behavioral': {'enabled': True}
        }
    }
    
    # Create and start engine
    engine = QuantumShieldEngine(config)
    
    try:
        await engine.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        await engine.stop()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    asyncio.run(main())