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
from .traffic_processor import TrafficProcessor
from .decision_maker import DecisionMaker, ThreatContext, ThreatIndicator
from .response_executor import ResponseExecutor

logger = logging.getLogger(__name__)


class QuantumShieldEngine:
    """Main orchestration engine for QuantumShield IPS/Firewall"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.running = False
        self.components = {}
        
        # Initialize core components
        self.packet_capture = PacketCapture(config.get('capture', {}))
        self.traffic_processor = TrafficProcessor(config.get('processor', {}))
        self.decision_maker = DecisionMaker(config.get('decision', {}))
        self.response_executor = ResponseExecutor(config.get('response', {}))
        
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
        
        # Setup signal handlers
        self._setup_signal_handlers()
        
        # Load detection engines
        await self._load_detection_engines()
        
        # Load ML models
        await self._load_ml_models()
        
        # Start components
        await self.packet_capture.start()
        await self.response_executor.start()
        
        # Start processing pipelines
        tasks = [
            asyncio.create_task(self._packet_capture_loop()),
            asyncio.create_task(self._traffic_processing_loop()),
            asyncio.create_task(self._analysis_loop()),
            asyncio.create_task(self._decision_loop()),
            asyncio.create_task(self._monitoring_loop()),
            asyncio.create_task(self._cleanup_loop())
        ]
        
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
        
        # Stop components
        await self.packet_capture.stop()
        await self.response_executor.stop()
        
        # Save state if needed
        await self._save_state()
        
        logger.info("QuantumShield Engine stopped")
    
    async def _packet_capture_loop(self):
        """Capture packets and queue for processing"""
        logger.info("Packet capture loop started")
        
        while self.running:
            try:
                # Capture packet batch
                packets = await self.packet_capture.capture_batch(batch_size=100)
                
                for packet in packets:
                    await self.packet_queue.put(packet)
                    self.stats['packets_processed'] += 1
                
                # Small delay to prevent CPU spinning
                await asyncio.sleep(0.001)
                
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
                
                # Process packet
                flow_data = await self.traffic_processor.process_packet(packet)
                
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
                
                # Run ML models
                ml_indicators = await self._run_ml_models(flow_data)
                indicators.extend(ml_indicators)
                
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
                
                # Cleanup flow tracker
                await self.traffic_processor.cleanup_old_flows()
                
                logger.debug("Cleanup completed")
                
            except Exception as e:
                logger.error(f"Error in cleanup: {e}", exc_info=True)
    
    async def _load_detection_engines(self):
        """Load and initialize detection engines"""
        logger.info("Loading detection engines...")
        
        engines_config = self.config.get('detection_engines', {})
        
        # Import detection engines
        try:
            from ..detection_engines.signature_engine import SignatureEngine
            from ..detection_engines.anomaly_engine import AnomalyEngine
            from ..detection_engines.behavioral_engine import BehavioralEngine
            
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
            
            logger.info(f"Loaded {len(self.detection_engines)} detection engines")
            
        except Exception as e:
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
    
    def _create_context(self, flow_data: Dict) -> PacketContext:
        """Create PacketContext from flow data"""
        return PacketContext(
            src_ip=flow_data.get('src_ip', ''),
            dst_ip=flow_data.get('dst_ip', ''),
            src_port=flow_data.get('src_port', 0),
            dst_port=flow_data.get('dst_port', 0),
            protocol=flow_data.get('protocol', ''),
            payload_size=flow_data.get('payload_size', 0),
            flow_id=flow_data.get('flow_id', ''),
            timestamp=datetime.utcnow(),
            metadata=flow_data
        )
    
    def _setup_signal_handlers(self):
        """Setup graceful shutdown handlers"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating shutdown...")
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
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