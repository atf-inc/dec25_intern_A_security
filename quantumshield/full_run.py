#!/usr/bin/env python3
"""
QuantumShield Full Run Script
Starts the complete firewall with adaptive learning enabled
"""

import asyncio
import sys
import signal
import logging
from pathlib import Path

# Add parent directory to path for imports
_current_dir = Path(__file__).parent
_parent_dir = _current_dir.parent
if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))
if str(_current_dir) not in sys.path:
    sys.path.insert(0, str(_current_dir))

from quantumshield.core.engine import QuantumShieldEngine
from quantumshield.config.logging_config import setup_logging, get_logger
from quantumshield.api.rest_api import app as api_app
import uvicorn

logger = get_logger(__name__)


def create_config():
    """Create configuration for QuantumShield"""
    return {
        'capture': {
            'interface': None,  # Set to None for Windows, or 'eth0' for Linux
            'enabled': False  # Disable actual packet capture for testing
        },
        'processor': {
            'max_flows': 10000,
            'flow_timeout': 300,
            'cleanup_interval': 60
        },
        'decision': {
            'confidence_threshold': 0.7,
            'enable_ml_scores': True,
            'enable_reputation': True
        },
        'response': {
            'enable_blocking': True,
            'enable_rate_limiting': True,
            'enable_alerts': True
        },
        'detection_engines': {
            'signature': {'enabled': True},
            'anomaly': {'enabled': True},
            'behavioral': {'enabled': True},
            'protocol': {'enabled': True}
        },
        'ml_models': {
            'traffic_classifier': {'enabled': True},
            'anomaly_detector': {'enabled': True},
            'ddos_predictor': {'enabled': True}
        },
        'adaptive_learning': {
            'training_mode': True,
            'learning_enabled': True,
            'rl_agent': {
                'learning_rate': 0.001,
                'gamma': 0.95,
                'epsilon_start': 1.0,
                'epsilon_min': 0.01,
                'epsilon_decay': 0.995,
                'batch_size': 32,
                'memory_size': 10000,
                'prioritized_replay': True
            },
            'pattern_learner': {
                'similarity_threshold': 0.7,
                'min_pattern_count': 3,
                'storage_path': 'adaptive_learning/patterns'
            },
            'policy_updater': {
                'min_confidence': 0.7,
                'min_pattern_count': 5,
                'update_interval': 3600
            },
            'storage_path': 'adaptive_learning'
        },
        'api': {
            'enabled': True,
            'host': '0.0.0.0',
            'port': 8081
        },
        'waf': {
            'enabled': True
        }
    }


async def start_engine_with_adaptive_learning(engine: QuantumShieldEngine, config: dict):
    """Start engine with adaptive learning integrated"""
    # Try to import and initialize adaptive learner; fall back gracefully if unavailable
    try:
        from quantumshield.adaptive_learning import AdaptiveLearner  # type: ignore
    except Exception as e:  # pragma: no cover - defensive import guard
        logger.warning(
            "Adaptive Learning module could not be loaded; "
            "continuing without adaptive learning. Error: %s",
            e,
        )
        engine.adaptive_learner = None
        return

    logger.info("Initializing Adaptive Learning module...")
    adaptive_learner = AdaptiveLearner(
        engine.decision_maker,
        config.get('adaptive_learning', {})
    )
    await adaptive_learner.initialize()

    # Attach adaptive learner to engine
    engine.adaptive_learner = adaptive_learner
    
    # Monkey patch decision loop to integrate adaptive learning
    original_decision_loop = engine._decision_loop
    
    async def enhanced_decision_loop():
        """Enhanced decision loop with adaptive learning"""
        logger.info("Enhanced decision loop with adaptive learning started")
        
        while engine.running:
            try:
                # Get context and indicators from decision queue
                context, indicators = await asyncio.wait_for(
                    engine.decision_queue.get(),
                    timeout=1.0
                )
                
                # Get RL suggestion (optional, can be used to influence decision)
                suggestion = None
                if engine.adaptive_learner and engine.adaptive_learner.learning_enabled:
                    try:
                        suggestion = await engine.adaptive_learner.suggest_action(context)
                        if suggestion:
                            logger.debug(f"RL Suggestion: {suggestion.get('action')}, "
                                       f"Confidence: {suggestion.get('confidence', 0):.3f}")
                    except Exception as e:
                        logger.warning(f"Failed to get RL suggestion: {e}")
                
                # Make decision
                decision = await engine.decision_maker.make_decision(context, indicators)
                
                # Execute response
                await engine.response_executor.execute(decision)
                engine.stats['actions_taken'] += 1
                
                # Learn from decision (simulate outcome for now)
                if engine.adaptive_learner and engine.adaptive_learner.learning_enabled:
                    from quantumshield.core.decision_maker import ActionType
                    outcome = {
                        'attack_prevented': decision.action in [
                            ActionType.BLOCK_PERMANENT, 
                            ActionType.BLOCK_TEMPORARY, 
                            ActionType.QUARANTINE
                        ],
                        'false_positive': False,
                        'response_time': 0.1
                    }
                    try:
                        await engine.adaptive_learner.process_decision(context, decision, outcome)
                    except Exception as e:
                        logger.warning(f"Failed to process decision for learning: {e}")
                    
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in decision loop: {e}", exc_info=True)
                await asyncio.sleep(1)
    
    # Replace decision loop
    engine._decision_loop = enhanced_decision_loop
    
    logger.info("Adaptive learning integrated with engine")


async def run_engine(engine: QuantumShieldEngine):
    """Run the engine"""
    try:
        await engine.start()
    except KeyboardInterrupt:
        logger.info("Shutdown signal received")
        await engine.stop()
    except Exception as e:
        logger.error(f"Engine error: {e}", exc_info=True)
        await engine.stop()


def start_api_server(config: dict):
    """Start REST API server"""
    api_config = config.get('api', {})
    if not api_config.get('enabled', False):
        return None
    
    def run_api():
        import socket
        host = api_config.get('host', '0.0.0.0')
        port = api_config.get('port', 8000)
        
        # Check if port is available
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((host, port))
            sock.close()
        except OSError as e:
            if e.errno == 10048 or e.errno == 98:  # Windows: 10048, Linux: 98
                logger.error(f"Port {port} is already in use. Please stop the other process or change the port in config.")
                logger.error(f"To find the process using port {port}:")
                logger.error(f"  Windows: netstat -ano | findstr :{port}")
                logger.error(f"  Linux/Mac: lsof -i :{port}")
                return None
            else:
                raise
        
        try:
            uvicorn.run(
                api_app,
                host=host,
                port=port,
                log_level="info"
            )
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")
            raise
    
    return run_api


async def main():
    """Main entry point"""
    # Setup logging
    setup_logging("INFO")
    
    logger.info("=" * 60)
    logger.info("QuantumShield - Starting Full Firewall")
    logger.info("=" * 60)
    
    # Create configuration
    config = create_config()
    
    # Create engine
    logger.info("Initializing QuantumShield Engine...")
    engine = QuantumShieldEngine(config)
    
    # Integrate adaptive learning
    await start_engine_with_adaptive_learning(engine, config)
    
    # Start API server if enabled
    api_server = start_api_server(config)
    if api_server:
        # Inject engine into app state and global reference so API endpoints can use it
        from quantumshield.api.rest_api import set_engine
        api_app.state.engine = engine
        set_engine(engine)  # Also set global reference for thread safety
        
        import threading
        api_thread = threading.Thread(target=api_server, daemon=True)
        api_thread.start()
        logger.info(f"API server started on {config['api']['host']}:{config['api']['port']}")
    
    # Start Reverse Proxy
    from quantumshield.proxy.reverse_proxy import ReverseProxy
    from quantumshield.config.settings import get_settings
    settings = get_settings()
    
    proxy = ReverseProxy(engine, target_url=settings.proxy_target)
    logger.info(f"Starting Reverse Proxy on port {settings.proxy_port}...")
    
    # Run proxy in the event loop (it's async)
    # Since we are already in an async main(), we can create a task for it
    proxy_task = asyncio.create_task(proxy.start(port=settings.proxy_port))
    engine.proxy = proxy # Attach to engine for later cleanup
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        logger.info("\nShutdown signal received...")
        asyncio.create_task(engine.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("QuantumShield is running...")
    logger.info("Press Ctrl+C to stop")
    
    # Run engine
    await run_engine(engine)
    
    # Shutdown adaptive learner
    if hasattr(engine, 'adaptive_learner') and engine.adaptive_learner:
        await engine.adaptive_learner.shutdown()
        
    # Shutdown proxy
    if hasattr(engine, 'proxy') and engine.proxy:
        await engine.proxy.stop()
    
    logger.info("QuantumShield stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

