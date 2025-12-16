import sys
import os
import asyncio
import logging
import yaml
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("quantumshield_run.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("QuantumShieldRunner")

def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file or use defaults."""
    config_file = Path(config_path)
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from {config_path}")
                return config
        except Exception as e:
            logger.warning(f"Failed to load config file: {e}. Using defaults.")
    
    # Default configuration
    return {
        'capture': {
            'interface': 'eth0',
            'enabled': True
        },
        'processor': {'enabled': True},
        'decision': {'enabled': True, 'auto_block': True},
        'response': {'enabled': True, 'block_ip': True},
        'detection_engines': {
            'signature': {'enabled': True},
            'anomaly': {'enabled': True},
            'behavioral': {'enabled': True}
        },
        'integrations': {
            'enabled': False  # Explicitly disable external tools
        },
        'waf': {
            'enabled': True,
            'block_on_violation': True
        },
        'ml_models': {
            'enabled': True
        },
        'network_layer': {
            'ddos_detection': True
        },
        'quantum_llma': {
            'enabled': True
        },
        'proxy': {
            'enabled': True,
            'port': 8080,
            'backend_url': 'http://localhost:3000'
        }
    }

def main():
    """
    Full run script for QuantumShield.
    """
    logger.info("=" * 60)
    logger.info("QuantumShield IPS/Firewall - Starting...")
    logger.info("=" * 60)
    
    # 1. Ensure project root is in python path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
        
    try:
        from quantumshield.core.engine import QuantumShieldEngine
    except ImportError as e:
        logger.error(f"Failed to import QuantumShieldEngine: {e}")
        logger.error("Make sure you are running this script from the 'AITF_IPS' folder.")
        logger.error("Also ensure all dependencies are installed: pip install -r requirements.txt")
        return

    # 2. Load Configuration
    config = load_config()

    logger.info("Configuration loaded.")
    if not config.get('integrations', {}).get('enabled', False):
        logger.info("[OK] Integrations layer DISABLED (as requested)")

    # 3. Initialize Engine
    logger.info("Initializing QuantumShield Engine...")
    try:
        engine = QuantumShieldEngine(config)
        logger.info("[OK] Engine initialized successfully")
    except Exception as e:
        logger.critical(f"[FAIL] Engine initialization failed: {e}", exc_info=True)
        return

    # 4. Initialize Proxy (if enabled)
    proxy = None
    if config.get('proxy', {}).get('enabled', True):
        try:
            from quantumshield.proxy.reverse_proxy import ReverseProxy
            backend_url = config.get('proxy', {}).get('backend_url', 'http://localhost:3000')
            port = config.get('proxy', {}).get('port', 8080)
            proxy = ReverseProxy(backend_url=backend_url, port=port, engine=engine)
            logger.info(f"[OK] Proxy initialized: http://localhost:{port} -> {backend_url}")
        except Exception as e:
            logger.error(f"[FAIL] Proxy init failed: {e}", exc_info=True)
            logger.warning("Continuing without proxy...")

    # 5. Run Engine & Proxy
    logger.info("=" * 60)
    logger.info("Starting QuantumShield System...")
    logger.info("=" * 60)
    
    async def run_system():
        """Run the complete system."""
        try:
            # Start Engine
            engine_task = asyncio.create_task(engine.start())
            logger.info("[OK] Engine started")
            
            # Start Proxy
            if proxy:
                proxy_task = asyncio.create_task(proxy.start())
                logger.info("[OK] Proxy started")
            
            logger.info("")
            logger.info("=" * 60)
            logger.info("SYSTEM RUNNING - All components active")
            logger.info("=" * 60)
            logger.info("")
            logger.info("Firewall Status:")
            logger.info(f"  • Engine: Active")
            if proxy:
                logger.info(f"  • Proxy: http://localhost:{config.get('proxy', {}).get('port', 8080)}")
                logger.info(f"  • Backend: {config.get('proxy', {}).get('backend_url', 'http://localhost:3000')}")
            logger.info(f"  • WAF: {'Enabled' if config.get('waf', {}).get('enabled', True) else 'Disabled'}")
            logger.info(f"  • Detection Engines: {len(engine.detection_engines)} loaded")
            logger.info(f"  • ML Models: {'Enabled' if config.get('ml_models', {}).get('enabled', True) else 'Disabled'}")
            logger.info("")
            logger.info("Press Ctrl+C to stop...")
            logger.info("")
            
            # Wait for tasks
            tasks = [engine_task]
            if proxy:
                tasks.append(proxy_task)
            
            await asyncio.gather(*tasks)
            
        except asyncio.CancelledError:
            logger.info("Tasks cancelled")
        except Exception as e:
            logger.error(f"Runtime error: {e}", exc_info=True)
        finally:
            # Cleanup
            logger.info("Shutting down...")
            if proxy:
                await proxy.stop()
            await engine.stop()
            logger.info("Shutdown complete")
    
    try:
        asyncio.run(run_system())
    except KeyboardInterrupt:
        logger.info("")
        logger.info("Shutdown signal received (Ctrl+C)")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)

if __name__ == "__main__":
    main()
