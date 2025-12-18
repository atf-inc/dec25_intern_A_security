"""
Response Executor
Executes decisions made by the DecisionMaker.
"""
import logging
import asyncio
from typing import Dict, Any

try:
    from ..response_system.blocking_engine import BlockingEngine
    from ..response_system.rate_limiter import RateLimiter
except (ImportError, ValueError):
    try:
        from response_system.blocking_engine import BlockingEngine
        from response_system.rate_limiter import RateLimiter
    except ImportError:
        # Handle relative imports if needed during testing or different run contexts
        import sys
        import os
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
        from response_system.blocking_engine import BlockingEngine
        from response_system.rate_limiter import RateLimiter

from .decision_maker import Decision, ActionType

logger = logging.getLogger(__name__)

class ResponseExecutor:
    """Executes responses based on decisions."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.blocking_engine = BlockingEngine()
        self.rate_limiter = RateLimiter()
        self.running = False

    async def start(self):
        """Start the response executor."""
        self.running = True
        logger.info("Response Executor started")

    async def stop(self):
        """Stop the response executor."""
        self.running = False
        logger.info("Response Executor stopped")

    async def execute(self, decision: Decision):
        """
        Execute a decision.
        
        Args:
            decision: Decision object containing action, context, etc.
        """
        action = decision.action
        context = decision.context
        src_ip = context.source_ip
        
        if not action:
            logger.warning("Received decision with no action")
            return

        if action in [ActionType.BLOCK_PERMANENT, ActionType.BLOCK_TEMPORARY]:
            if src_ip:
                self.blocking_engine.block_ip(src_ip)
                logger.warning(f"EXECUTED BLOCK: Source IP {src_ip} blocked based on decision.", 
                               extra={"decision": decision})
            else:
                logger.error("Cannot execute BLOCK action: No source IP in context")

        elif action == ActionType.RATE_LIMIT:
            # Note: Rate limiting is usually applied earlier in the pipeline, 
            # but we can enforce strict blocking here if rate limit triggered a decision
            if src_ip:
                logger.info(f"Rate limit enforcement triggered for {src_ip}")
                # For now, we might just log, or block temporarily
                 
        elif action == ActionType.LOG:
            logger.info(f"Traffic logged: {src_ip} -> {context.destination_ip}",
                        extra={"decision": decision})

        elif action == ActionType.ALLOW:
            # No specific action needed for allow, traffic proceeds
            pass
            
        else:
            logger.warning(f"Unknown action: {action}")
