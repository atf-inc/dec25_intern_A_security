
import asyncio
import aiohttp
from aiohttp import web
import logging
import time
import json
from json import JSONDecodeError
from typing import Optional

from quantumshield.core.engine import QuantumShieldEngine
from quantumshield.core.decision_maker import ActionType, ThreatContext, ThreatIndicator, ThreatLevel
from quantumshield.config.settings import get_settings

logger = logging.getLogger(__name__)

class ReverseProxy:
    """
    QuantumShield Reverse Proxy.
    Intercepts traffic, analyzes it using the engine, and forwards valid requests to the backend.
    """

    def __init__(self, engine: QuantumShieldEngine, target_url: str = "http://localhost:3000"):
        self.engine = engine
        self.target_url = target_url.rstrip('/')
        self.app = web.Application()
        # Catch-all route for proxying
        self.app.router.add_route('*', '/{path_info:.*}', self.handle_request)
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        
    async def start(self, host: str = "0.0.0.0", port: int = 8000):
        """Start the proxy server."""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, host, port)
        await self.site.start()
        logger.info(f"Reverse Proxy started on http://{host}:{port} -> {self.target_url}")

    async def stop(self):
        """Stop the proxy server."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        logger.info("Reverse Proxy stopped")

    async def handle_request(self, request: web.Request) -> web.Response:
        """Handle incoming requests."""
        try:
            path = request.match_info['path_info']
            full_path = f"/{path}"
            if request.query_string:
                full_path += f"?{request.query_string}"
                
            # 1. Extract context for analysis
            client_ip = request.remote 
            # In a real deployment, would parse X-Forwarded-For if behind another LB
            
            context = ThreatContext(
                source_ip=client_ip,
                destination_ip="127.0.0.1", # Self
                source_port=0, # ephemeral
                destination_port=8000,
                protocol="HTTP",
                byte_count=request.content_length or 0,
                packet_count=1
            )
            
            # 2. Extract initial indicators (Basic WAF check simulation)
            indicators = []
            
            # Use WAF engine explicitly if available (it is part of engine)
            if hasattr(self.engine, 'waf_engine'):
                pass

            # 3. Analyze
            indicators.append(ThreatIndicator(
                name="HTTP Request",
                confidence=0.5, # Neutral start
                severity=ThreatLevel.LOW,
                source="ReverseProxy"
            ))
            
            blocked = False
            decision = None
            violations = []  # Store violations for later use
            body_text = ""
            body_bytes = None
            
            # Read body once (can only be read once in aiohttp)
            try:
                if request.can_read_body:
                    body_bytes = await request.read()
                    body_text = body_bytes.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Error reading body: {e}")
            
            # Skip WAF analysis for internal WAF API requests
            if self.engine.waf_engine and not full_path.startswith('/api/waf/'):
                logger.info(f"[ReverseProxy] Analyzing request: {request.method} {full_path}")
                
                # Extract query parameters
                query_params = {}
                if request.query_string:
                    from urllib.parse import parse_qs
                    parsed_qs = parse_qs(request.query_string)
                    query_params = {k: v[0] if len(v) == 1 else v for k, v in parsed_qs.items()}
                    logger.debug(f"[ReverseProxy] Query params: {query_params}")
                
                # Extract body parameters (if JSON or form data)
                body_params = {}
                if body_text:
                    try:
                        # Try JSON first
                        body_params = json.loads(body_text)
                        logger.debug(f"[ReverseProxy] Body params (JSON): {body_params}")
                    except (JSONDecodeError, ValueError, TypeError):
                        # JSON decode failed, try URL-encoded form data
                        try:
                            from urllib.parse import parse_qs
                            parsed_body = parse_qs(body_text)
                            body_params = {k: v[0] if len(v) == 1 else v for k, v in parsed_body.items()}
                            logger.debug(f"[ReverseProxy] Body params (form): {body_params}")
                        except Exception:
                            # Raw body
                            body_params = {"_raw": body_text}
                            logger.debug(f"[ReverseProxy] Body params (raw): {len(body_text)} chars")
                
                # Combine all parameters
                all_params = {**query_params, **body_params}
                
                # Get detailed violations - pass all parameters
                violations = self.engine.waf_engine.process_request(
                    request.method,
                    full_path,
                    dict(request.headers),
                    body_text,
                    query_params=query_params,
                    body_params=body_params,
                    all_params=all_params
                )
                
                if violations:
                    logger.warning(f"[ReverseProxy] WAF BLOCKED {full_path}: {len(violations)} violation(s)")
                    for v in violations:
                        logger.warning(f"[ReverseProxy]   - {v.get('type')}: {v.get('reason')}")
                else:
                    logger.info(f"[ReverseProxy] WAF ALLOWED {full_path}")
                
                if violations:
                     indicators.append(ThreatIndicator(
                         name="WAF Detection",
                         confidence=1.0,
                         severity=ThreatLevel.CRITICAL,
                         source="WAF",
                         indicator_type=violations[0].get('type', 'waf_detection')
                     ))

            # Get Decision
            decision = await self.engine.decision_maker.make_decision(context, indicators)
            reason = f"ThreatLevel: {decision.threat_level.name}, Indicators: {[i.name for i in decision.indicators]}"
            logger.info(f"Decision for {full_path}: {decision.action} ({reason})")
            
            # 4. Enforce
            # 4. Enforce
            # Note: We do NOT block here anymore. We redirect to Honeypot in step 5.
            # Only block if strictly necessary (e.g. DDOS volume), but for this integration we want deception.
            if decision.action in [ActionType.BLOCK_PERMANENT, ActionType.BLOCK_TEMPORARY, ActionType.QUARANTINE]:
                 logger.info(f"Verdict is BLOCK/QUARANTINE. Will redirect to Honeypot.")

            # 5. Forward (Proxy)
            # Determine target based on path and decision
            target_base = self.engine.settings.dvwa_url # Default to Safe App

            # A. WAF API - Internal
            if full_path.startswith('/api/waf/'):
                target_base = "http://localhost:8081"
            
            # B. Analytics/Stats - Route to Honeypot Analytics API
            elif full_path.startswith('/api/analytics') or full_path.startswith('/api/stats'):
                target_base = self.engine.settings.honeypot_url
            
            # C. Malicious/Suspicious - Route to Honeypot
            elif decision.action in [ActionType.BLOCK_PERMANENT, ActionType.BLOCK_TEMPORARY, ActionType.QUARANTINE]:
                logger.warning(f"Redirecting ATTACK from {client_ip} to Honeypot at {self.engine.settings.honeypot_url}")
                target_base = self.engine.settings.honeypot_url
                # We are allowing the request to proceed to the honeypot, effectively "unblocking" it from a network perspective
                # but "blocking" it from the real app.
            
            target = f"{target_base}{full_path}"
            
            try:
                # Create client session for forwarding
                async with aiohttp.ClientSession() as session:
                    # Use the body we read earlier, or None if no body
                    data_to_send = body_bytes if body_bytes else None
                    
                    # Exclude hop-by-hop headers
                    headers = {k: v for k, v in request.headers.items() if k.lower() not in ['host', 'content-length']} 
                    
                    # Add Security Headers for Honeypot Context
                    if target_base == self.engine.settings.honeypot_url:
                        headers['X-WAF-Verdict'] = "MALICIOUS" if decision.action != ActionType.ALLOW else "SUSPICIOUS"
                        headers['X-WAF-Confidence'] = str(indicators[0].confidence if indicators else 0.5)
                        headers['X-Attacker-IP'] = client_ip
                    
                    async with session.request(
                        request.method,
                        target,
                        headers=headers,
                        data=data_to_send,
                        allow_redirects=False # Proxy redirects back to client
                    ) as backend_response:
                        
                        # Read backend response
                        response_body = await backend_response.read()
                        
                        # Create response to client
                        proxy_response = web.Response(
                            status=backend_response.status,
                            body=response_body,
                            headers={k: v for k, v in backend_response.headers.items() if k.lower() not in ['transfer-encoding', 'content-encoding']}
                        )
                        return proxy_response
                        
            except Exception as e:
                logger.error(f"Upstream error: {e}")
                return web.Response(status=502, text="Bad Gateway")

        except Exception as e:
            import traceback
            logger.error(f"Internal Proxy Error: {e}", exc_info=True)
            return web.Response(status=500, text=f"Internal Proxy Error: {e}\n{traceback.format_exc()}")
