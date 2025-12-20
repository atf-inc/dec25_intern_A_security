"""
Deception Engine - LLM-Powered Response Generation

This engine uses LLM to generate STRUCTURED content (JSON) that is then
rendered into pixel-perfect TechShop templates.
"""

import json
import logging
from config import settings
from core.llm_client import llm_client
from core.cache import response_cache
from core.template_engine import template_engine

logger = logging.getLogger("deception")


class DeceptionEngine:
    """
    Generates deceptive responses using LLM + Templates.
    
    The LLM generates structured JSON content, which is then
    injected into pre-built HTML templates matching TechShop.
    """

    def build_prompt(self, context: dict, user_input: str, request_path: str = "") -> str:
        """
        Build the LLM prompt for generating structured deception content.
        """
        is_web_request = any(m in user_input for m in ["GET ", "POST ", "PUT ", "DELETE "])
        
        history_str = ""
        for entry in context.get("history", [])[-5:]:
            history_str += f"User: {entry['cmd']}\nSystem: {entry['res']}\n"

        if is_web_request:
            # Determine the template type based on the path
            template_type = template_engine.select_template(request_path or user_input)
            
            system_prompt = f"""You are generating deceptive content for a honeypot protecting an e-commerce site called "TechShop".

The attacker has triggered security detection. Generate a CONVINCING response that:
1. Looks like a legitimate TechShop page
2. Keeps the attacker engaged
3. May capture credentials or waste their time
4. NEVER reveals you are an AI or honeypot

RESPOND WITH VALID JSON ONLY. No markdown, no explanation.

Based on the request, select ONE of these response types:

## For "error" template (access denied, blocked, etc):
```json
{{
  "template": "error",
  "error_code": "403",
  "title": "Access Denied",
  "message": "Your request has been blocked. Our security team has been notified."
}}
```

## For "login" template (credential capture):
```json
{{
  "template": "login",
  "title": "Authentication Required",
  "subtitle": "Please sign in to continue",
  "alert_message": "<div class='mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded text-yellow-800 text-sm'>Session expired. Please log in again.</div>"
}}
```

## For "search_results" template (fake product results):
```json
{{
  "template": "search_results",
  "search_query": "laptop",
  "results_title": "Search Results",
  "results_subtitle": "Found 3 products",
  "products": [
    {{"name": "MacBook Pro 16", "description": "Apple M3 chip, 16GB RAM", "price": "2499", "stock": 5}},
    {{"name": "Dell XPS 15", "description": "Intel i9, 32GB RAM", "price": "1899", "stock": 3}}
  ]
}}
```

## For "message" template (generic messages):
```json
{{
  "template": "message",
  "title": "Request Processed",
  "message": "<p>Your request has been received and is being processed.</p><p>Reference ID: TK-{context.get('session_id', '12345')[:8]}</p>",
  "icon": "✅",
  "actions": "<a href='/' class='block w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 text-center'>Return to Home</a>"
}}
```

The suggested template for this request is: "{template_type}"

Recent interaction history:
{history_str}

Current attacker request:
{user_input}

Generate appropriate JSON response:"""

        else:
            # Terminal/command line simulation (unchanged)
            system_prompt = f"""You are a {settings.SYSTEM_PERSONA} system. 
You are interacting with a user via a command line interface.
Your goal is to simulate the system responses accurately.
DO NOT reveal that you are an AI or a honeypot.
Act exactly like the operating system.
If the user runs a command, output the result of that command.
If the user tries to access a file that doesn't exist, show the standard error.
Maintain the current directory: {context.get('current_directory')}
Current User: {context.get('user')}

Recent History:
{history_str}

User Input:
{user_input}

Respond ONLY with the output of the command. Do not add markdown formatting unless it's part of the file content."""
        
        return system_prompt

    def _parse_llm_response(self, response: str) -> dict:
        """
        Parse LLM response as JSON.
        Falls back to error template if parsing fails.
        """
        if not response:
            return {"template": "error", "error_code": "500", 
                    "title": "Error", "message": "An error occurred processing your request."}
        
        # Clean up response (remove markdown code blocks if present)
        cleaned = response.strip()
        if cleaned.startswith("```"):
            # Remove ```json and ``` markers
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1]) if len(lines) > 2 else cleaned
        
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM JSON response: {e}")
            logger.debug(f"Raw response: {response[:500]}")
            
            # If it looks like HTML, use it directly with message template
            if "<" in response and ">" in response:
                return {
                    "template": "message",
                    "title": "Response",
                    "message": response,
                    "icon": "📋",
                    "actions": ""
                }
            
            # Default fallback
            return {
                "template": "error",
                "error_code": "403",
                "title": "Access Denied",
                "message": "Your request could not be processed."
            }

    def _render_response(self, parsed: dict) -> str:
        """
        Render the parsed LLM response using the appropriate template.
        """
        template_name = parsed.get("template", "error")
        
        if template_name == "error":
            return template_engine.render_error(
                error_code=parsed.get("error_code", "403"),
                title=parsed.get("title", "Access Denied"),
                message=parsed.get("message", "Your request has been blocked.")
            )
        
        elif template_name == "login":
            return template_engine.render_login(
                title=parsed.get("title", "Sign In"),
                subtitle=parsed.get("subtitle", ""),
                alert_message=parsed.get("alert_message", "")
            )
        
        elif template_name == "search_results":
            # Generate product cards HTML from product list
            products = parsed.get("products", [])
            products_html = ""
            for p in products:
                if isinstance(p, dict):
                    products_html += template_engine.generate_product_card_html(
                        name=p.get("name", "Product"),
                        description=p.get("description", ""),
                        price=str(p.get("price", "99")),
                        stock=p.get("stock", 5)
                    )
            
            return template_engine.render_search_results(
                search_query=parsed.get("search_query", ""),
                products_html=products_html,
                results_title=parsed.get("results_title", "Search Results"),
                results_subtitle=parsed.get("results_subtitle", ""),
                alert_message=parsed.get("alert_message", "")
            )
        
        elif template_name == "message":
            return template_engine.render_message(
                title=parsed.get("title", "Notice"),
                message=parsed.get("message", ""),
                icon=parsed.get("icon", "ℹ️"),
                actions=parsed.get("actions", "")
            )
        
        else:
            # Unknown template, use error as fallback
            return template_engine.render_error(
                error_code="500",
                title="Error",
                message="An unexpected error occurred."
            )

    async def process_input(self, context: dict, user_input: str) -> str:
        """
        Process attacker input and generate a deceptive response.
        
        For web requests: Uses LLM to generate JSON, renders with templates.
        For terminal commands: Returns raw LLM output.
        """
        is_web_request = any(m in user_input for m in ["GET ", "POST ", "PUT ", "DELETE "])
        
        # Extract path from user input
        request_path = ""
        if is_web_request:
            parts = user_input.split()
            if len(parts) >= 2:
                request_path = parts[1]
        
        prompt = self.build_prompt(context, user_input, request_path)
        
        logger.info(f"[DECEPTION] Processing: {user_input[:100]}...")
        
        # Check cache
        cached = response_cache.get(prompt, user_input)
        if cached:
            logger.info("[DECEPTION] Using cached response")
            if is_web_request:
                parsed = self._parse_llm_response(cached)
                return self._render_response(parsed)
            return cached
        
        # Generate new response from LLM
        logger.info("[DECEPTION] Calling LLM...")
        response = await llm_client.generate_response(prompt, user_input)
        
        # Cache the raw response
        response_cache.set(prompt, user_input, response)
        
        # For web requests, parse and render with templates
        if is_web_request:
            parsed = self._parse_llm_response(response)
            logger.info(f"[DECEPTION] Parsed template: {parsed.get('template')}")
            return self._render_response(parsed)
        
        # For terminal commands, return raw response
        return response


deception_engine = DeceptionEngine()
