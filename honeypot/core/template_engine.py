"""
Template Engine for Honeypot Responses

Renders pre-built HTML templates with dynamic content from the LLM.
This creates pixel-perfect fake pages that match the real TechShop site.
"""

import os
import re
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("template_engine")

# Path to templates directory
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


class TemplateEngine:
    """
    Simple template engine that replaces {{placeholders}} with values.
    """

    def __init__(self):
        self.templates_dir = TEMPLATES_DIR
        self._cache: Dict[str, str] = {}

    def _load_template(self, template_name: str) -> str:
        """Load a template file from disk (with caching)."""
        if template_name in self._cache:
            return self._cache[template_name]

        template_path = os.path.join(self.templates_dir, f"{template_name}.html")
        
        if not os.path.exists(template_path):
            logger.error(f"Template not found: {template_path}")
            return self._get_fallback_template()

        with open(template_path, "r", encoding="utf-8") as f:
            template = f.read()

        self._cache[template_name] = template
        return template

    def _get_fallback_template(self) -> str:
        """Return a minimal fallback template if the requested one is missing."""
        return """
        <!DOCTYPE html>
        <html>
        <head><title>TechShop</title></head>
        <body style="font-family: Arial; padding: 50px; text-align: center;">
            <h1>{{title}}</h1>
            <p>{{message}}</p>
        </body>
        </html>
        """

    def render(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        Render a template with the given context.
        
        Args:
            template_name: Name of the template (without .html extension)
            context: Dictionary of values to inject into the template
            
        Returns:
            Rendered HTML string
        """
        template = self._load_template(template_name)
        
        # Replace all {{placeholder}} with context values
        def replace_placeholder(match):
            key = match.group(1).strip()
            value = context.get(key, "")
            # Convert non-string values
            if isinstance(value, (list, dict)):
                return str(value)
            return str(value) if value else ""

        rendered = re.sub(r"\{\{(\w+)\}\}", replace_placeholder, template)
        
        return rendered

    def render_error(self, error_code: str, title: str, message: str) -> str:
        """Convenience method for rendering error pages."""
        return self.render("error", {
            "error_code": error_code,
            "title": title,
            "message": message
        })

    def render_login(self, title: str = "Sign in to your account", 
                     subtitle: str = "", alert_message: str = "") -> str:
        """Convenience method for rendering login pages."""
        return self.render("login", {
            "title": title,
            "subtitle": subtitle,
            "alert_message": alert_message
        })

    def render_search_results(self, search_query: str, products_html: str,
                              results_title: str = "Search Results",
                              results_subtitle: str = "",
                              alert_message: str = "",
                              pagination: str = "") -> str:
        """Convenience method for rendering search results."""
        return self.render("search_results", {
            "search_query": search_query,
            "products": products_html,
            "results_title": results_title,
            "results_subtitle": results_subtitle,
            "alert_message": alert_message,
            "pagination": pagination
        })

    def render_message(self, title: str, message: str, icon: str = "ℹ️",
                       actions: str = "") -> str:
        """Convenience method for rendering generic message pages."""
        return self.render("message", {
            "title": title,
            "message": message,
            "icon": icon,
            "actions": actions
        })

    def select_template(self, request_path: str, attack_type: str = None) -> str:
        """
        Select the appropriate template based on the request context.
        
        Args:
            request_path: The URL path that was attacked
            attack_type: Type of attack detected (sql_injection, xss, etc.)
            
        Returns:
            Template name to use
        """
        path_lower = request_path.lower()
        
        # Homepage / root
        if path_lower in ["/", "get /", "post /", "get /?", ""]:
            return "home"
        
        # Login-related paths
        if any(p in path_lower for p in ["/login", "/signin", "/auth", "/admin"]):
            return "login"
        
        # Products/search-related paths
        if any(p in path_lower for p in ["/search", "/product", "/api/product", "/shop", "/catalog"]):
            return "search_results"
        
        # API endpoints - could be error or message depending on context
        if "/api/" in path_lower:
            # For POST requests to API, show message template
            if "post" in path_lower:
                return "message"
            # For GET requests to API, show error
            return "error"
        
        # Default to homepage for unrecognized paths (better than error)
        return "home"

    def generate_product_card_html(self, name: str, description: str, 
                                    price: str, stock: int = 5) -> str:
        """Generate HTML for a single product card."""
        return f"""
        <div class="bg-white rounded-lg shadow-md overflow-hidden hover:shadow-lg transition-shadow">
            <div class="h-48 bg-gradient-to-br from-gray-200 to-gray-300 flex items-center justify-center">
                <span class="text-gray-500 text-sm">{name}</span>
            </div>
            <div class="p-4">
                <h4 class="font-semibold text-lg text-gray-900 mb-2">{name}</h4>
                <p class="text-gray-600 text-sm mb-3 line-clamp-2">{description}</p>
                <div class="flex justify-between items-center">
                    <span class="text-2xl font-bold text-blue-600">${price}</span>
                    <span class="text-sm text-gray-500">{stock} in stock</span>
                </div>
            </div>
        </div>
        """

    def generate_alert_html(self, message: str, alert_type: str = "error") -> str:
        """Generate HTML for an alert message."""
        colors = {
            "error": ("red", "red"),
            "warning": ("yellow", "yellow"),
            "success": ("green", "green"),
            "info": ("blue", "blue")
        }
        bg, border = colors.get(alert_type, ("gray", "gray"))
        
        return f"""
        <div class="mb-6 p-4 bg-{bg}-50 border border-{bg}-200 rounded-md">
            <p class="text-sm text-{border}-800">{message}</p>
        </div>
        """


# Singleton instance
template_engine = TemplateEngine()
