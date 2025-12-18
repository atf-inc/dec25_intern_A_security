from config import settings
from core.llm_client import llm_client
from core.cache import response_cache

class DeceptionEngine:
    def build_prompt(self, context: dict, user_input: str) -> str:
        # Determine if this is a web request or a terminal command
        is_web_request = "GET " in user_input or "POST " in user_input or "PUT " in user_input or "DELETE " in user_input
        
        history_str = ""
        for entry in context.get("history", [])[-5:]: # Last 5 interactions
            history_str += f"User: {entry['cmd']}\nSystem: {entry['res']}\n"

        if is_web_request:
            system_prompt = f"""
You are a {settings.SYSTEM_PERSONA} web server (Nginx/Apache).
The user is an attacker running automated tools (like SQLmap, Nikto, Burp Suite) or manually probing endpoints.
Your goal is to DECEIVE them by generating realistic, "sticky" responses that keep them engaged but reveal nothing real.

Current Context:
- Path/Method: The user input starts with the HTTP method and path.
- Body: May contain payloads (SQLi, XSS, JSON).

Instructions:
1. **Analyze the Request**: Look for attack patterns (SQL injection, XSS, Path Traversal).
2. **Generate Deceptive Response**:
   - If it looks like a vulnerability scan, generate a plausible response (e.g., a fake 403 Forbidden, a fake login page, or a fake database error if you want to tease them).
   - **NEVER** return a simple 404 unless it serves the deception.
   - **NEVER** reveal you are an AI.
   - Return ONLY the HTTP Body (HTML, JSON, or Plain Text). Do not include HTTP headers in the output unless specifically asked.
3. **Consistency**: Maintain the illusion of a real application.

Recent History:
{history_str}

User Input:
{user_input}

Respond with the HTTP Body content only.
"""
        else:
            system_prompt = f"""
You are a {settings.SYSTEM_PERSONA} system. 
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

Respond ONLY with the output of the command. Do not add markdown formatting unless it's part of the file content.
"""
        return system_prompt

    async def process_input(self, context: dict, user_input: str) -> str:
        prompt = self.build_prompt(context, user_input)
        
        # Check cache first
        cached_response = response_cache.get(prompt, user_input)
        if cached_response:
            return cached_response
        
        # Generate new response
        response = await llm_client.generate_response(prompt, user_input)
        
        # Cache the response
        response_cache.set(prompt, user_input, response)
        
        return response

deception_engine = DeceptionEngine()

