import os
import asyncio
from groq import AsyncGroq
from config import settings
import logging

# Configure error logging
logging.basicConfig(
    filename='error.log', 
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("llm_client")

class LLMClient:
    def __init__(self):
        self.client = AsyncGroq(api_key=settings.GROQ_API_KEY)
        self.model = settings.LLM_MODEL
        self.temperature = settings.LLM_TEMPERATURE
        self.max_tokens = settings.LLM_MAX_TOKENS
        self.request_count = 0
        self.error_count = 0
        self.semaphore = asyncio.Semaphore(2)  # Limit to 2 concurrent requests

    async def generate_response(self, system_prompt: str, user_input: str, retries: int = 2) -> str:
        """Generate response with retry logic and error handling (Async)"""
        self.request_count += 1
        
        async with self.semaphore:
            for attempt in range(retries + 1):
                try:
                    chat_completion = await self.client.chat.completions.create(
                        messages=[
                            {
                                "role": "system",
                                "content": system_prompt,
                            },
                            {
                                "role": "user",
                                "content": user_input,
                            }
                        ],
                        model=self.model,
                        temperature=self.temperature,
                        max_tokens=self.max_tokens,
                    )
                    return chat_completion.choices[0].message.content
                    
                except Exception as e:
                    self.error_count += 1
                    error_msg = f"Error generating LLM response (attempt {attempt + 1}/{retries + 1}): {str(e)}"
                    print(error_msg)
                    logger.error(error_msg)
                    
                    if attempt < retries:
                    # Exponential backoff
                        sleep_time = 2 ** attempt
                        if "rate_limit_exceeded" in str(e):
                            sleep_time = 10  # Wait longer for rate limits
                            print(f"Rate limit hit. Sleeping {sleep_time}s...")
                        await asyncio.sleep(sleep_time)
                    else:
                        # Final fallback response
                        return "Command not found" if "command" in user_input.lower() else "404 Not Found"
    
    def get_stats(self) -> dict:
        """Get LLM usage statistics"""
        return {
            "total_requests": self.request_count,
            "errors": self.error_count,
            "model": self.model
        }

llm_client = LLMClient()

