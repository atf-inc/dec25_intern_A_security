import hashlib
import time
from typing import Optional, Dict
from collections import OrderedDict
from config import settings

class ResponseCache:
    """
    In-memory LRU cache for LLM responses to reduce API calls.
    Cache key is based on system prompt + user input hash.
    """
    def __init__(self):
        self.cache: OrderedDict[str, Dict] = OrderedDict()
        self.max_size = settings.CACHE_MAX_SIZE
        self.ttl = settings.CACHE_TTL_SECONDS
        self.hits = 0
        self.misses = 0
    
    def _generate_key(self, system_prompt: str, user_input: str) -> str:
        """Generate a unique cache key from inputs"""
        combined = f"{system_prompt}|{user_input}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def get(self, system_prompt: str, user_input: str) -> Optional[str]:
        """Retrieve cached response if it exists and is not expired"""
        key = self._generate_key(system_prompt, user_input)
        
        if key in self.cache:
            entry = self.cache[key]
            # Check if expired
            if time.time() - entry['timestamp'] < self.ttl:
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                self.hits += 1
                return entry['response']
            else:
                # Expired, remove it
                del self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, system_prompt: str, user_input: str, response: str):
        """Store response in cache with timestamp"""
        key = self._generate_key(system_prompt, user_input)
        
        # If cache is full, remove oldest item
        if len(self.cache) >= self.max_size and key not in self.cache:
            self.cache.popitem(last=False)  # Remove first (oldest) item
        
        self.cache[key] = {
            'response': response,
            'timestamp': time.time()
        }
        
        # Move to end
        self.cache.move_to_end(key)
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": f"{hit_rate:.2f}%",
            "ttl_seconds": self.ttl
        }
    
    def clear(self):
        """Clear the entire cache"""
        self.cache.clear()
        self.hits = 0
        self.misses = 0

# Global cache instance
response_cache = ResponseCache()
