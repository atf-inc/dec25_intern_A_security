import asyncio
from core.llm_client import llm_client
from core.deception import deception_engine

async def test_llm():
    print("Testing LLM connection...")
    
    # Simple test
    context = {
        "user": "www-data",
        "current_directory": "/var/www/html",
        "history": []
    }
    
    user_input = "POST /login\nBody: username=admin' OR 1=1--&password=test"
    
    try:
        response = await deception_engine.process_input(context, user_input)
        print("\n✅ LLM Response:")
        print(response)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_llm())
