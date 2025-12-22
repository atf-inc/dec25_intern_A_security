from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sys
import os
from pathlib import Path

# Add src to path
current_dir = Path(__file__).parent
sys.path.append(str(current_dir / "src"))

from agent import app as agent_app

app = FastAPI(title="Quantum LLM Secure Agent API")

class ChatRequest(BaseModel):
    message: string
    history: list = []

@app.post("/chat")
async def chat(request: ChatRequest):
    try:
        inputs = {"messages": [("user", request.message)]}
        # In a real scenario, we'd handle state/history better
        result = await agent_app.ainvoke(inputs)
        
        # Extract the last message and safety status
        last_message = result["messages"][-1].content
        safety_status = result.get("safety_status", "unknown")
        
        return {
            "response": last_message,
            "safety_status": safety_status
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
