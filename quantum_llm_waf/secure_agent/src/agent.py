import os
from typing import TypedDict, List, Optional
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from guard import ChatGPTGuard

class AgentState(TypedDict):
    messages: List[BaseMessage]
    safety_status: str
    guard_reason: str

# Lazy initialization - these will be created when first needed
_llm: Optional[ChatOpenAI] = None
_guard: Optional[ChatGPTGuard] = None

def get_llm() -> ChatOpenAI:
    """Lazy initialization of the LLM."""
    global _llm
    if _llm is None:
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError(
                "OPENAI_API_KEY is not set. "
                "Please set it in your environment or .env file."
            )
        OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        _llm = ChatOpenAI(model=OPENAI_MODEL, temperature=0.7)
    return _llm

def get_guard() -> ChatGPTGuard:
    """Lazy initialization of the guard using ChatGPT API."""
    global _guard
    if _guard is None:
        try:
            # Use ChatGPT API for safety checks (replaces local Llama Guard models)
            _guard = ChatGPTGuard()
            print("[INFO] Using ChatGPT API for safety checks")
        except RuntimeError as e:
            # If OpenAI key is missing, create a dummy guard
            print(f"[WARNING] Guard initialization failed: {e}")
            print("[WARNING] Running without guard protection. Set OPENAI_API_KEY in .env")
            class DummyGuard:
                def check_input(self, text):
                    return {"safe": True, "response": "safe (no guard available)"}
                def check_output(self, text):
                    return {"safe": True, "response": "safe (no guard available)"}
            _guard = DummyGuard()
    return _guard

def input_guard_node(state: AgentState):
    """Checks the latest user message for safety."""
    last_message = state["messages"][-1]
    if isinstance(last_message, HumanMessage):
        user_input = last_message.content
        guard = get_guard()
        result = guard.check_input(user_input)
        
        if not result["safe"]:
            return {"safety_status": "unsafe_input", "guard_reason": result["response"]}
            
    return {"safety_status": "safe"}

def chatbot_node(state: AgentState):
    """Generates a response from the LLM."""
    messages = state["messages"]
    llm = get_llm()
    response = llm.invoke(messages)
    return {"messages": [response]}

def output_guard_node(state: AgentState):
    """Checks the latest agent message for safety."""
    last_message = state["messages"][-1]
    if isinstance(last_message, AIMessage):
        agent_output = last_message.content
        guard = get_guard()
        result = guard.check_output(agent_output)
        
        if not result["safe"]:
            return {
                "safety_status": "unsafe_output", 
                "guard_reason": result["response"],
                # We replace the unsafe message or flag it.
                # Here we will keep it but state marks it as unsafe, so main loop can handle it.
            }
            
    return {"safety_status": "safe"}

def route_input(state: AgentState):
    if state["safety_status"] == "unsafe_input":
        return "unsafe"
    return "safe"

def route_output(state: AgentState):
    if state["safety_status"] == "unsafe_output":
        return "unsafe"
    return "safe"

# Build Graph
workflow = StateGraph(AgentState)

workflow.add_node("input_guard", input_guard_node)
workflow.add_node("chatbot", chatbot_node)
workflow.add_node("output_guard", output_guard_node)

workflow.set_entry_point("input_guard")

workflow.add_conditional_edges(
    "input_guard",
    route_input,
    {
        "unsafe": END,
        "safe": "chatbot"
    }
)

workflow.add_edge("chatbot", "output_guard")

workflow.add_conditional_edges(
    "output_guard",
    route_output,
    {
        "unsafe": END,
        "safe": END
    }
)

app = workflow.compile()
