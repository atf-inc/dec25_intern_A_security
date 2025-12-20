import os
import sys
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from termcolor import colored

# Add src to path to allow imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    # Load environment variables first
    load_dotenv()
    load_dotenv(".env.local", override=True)
    
    # Validate required environment variables before importing agent
    if not os.environ.get("OPENAI_API_KEY"):
        print(colored("Error: OPENAI_API_KEY not found in environment.", "red"))
        print("Please set OPENAI_API_KEY in your environment or .env file.")
        return
    
    # Note: Guard now uses ChatGPT API (requires OPENAI_API_KEY, which is already checked above)
    
    # Import agent after environment is validated
    from agent import app

    print(colored("PurpleLlama Secure Agent Initialized.", "green", attrs=["bold"]))
    print("Type 'quit' or 'exit' to end the session.\n")

    # Seed the conversation with a safety-focused system message.
    chat_history = [
        SystemMessage(
            content=(
                "You are a helpful, honest, and safe assistant. "
                "Follow safety policies, avoid harmful, illegal, "
                "or unethical instructions, and refuse requests that violate those policies."
            )
        )
    ]

    while True:
        try:
            user_input = input(colored("You: ", "cyan"))
            if user_input.lower() in ["quit", "exit"]:
                break
            
            chat_history.append(HumanMessage(content=user_input))
            
            print(colored("Processing...", "yellow"), end="\r")
            
            # Invoke the graph
            final_state = app.invoke({"messages": chat_history, "safety_status": "unknown", "guard_reason": ""})
            
            # Check outcome
            status = final_state.get("safety_status")
            
            if status == "unsafe_input":
                print(colored(f"\n[BLOCKED] Input detected as unsafe by safety guard.", "red"))
                print(colored(f"Reason: {final_state.get('guard_reason')}\n", "red"))
                chat_history.pop() # Remove unsafe input from history
                
            elif status == "unsafe_output":
                print(colored(f"\n[BLOCKED] Agent response detected as unsafe by safety guard.", "red"))
                print(colored(f"Reason: {final_state.get('guard_reason')}\n", "red"))
                # We might want to remove the unsafe output from history too in a real app
                
            else:
                ai_response = final_state["messages"][-1].content
                print(colored(f"\nAgent: {ai_response}\n", "green"))
                chat_history = final_state["messages"]

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(colored(f"\nError: {e}", "red"))

if __name__ == "__main__":
    main()
