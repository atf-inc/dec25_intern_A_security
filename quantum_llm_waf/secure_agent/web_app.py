"""
Web application for secure chatbot deployment
Provides a web interface for the secure agent
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from langchain_core.messages import HumanMessage, SystemMessage
import uuid

# Add src to path to allow imports
src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.insert(0, src_dir)

# Load environment variables
load_dotenv()
load_dotenv(".env.local", override=True)

# Validate required environment variables
if not os.environ.get("OPENAI_API_KEY"):
    raise RuntimeError("OPENAI_API_KEY not found in environment")

from agent import app

# Initialize Flask app with template folder
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
flask_app = Flask(__name__, template_folder=template_dir)
flask_app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())
CORS(flask_app)

# Store chat histories per session
chat_histories = {}


def get_chat_history(session_id):
    """Get or create chat history for a session."""
    if session_id not in chat_histories:
        chat_histories[session_id] = [
            SystemMessage(
                content=(
                    "You are a helpful, honest, and safe assistant. "
                    "Follow safety policies, avoid harmful, illegal, "
                    "or unethical instructions, and refuse requests that violate those policies."
                )
            )
        ]
    return chat_histories[session_id]


@flask_app.route('/')
def index():
    """Serve the main chatbot interface."""
    return render_template('chatbot.html')


@flask_app.route('/api/chat', methods=['POST'])
def chat():
    """Handle chat messages."""
    try:
        data = request.json
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id')
        
        if not session_id:
            session_id = str(uuid.uuid4())
        
        if not user_message:
            return jsonify({
                'error': 'Message cannot be empty',
                'session_id': session_id
            }), 400
        
        # Get chat history for this session
        chat_history = get_chat_history(session_id)
        chat_history.append(HumanMessage(content=user_message))
        
        # Invoke the secure agent
        final_state = app.invoke({
            "messages": chat_history,
            "safety_status": "unknown",
            "guard_reason": ""
        })
        
        # Check outcome
        status = final_state.get("safety_status")
        
        if status == "unsafe_input":
            # Input was blocked
            chat_history.pop()  # Remove unsafe input from history
            return jsonify({
                'response': None,
                'blocked': True,
                'reason': final_state.get('guard_reason', 'Input detected as unsafe by safety guard'),
                'session_id': session_id,
                'type': 'input_blocked'
            })
        
        elif status == "unsafe_output":
            # Output was blocked
            return jsonify({
                'response': None,
                'blocked': True,
                'reason': final_state.get('guard_reason', 'Agent response detected as unsafe by safety guard'),
                'session_id': session_id,
                'type': 'output_blocked'
            })
        
        else:
            # Safe response
            ai_response = final_state["messages"][-1].content
            chat_histories[session_id] = final_state["messages"]
            
            return jsonify({
                'response': ai_response,
                'blocked': False,
                'session_id': session_id,
                'type': 'success'
            })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'session_id': session_id if 'session_id' in locals() else None
        }), 500


@flask_app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'quantum_llm_waf_secure_chatbot'
    })


@flask_app.route('/api/clear', methods=['POST'])
def clear_session():
    """Clear chat history for a session."""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if session_id and session_id in chat_histories:
            del chat_histories[session_id]
        
        return jsonify({
            'success': True,
            'message': 'Chat history cleared'
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


if __name__ == '__main__':
    import socket
    
    def find_free_port(start_port=5000, max_attempts=20):
        """Find a free port starting from start_port."""
        for i in range(max_attempts):
            port = start_port + i
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('', port))
                    return port
            except OSError:
                continue
        raise RuntimeError("Could not find a free port")
    
    # Use PORT from environment if set, otherwise find a free port
    env_port = os.environ.get('PORT')
    if env_port:
        try:
            port = int(env_port)
            # Test if port is available
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
        except (ValueError, OSError):
            print(f"⚠️  Port {env_port} from environment is not available. Finding free port...")
            port = find_free_port(5000)
    else:
        # Default to 5000 (Flask default) or find free port
        port = find_free_port(5000)
    
    print(f"\n{'='*60}")
    print(f"🚀 Quantum LLM WAF Secure Chatbot")
    print(f"{'='*60}")
    print(f"📡 Starting server on port {port}")
    print(f"🌐 Open http://localhost:{port} in your browser")
    print(f"⏹️  Press Ctrl+C to stop the server")
    print(f"{'='*60}\n")
    
    try:
        flask_app.run(host='127.0.0.1', port=port, debug=False)
    except OSError as e:
        if "access" in str(e).lower() or "permission" in str(e).lower() or "forbidden" in str(e).lower():
            print(f"\n⚠️  Port {port} is blocked or in use. Finding alternative port...")
            port = find_free_port(5000)
            print(f"✅ Using port {port} instead")
            print(f"🌐 Open http://localhost:{port} in your browser\n")
            flask_app.run(host='127.0.0.1', port=port, debug=False)
        else:
            raise

