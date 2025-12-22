#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to verify web app works locally before deployment
"""

import os
import sys
from pathlib import Path

# Add paths
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "secure_agent" / "src"))

# Load environment
from dotenv import load_dotenv
load_dotenv()

def test_web_app():
    """Test if web app can be imported and initialized."""
    print("Testing web app import...")
    try:
        from secure_agent.web_app import flask_app
        print("✅ Web app imported successfully")
        
        # Check if template exists
        template_path = project_root / "secure_agent" / "templates" / "chatbot.html"
        if template_path.exists():
            print("✅ Template file exists")
        else:
            print("❌ Template file not found")
            return False
        
        # Check Flask app
        if flask_app:
            print("✅ Flask app initialized")
            print(f"   Template folder: {flask_app.template_folder}")
            return True
        else:
            print("❌ Flask app not initialized")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_agent_import():
    """Test if agent can be imported."""
    print("\nTesting agent import...")
    try:
        from agent import app
        print("✅ Agent imported successfully")
        return True
    except Exception as e:
        print(f"❌ Error importing agent: {e}")
        return False

def main():
    print("=" * 60)
    print("Local Web App Test")
    print("=" * 60)
    
    # Check environment
    if not os.environ.get("OPENAI_API_KEY"):
        print("⚠️  Warning: OPENAI_API_KEY not set")
        print("   Set it for full functionality")
    else:
        print("✅ OPENAI_API_KEY is set")
    
    # Test imports
    agent_ok = test_agent_import()
    web_ok = test_web_app()
    
    print("\n" + "=" * 60)
    if agent_ok and web_ok:
        print("✅ All tests passed! Ready for deployment.")
        print("\nTo test locally, run:")
        print("  cd secure_agent")
        print("  python web_app.py")
        print("\nThen visit: http://localhost:8080")
    else:
        print("❌ Some tests failed. Fix issues before deploying.")
    print("=" * 60)

if __name__ == "__main__":
    main()

