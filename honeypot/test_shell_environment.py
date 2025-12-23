"""
Test script for the enhanced shell environment

Tests basic shell commands, file system operations, and session persistence.
"""

import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fake_filesystem import get_filesystem, FakeFileSystem
from core.shell_processor import shell_processor


async def test_basic_commands():
    """Test basic shell commands"""
    print("=" * 60)
    print("Testing Basic Shell Commands")
    print("=" * 60)
    
    session_id = "test-session-001"
    fs = get_filesystem(session_id)
    
    tests = [
        ("pwd", "Print working directory"),
        ("whoami", "Current user"),
        ("hostname", "System hostname"),
        ("ls", "List current directory"),
        ("ls -la", "List with details"),
        ("cd /etc", "Change to /etc"),
        ("pwd", "Verify directory change"),
        ("ls", "List /etc contents"),
        ("cat passwd", "Read /etc/passwd"),
        ("cd /var/www", "Change to /var/www"),
        ("ls -la", "List web directory"),
        ("cat techshop/.env", "Read .env file"),
        ("find /etc -name '*.conf'", "Find config files"),
        ("uname -a", "System information"),
        ("ps aux", "Process list"),
        ("netstat -tulpn", "Network connections"),
        ("history", "Command history"),
    ]
    
    for command, description in tests:
        print(f"\n[TEST] {description}")
        print(f"$ {command}")
        output, should_use_llm = shell_processor.process_command(session_id, command, fs)
        
        if should_use_llm:
            print(f"[INFO] Command routed to LLM: {command}")
        else:
            print(output)
            print()


async def test_file_system_navigation():
    """Test file system navigation and persistence"""
    print("=" * 60)
    print("Testing File System Navigation")
    print("=" * 60)
    
    session_id = "test-session-002"
    fs = get_filesystem(session_id)
    
    print(f"\n[TEST] Initial directory: {fs.pwd()}")
    
    # Navigate through directories
    print("\n[TEST] Navigating to /home/admin/.ssh")
    success, result = fs.cd("/home/admin/.ssh")
    print(f"Success: {success}, Current: {fs.pwd()}")
    
    print("\n[TEST] List SSH directory")
    print(fs.ls(".", show_all=True, long_format=True))
    
    print("\n[TEST] Read SSH private key")
    print(fs.cat("id_rsa")[:200] + "...")
    
    print("\n[TEST] Navigate to parent directory")
    success, result = fs.cd("..")
    print(f"Current: {fs.pwd()}")
    
    print("\n[TEST] Navigate to /var/log")
    success, result = fs.cd("/var/log")
    print(f"Current: {fs.pwd()}")
    print(fs.ls(".", long_format=True))


async def test_session_persistence():
    """Test that different sessions have isolated file systems"""
    print("=" * 60)
    print("Testing Session Isolation")
    print("=" * 60)
    
    session1 = "test-session-003"
    session2 = "test-session-004"
    
    fs1 = get_filesystem(session1)
    fs2 = get_filesystem(session2)
    
    print(f"\n[TEST] Session 1 initial directory: {fs1.pwd()}")
    print(f"[TEST] Session 2 initial directory: {fs2.pwd()}")
    
    # Change directory in session 1
    fs1.cd("/etc")
    print(f"\n[TEST] Session 1 after cd /etc: {fs1.pwd()}")
    print(f"[TEST] Session 2 should be unchanged: {fs2.pwd()}")
    
    # Verify isolation
    if fs1.pwd() == "/etc" and fs2.pwd() == "/var/www":
        print("\n✅ Session isolation working correctly!")
    else:
        print("\n❌ Session isolation failed!")


async def test_command_history():
    """Test command history functionality"""
    print("=" * 60)
    print("Testing Command History")
    print("=" * 60)
    
    session_id = "test-session-005"
    fs = get_filesystem(session_id)
    
    commands = ["ls", "pwd", "whoami", "cd /etc", "cat passwd"]
    
    print("\n[TEST] Executing commands...")
    for cmd in commands:
        shell_processor.process_command(session_id, cmd, fs)
        print(f"  $ {cmd}")
    
    print("\n[TEST] Retrieving history...")
    output, _ = shell_processor.process_command(session_id, "history", fs)
    print(output)


async def test_realistic_attack_scenario():
    """Simulate a realistic attacker reconnaissance scenario"""
    print("=" * 60)
    print("Simulating Attacker Reconnaissance")
    print("=" * 60)
    
    session_id = "attacker-session-001"
    fs = get_filesystem(session_id)
    
    attack_commands = [
        "whoami",
        "id",
        "uname -a",
        "ls -la",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "find / -name '*.conf' 2>/dev/null",
        "cat /var/www/techshop/.env",
        "cat /home/admin/.ssh/id_rsa",
        "netstat -tulpn",
        "ps aux",
        "cat /var/log/auth.log",
    ]
    
    for cmd in attack_commands:
        print(f"\n$ {cmd}")
        output, should_use_llm = shell_processor.process_command(session_id, cmd, fs)
        
        if should_use_llm:
            print(f"[LLM FALLBACK] {cmd}")
        else:
            # Truncate long outputs
            if len(output) > 300:
                print(output[:300] + "\n... [truncated]")
            else:
                print(output)


async def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("ENHANCED SHELL ENVIRONMENT TEST SUITE")
    print("=" * 60 + "\n")
    
    try:
        await test_basic_commands()
        await test_file_system_navigation()
        await test_session_persistence()
        await test_command_history()
        await test_realistic_attack_scenario()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS COMPLETED")
        print("=" * 60 + "\n")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
