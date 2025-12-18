"""
Fixed script to run MITRE benchmark with proper paths and imports.
Run from project root: python run_mitre_benchmark.py
"""
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.absolute()
purplellama_path = project_root / "PurpleLlama"
codeshield_path = purplellama_path / "CodeShield"

# Add paths to sys.path
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(purplellama_path))
sys.path.insert(0, str(codeshield_path))

# Set PYTHONPATH
pythonpath = os.environ.get("PYTHONPATH", "")
os.environ["PYTHONPATH"] = os.pathsep.join([
    str(project_root),
    str(purplellama_path),
    str(codeshield_path),
    pythonpath
]).strip(os.pathsep)

# Load .env file from PurpleLlama directory
try:
    from dotenv import load_dotenv
    env_file = purplellama_path / ".env"
    if env_file.exists():
        load_dotenv(env_file, override=True)
        print(f"[OK] Loaded .env file from: {env_file}")
    else:
        # Also try project root
        env_file_root = project_root / ".env"
        if env_file_root.exists():
            load_dotenv(env_file_root, override=True)
            print(f"[OK] Loaded .env file from: {env_file_root}")
        else:
            print("[WARNING] No .env file found. Using environment variables only.")
except ImportError:
    print("[WARNING] python-dotenv not installed. Install with: pip install python-dotenv")
    print("[WARNING] Using environment variables only.")

if __name__ == "__main__":
    import subprocess
    
    # Get the dataset path (absolute)
    dataset_path = purplellama_path / "CybersecurityBenchmarks" / "datasets" / "mitre" / "mitre_benchmark_100_per_category_with_augmentation.json"
    
    if not dataset_path.exists():
        print(f"[ERROR] Dataset not found at: {dataset_path}")
        print("Please ensure the dataset file exists.")
        sys.exit(1)
    
    # Get OpenAI API key from environment (now loaded from .env if available)
    openai_key = os.environ.get("OPENAI_API_KEY")
    if not openai_key:
        print("[ERROR] OPENAI_API_KEY not found")
        print("Please either:")
        print("  1. Set it in PurpleLlama/.env file: OPENAI_API_KEY=sk-your-key-here")
        print("  2. Or set it in environment: $env:OPENAI_API_KEY = 'sk-your-key-here'")
        sys.exit(1)
    
    print(f"[OK] Found OpenAI API key: {openai_key[:10]}...{openai_key[-5:]}")

    # ------------------------------------------------------------------
    # Fast OpenAI key validation to avoid long 401 retry loops
    # ------------------------------------------------------------------
    try:
        import openai
        from openai import AuthenticationError

        try:
            client = openai.OpenAI(api_key=openai_key)
            # Lightweight call – will immediately fail if key is invalid
            client.models.list(limit=1)
        except AuthenticationError as e:
            print("[ERROR] OpenAI rejected the API key (authentication error).")
            print("Details:", e)
            print()
            print("How to fix:")
            print("  1. Go to https://platform.openai.com/api-keys")
            print("  2. Create a NEW secret key")
            print("  3. Update PurpleLlama/.env with:")
            print("       OPENAI_API_KEY=sk-your-new-valid-key-here")
            print("  4. Re-run: python run_mitre_benchmark.py")
            sys.exit(1)
        except Exception as e:
            # Any other error – show info but still continue to benchmark runner
            print("[WARNING] Could not pre-validate OpenAI key:", e)
            print("          Continuing to run benchmark; if the key is invalid,")
            print("          CybersecurityBenchmarks will report 401 errors.")
    except ImportError:
        # openai package not available – skip pre-check
        print("[WARNING] 'openai' package not installed; skipping API key pre-check.")
    
    # Build command - run from project root with full module path
    dataset_path_str = str(dataset_path)
    
    # Format: OPENAI::MODEL::API_KEY
    # Get model name from environment or use default
    # Valid models: gpt-3.5-turbo, gpt-4, gpt-4o, gpt-4o-mini, gpt-4-turbo, o1, o1-mini, o3, o3-mini, o4-mini, gpt-5-mini
    model_name = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")  # Default to gpt-4o-mini
    llm_spec = f"OPENAI::{model_name}::{openai_key}"
    print(f"[OK] Using model: {model_name}")
    
    cmd = [
        sys.executable,
        "-m", "CybersecurityBenchmarks.benchmark.run",
        "--benchmark=mitre",
        f"--prompt-path={dataset_path_str}",
        "--response-path=mitre_results.json",
        "--judge-response-path=mitre_judge_results.json",
        "--stat-path=mitre_stat.json",
        f"--judge-llm={llm_spec}",
        f"--expansion-llm={llm_spec}",
        f"--llm-under-test={llm_spec}",
        "--num-test-cases=5",
    ]
    
    print("[System] Running MITRE benchmark...")
    print(f"[System] Working directory: {project_root}")
    print(f"[System] Command: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(cmd, check=False, cwd=str(project_root))
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        print("\n[System] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to run benchmark: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

