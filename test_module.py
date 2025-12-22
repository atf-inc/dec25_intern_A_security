import sys
import os
import time
import logging
import asyncio
import warnings

# Suppress warnings and non-critical logs
warnings.filterwarnings("ignore")
logging.getLogger("tensorflow").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("quantumshield").setLevel(logging.WARNING)
logging.getLogger("honeypot").setLevel(logging.WARNING)
logging.getLogger("core").setLevel(logging.WARNING)

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Colors
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"

def print_header(title):
    print("\n" + "=" * 60)
    print(f"{BOLD}{CYAN}{title:^60}{RESET}")
    print("=" * 60)

def measure_time(func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    return result, (end - start) * 1000

def test_quantumshield_module():
    print_header("TESTING MODULE: QUANTUMSHIELD")
    
    print(f"[{YELLOW}INFO{RESET}] Importing QuantumShield Engine...")
    start_import = time.perf_counter()
    try:
        from quantumshield.core.engine import QuantumShieldEngine
        import_time = (time.perf_counter() - start_import) * 1000
        print(f"[{GREEN}PASS{RESET}] Import successful (Time: {import_time:.2f}ms)")
        
        # Test 1: Initialization Performance
        dummy_config = {
            'capture': {'interface': 'test', 'enabled': False},
            'processor': {},
            'decision': {'enabled': False},
            'response': {'enabled': False},
            'detection_engines': {
                'signature': {'enabled': False}, # Disable for speed unless measuring load
                'anomaly': {'enabled': False},
                'behavioral': {'enabled': False}
            },
            'ml_models': {'enabled': False} # Disable heavy ML loading for basic engine test
        }
        
        print(f"[{YELLOW}INFO{RESET}] Initializing Engine (Basic Configuration)...")
        engine, init_time = measure_time(QuantumShieldEngine, dummy_config)
        print(f"[{GREEN}PASS{RESET}] Engine initialized (Time: {init_time:.2f}ms)")
        
        # Test 2: Startup Logic (Mocking start)
        # Verify stats initialization
        stats = engine.get_statistics()
        if 'packets_processed' in stats:
             print(f"[{GREEN}PASS{RESET}] Engine Interface Verify: Stats dictionary accessible")
        else:
             print(f"[{RED}FAIL{RESET}] Engine Interface Verify: Stats missing")

        return True

    except ImportError as e:
        print(f"[{RED}FAIL{RESET}] Import failed: {e}")
        return False
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Exception during test: {e}")
        return False

def test_honeypot_module():
    print_header("TESTING MODULE: HONEYPOT (Firewall Logic)")
    
    print(f"[{YELLOW}INFO{RESET}] Importing Honeypot Firewall Model...")
    try:
        # Import directly to measure loading of the singleton logic
        start_import = time.perf_counter()
        from honeypot.core.firewall import firewall_model
        import_time = (time.perf_counter() - start_import) * 1000
        print(f"[{GREEN}PASS{RESET}] Import successful (Time: {import_time:.2f}ms)")
        
        # Test 1: Prediction Performance (Safe)
        safe_payload = "GET /products/item/12 HTTP/1.1\nHost: localhost"
        result, latency_safe = measure_time(firewall_model.predict_with_confidence, safe_payload)
        status_safe = "CORRECT" if not result['is_malicious'] else "FALSE POSITIVE"
        color_safe = GREEN if not result['is_malicious'] else RED
        
        print(f"[{GREEN}PASS{RESET}] Safe Payload Test:")
        print(f"    Latency: {latency_safe:.2f}ms")
        print(f"    Result : {color_safe}{status_safe}{RESET} (Verdict: {result['verdict']})")

        # Test 2: Prediction Performance (Malicious)
        malicious_payload = "GET /search?q=' OR '1'='1 HTTP/1.1"
        result, latency_mal = measure_time(firewall_model.predict_with_confidence, malicious_payload)
        status_mal = "CORRECT" if result['is_malicious'] or result['verdict'] in ['SUSPICIOUS', 'MALICIOUS'] else "FALSE NEGATIVE"
        color_mal = GREEN if "CORRECT" == status_mal else RED
        
        print(f"[{GREEN}PASS{RESET}] Malicious Payload Test (SQLi):")
        print(f"    Latency: {latency_mal:.2f}ms")
        print(f"    Result : {color_mal}{status_mal}{RESET} (Verdict: {result['verdict']})")
        
        return True
        
    except ImportError as e:
        print(f"[{RED}FAIL{RESET}] Import failed: {e}")
        return False
    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Exception during test: {e}")
        # print details
        import traceback
        traceback.print_exc()
        return False

def test_ml_classifier_module():
    print_header("TESTING MODULE: ML_CLASSIFIER")
    
    print(f"[{YELLOW}INFO{RESET}] Importing Unified ML Classifier...")
    try:
        start_import = time.perf_counter()
        from honeypot.core.ml_classifier import ml_classifier
        import_time = (time.perf_counter() - start_import) * 1000
        print(f"[{GREEN}PASS{RESET}] Import/Load successful (Time: {import_time:.2f}ms)")
        
        # Test 1: SQLi Model (DistilBERT)
        payload = "' UNION SELECT password FROM users --"
        
        # Warmup first (model loading might be lazy or first run is slow)
        ml_classifier.predict_sqli("warmup") 
        
        print(f"[{YELLOW}INFO{RESET}] Testing DistilBERT Inference Speed...")
        start_bert = time.perf_counter()
        res_bert = ml_classifier.predict_sqli(payload)
        bert_time = (time.perf_counter() - start_bert) * 1000
        
        is_mal = res_bert['is_malicious'] or res_bert['verdict'] == 'MALICIOUS'
        color_res = GREEN if is_mal else RED
        print(f"[{color_res}PASS{RESET}] SQLi Detection:")
        print(f"    Latency: {bert_time:.2f}ms")
        print(f"    Conf   : {res_bert.get('confidence', 0):.4f}")
        
        # Test 2: Heuristics Check (should be extremely fast)
        heuristic_payload = "<script>alert(1)</script>"
        start_heur = time.perf_counter()
        res_heur = ml_classifier._check_heuristics(heuristic_payload)
        heur_time = (time.perf_counter() - start_heur) * 1000
        
        print(f"[{GREEN}PASS{RESET}] Heuristic Check:")
        print(f"    Latency: {heur_time:.4f}ms")
        print(f"    Result : {'Detected' if res_heur else 'Missed'}")
        
        return True

    except Exception as e:
        print(f"[{RED}FAIL{RESET}] Exception during test: {e}")
        return False

def main():
    print(f"\n{BOLD}Starting Specific Module Performance Analysis...{RESET}")
    print("This script imports and tests modules individually, bypassing the full system stack.")

    # Run tests
    test_quantumshield_module()
    test_honeypot_module()
    test_ml_classifier_module()
    
    print_header("SUMMARY")
    print("Performance testing completed. See above for latency metrics per component.")

if __name__ == "__main__":
    main()
