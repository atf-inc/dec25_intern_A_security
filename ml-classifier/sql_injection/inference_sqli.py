import torch
import torch.nn.functional as F
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import os

class SQLiDetector:
    def __init__(self):
        """
        Initializes the SQL Injection Detector.
        """
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(self.base_path, "model")

        # Validation
        if not os.path.exists(os.path.join(self.model_path, "config.json")):
            print(f"Error: Model files not found in {self.model_path}")
            return

        try:
            self.tokenizer = DistilBertTokenizer.from_pretrained(self.model_path)
            self.model = DistilBertForSequenceClassification.from_pretrained(self.model_path)
            self.model.eval()
        except Exception as e:
            print(f"Failed to load model: {e}")

    def predict(self, text):
        """
        Classifies input text.
        Uses Temperature Scaling (T=5.0) to calibrate confidence scores,
        allowing for a distinct 'Suspicious' category.
        """
        if not hasattr(self, 'model'):
            return {"verdict": "ERROR", "message": "Model not loaded"}

        # 1. Tokenize
        inputs = self.tokenizer(
            text, 
            return_tensors="pt", 
            padding=True, 
            truncation=True, 
            max_length=64
        )

        # 2. Inference
        with torch.no_grad():
            outputs = self.model(**inputs)
        
        # 3. Calibration (Temperature Scaling)
        # T=5.0 spreads the probability distribution to detect ambiguous inputs
        temperature = 5.0 
        scaled_logits = outputs.logits / temperature
        
        # 4. Probability Calculation
        probs = F.softmax(scaled_logits, dim=1)
        attack_prob = probs[0][1].item()

        # 5. Decision Logic
        verdict = "SAFE"
        if attack_prob > 0.80:
            verdict = "MALICIOUS"
        elif attack_prob > 0.40:
            verdict = "SUSPICIOUS"

        return {
            "payload": text,
            "verdict": verdict,
            "confidence_score": attack_prob
        }

# --- Final Test Suite ---
if __name__ == "__main__":
    detector = SQLiDetector()
    
    # A mix of Safe, Suspicious, and Malicious for demonstration
    test_cases = [
        "<img src=x onerror=alert(1)>",             # XSS
        "$(whoami)",                                 # Command Injection
        "../etc/passwd",                             # Path Traversal
        "q=best laptop under 50000",                 # Safe Search
        '{"username": {"$ne": null}}',               # NoSQL Injection (Use Single Quotes here!)
        "http://localhost:8080",                     # SSRF / URL
        "acunetix_test",                             # Vulnerability Scanner
        "<%= 7*7 %>"                                 # Server Side Template Injection (SSTI)
    ]

    print(f"{'VERDICT':<15} | {'SCORE':<8} | {'PAYLOAD'}")
    print("-" * 50)
    
    for payload in test_cases:
        result = detector.predict(payload)
        print(f"{result['verdict']:<15} | {result['confidence_score']:.4f}   | {result['payload']}")