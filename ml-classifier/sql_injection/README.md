# SQL Injection Detection Module

This module utilizes a **fine-tuned DistilBERT** model to detect SQL Injection (SQLi) attacks in real-time. It analyzes the semantic structure of input queries to classify them as Safe, Suspicious, or Malicious.

##  Features

*   **Deep Learning Based**: Uses `DistilBERT` (Transformer architecture) for superior context understanding compared to traditional regex or keyword matching.
*   **Three-Level Classification**:
    *    **SAFE** (Probability < 0.40)
    *    **SUSPICIOUS** (0.40 ≤ Probability ≤ 0.80)
    *    **MALICIOUS** (Probability > 0.80)
*   **Low Latency**: Optimized for fast inference on CPU, suitable for integration into Web Application Firewalls (WAF).
*   **Self-Contained**: Includes the pre-trained model artifacts, requiring no external downloads.

##  Directory Structure

```
sql_injection/
├── model/                  # Fine-tuned DistilBERT Model Artifacts
│   ├── config.json
│   ├── model.safetensors   # The Model Weights
│   ├── vocab.txt           # Tokenizer Vocabulary
│   └── ...
├── inference_sqli.py       # Main Prediction Script
└── __init__.py
```

##  Setup & Installation

Ensure you have the required dependencies installed (from the root `requirements.txt`):

```bash
pip install torch transformers
```

##  Usage

### 1. Running the Diagnostics Script
You can run the script directly to test against a set of predefined payloads:

```bash
python sql_injection/inference_sqli.py
```

**sample Output:**
```text
Input: select * from users where id = 1
Verdict: SAFE
Score: 0.0001
------------------------------
Input: ' OR 1=1 --
Verdict: MALICIOUS
Score: 0.9998
```

### 2. Integration into your Code
To use the detector in your own application:

```python
from sql_injection.inference_sqli import SQLiDetector

# Initialize (loads model once)
detector = SQLiDetector()

# Analyze a query
query = "SELECT * FROM users WHERE name = 'admin' --"
result = detector.predict(query)

print(result)
# Output: {'payload': "...", 'verdict': 'MALICIOUS', 'confidence_score': 0.99}
```

##  Model Details

*   **Base Architecture**: `DistilBertForSequenceClassification`
*   **Fine-Tuning Strategy**: Full Fine-Tuning on a dataset of SQL injection payloads.
*   **Input Constraints**: Max sequence length of 64 tokens (truncated if longer).
