# SQL Injection Classifier

A machine learning based detector for SQL injection attacks using DistilBERT.

## Overview
This module provides a standalone SQL injection detection system. It uses a fine-tuned DistilBERT model to classify SQL queries as SAFE, SUSPICIOUS, or MALICIOUS.

## Setup
1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the inference script to test the detector:
```bash
python sql_injection/inference_sqli.py
```

## Model
The model is located in `sql_injection/model/` and includes:
- `config.json`: Model configuration
- `model.safetensors`: Pre-trained weights
- Tokenizer files (`vocab.txt`, etc.)
