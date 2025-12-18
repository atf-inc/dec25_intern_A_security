# Network Traffic Analysis Module

This module implements a machine learning-based **Network Intrusion Detection System (NIDS)**. It analyzes network packet features to identify malicious traffic patterns using **XGBoost**.

##  Features

*   **High Accuracy**: Utilizes `XGBoost` for state-of-the-art tabular data classification.
*   **Comprehensive Pipeline**: Includes scripts for **Training**, **Evaluation/Comparison**, and **Inference**.
*   **Model Comparison**: Built-in suite to benchmark XGBoost against Naive Bayes, SVM, LSTM, and CNNs.
*   **Robust Preprocessing**: Handles categorical encoding (e.g., protocols like TCP/UDP) and numerical scaling automatically.

##  Directory Structure

```
network_traffic/
├── data/                   # Dataset Folder (UNSW-NB15)
│   ├── UNSW_NB15_training-set.csv
│   └── UNSW_NB15_testing-set.csv
├── model/                  # Saved Artifacts
│   ├── xgboost_model.json  # Trained Model
│   ├── scaler.pkl          # Feature Scaler
│   └── label_encoders.pkl  # Categorical Encoders
├── train_xgboost.py        # Script to Train the Model
├── compare_models.py       # Script to Compare Multiple Models
└── inference_xgboost.py    # Script for Single-Packet Inference
```

##  Setup & Installation

Install the required ML libraries:

```bash
pip install pandas numpy xgboost scikit-learn seaborn matplotlib tensorflow
```

##  Usage

### 1. Training the Model
To train the XGBoost model on the dataset found in `data/`:

```bash
python network_traffic/train_xgboost.py
```
*This will generate and save the model artifacts (model, scaler, encoders) into the `model/` directory.*

### 2. Comparing Models
To see how XGBoost stacks up against Deep Learning (LSTM, CNN) and traditional ML (SVM, Naive Bayes):

```bash
python network_traffic/compare_models.py
```
*This produces an accuracy report and a bar chart visualization.*

### 3. Inference (Real-time Prediction)
To classify a single network packet (simulated dictionary):

```bash
python network_traffic/inference_xgboost.py
```

**code snippet for integration:**
```python
from network_traffic.inference_xgboost import NetworkTrafficClassifier

# Initialize
ids = NetworkTrafficClassifier()

# Define a packet (subset of features)
packet = {
    'dur': 0.001,
    'proto': 'tcp',
    'service': 'http',
    'sbytes': 1024,
    'dbytes': 2048,
    # ... (other features)
}

# Predict
result = ids.predict_packet(packet)
print(result) 
# Output: {'verdict': 'SAFE', 'confidence': 0.02, 'type': 'Network Traffic'}
```
