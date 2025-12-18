# Network Traffic Anomaly Detection

This module implements an XGBoost-based classifier for detecting malicious network traffic (IDS).

## Dataset
Uses the UNSW_NB15 dataset for training and testing.
The data is located in the `data/` directory.

## Training
To retrain the model:
```bash
python train_xgboost.py
```

## Inference
To run inference on new data:
```bash
python inference_xgboost.py
```

## Comparison
To compare different model variations:
```bash
python compare_models.py
```
