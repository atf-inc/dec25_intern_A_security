# ML Models Documentation

## Available Models

### Traffic Classifier
- **Architecture**: CNN + LSTM
- **Purpose**: Classify traffic as benign or malicious
- **Input**: Packet payload and flow features
- **Output**: Traffic class probabilities

### Anomaly Detector
- **Architecture**: Autoencoder
- **Purpose**: Detect anomalous traffic patterns
- **Input**: Flow-based features
- **Output**: Anomaly score

## Training

Models can be trained using the training scripts in `ml_models/` directories.

## Model Deployment

Trained models should be placed in the `models/` directory with appropriate naming.

