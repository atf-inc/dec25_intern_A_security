"""Traffic classification model (CNN+LSTM)."""

import torch
import torch.nn as nn
from typing import Dict, Any, Optional
import structlog
from pathlib import Path
from ...config.settings import get_settings
from ...config.logging_config import get_logger

logger = get_logger(__name__)


class TrafficClassifierModel(nn.Module):
    """Hybrid CNN-LSTM model for traffic classification."""
    
    def __init__(self, input_size: int = 1500, num_classes: int = 2):
        """Initialize model architecture."""
        super().__init__()
        
        # 1D CNN for spatial features
        self.conv1 = nn.Conv1d(1, 32, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(32, 64, kernel_size=3, padding=1)
        self.pool = nn.MaxPool1d(2)
        
        # LSTM for temporal patterns
        # Note: batch_size is not a parameter for LSTM - it's handled when passing data
        self.lstm = nn.LSTM(64, 128, bidirectional=True)
        
        # Classification head
        self.fc1 = nn.Linear(256, 128)
        self.fc2 = nn.Linear(128, num_classes)
        self.dropout = nn.Dropout(0.3)
        self.relu = nn.ReLU()
        self.softmax = nn.Softmax(dim=1)
    
    def forward(self, x):
        """Forward pass."""
        # x shape: (batch, 1, sequence_length)
        x = self.relu(self.conv1(x))
        x = self.pool(x)
        x = self.relu(self.conv2(x))
        x = self.pool(x)
        
        # Reshape for LSTM
        x = x.permute(2, 0, 1)  # (seq_len, batch, features)
        lstm_out, _ = self.lstm(x)
        
        # Take last output
        x = lstm_out[-1]
        
        # Classification
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        x = self.softmax(x)
        
        return x


class TrafficClassifier:
    """Traffic classifier using CNN+LSTM."""
    
    def __init__(self):
        """Initialize traffic classifier."""
        self.settings = get_settings()
        self.model: Optional[TrafficClassifierModel] = None
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() and self.settings.ml_enable_gpu
            else "cpu"
        )
        self.model_path = Path(self.settings.ml_models_path) / "traffic_classifier_v1.pth"
    
    async def load_model(self) -> None:
        """Load trained model."""
        try:
            # Initialize model architecture
            self.model = TrafficClassifierModel()
            logger.debug("TrafficClassifierModel architecture created successfully")
            
            # Try to load trained weights if available
            if self.model_path.exists():
                try:
                    state_dict = torch.load(self.model_path, map_location=self.device)
                    self.model.load_state_dict(state_dict, strict=False)
                    logger.info("Loaded trained traffic classifier model", path=str(self.model_path))
                except Exception as load_error:
                    logger.warning(
                        "Failed to load model weights, using untrained model",
                        path=str(self.model_path),
                        error=str(load_error)
                    )
                    # Continue with randomly initialized weights
            else:
                logger.info(
                    "Model file not found, using untrained model with random weights",
                    path=str(self.model_path)
                )
                # Model will use randomly initialized weights - still functional for inference
            
            # Move model to device and set to evaluation mode
            self.model.to(self.device)
            self.model.eval()
            
            # Verify model works with a test input
            try:
                test_input = torch.zeros(1, 1, 1500, dtype=torch.float32).to(self.device)
                with torch.no_grad():
                    _ = self.model(test_input)
                logger.info("Traffic classifier model initialized and verified successfully")
            except Exception as test_error:
                logger.error("Model architecture test failed", error=str(test_error))
                raise
            
        except Exception as e:
            logger.error("Failed to initialize traffic classifier", error=str(e), exc_info=True)
            # Set to None so system can continue without ML classification
            self.model = None
            logger.warning("Traffic classifier disabled - continuing without ML classification")
    
    async def infer(
        self, packet: Dict[str, Any], flow: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Classify traffic as benign or malicious.
        
        Returns:
            Dict with threat_score, class, and confidence
        """
        if not self.model:
            return {"threat_score": 0.0, "class": "unknown", "confidence": 0.0}
        
        try:
            # Extract features from packet
            features = self._extract_features(packet, flow)
            
            # Convert to tensor
            input_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0).unsqueeze(0)
            input_tensor = input_tensor.to(self.device)
            
            # Run inference
            with torch.no_grad():
                output = self.model(input_tensor)
                probabilities = output[0].cpu().numpy()
            
            # Interpret results
            # Assuming binary classification: [benign, malicious]
            malicious_prob = float(probabilities[1]) if len(probabilities) > 1 else 0.0
            threat_score = malicious_prob
            confidence = float(max(probabilities))
            
            class_label = "malicious" if malicious_prob > 0.5 else "benign"
            
            return {
                "threat_score": threat_score,
                "class": class_label,
                "confidence": confidence,
                "probabilities": {
                    "benign": float(probabilities[0]) if len(probabilities) > 0 else 0.0,
                    "malicious": malicious_prob,
                },
                "reason": f"Classified as {class_label} with {confidence:.2%} confidence",
            }
        
        except Exception as e:
            logger.error("Traffic classifier inference error", error=str(e), exc_info=True)
            return {"threat_score": 0.0, "class": "unknown", "confidence": 0.0}
    
    def _extract_features(self, packet: Dict[str, Any], flow: Dict[str, Any]) -> list:
        """Extract features for model input."""
        payload = packet.get("payload", b"")
        
        # Convert payload to feature vector (first 1500 bytes, pad if needed)
        features = list(payload[:1500])
        features.extend([0] * (1500 - len(features)))
        
        # Normalize to [0, 1]
        features = [f / 255.0 for f in features]
        
        return features

