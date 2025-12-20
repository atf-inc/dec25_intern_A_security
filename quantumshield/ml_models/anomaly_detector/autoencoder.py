"""Autoencoder-based anomaly detector."""

import torch
import torch.nn as nn
from typing import Dict, Any, Optional
import structlog
from pathlib import Path
from ...config.settings import get_settings
from ...config.logging_config import get_logger

logger = get_logger(__name__)


class AnomalyAutoencoder(nn.Module):
    """Autoencoder for anomaly detection."""
    
    def __init__(self, input_size: int = 40, encoding_dim: int = 10):
        """Initialize autoencoder."""
        super().__init__()
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_size, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, encoding_dim),
        )
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_size),
            nn.Sigmoid(),
        )
    
    def forward(self, x):
        """Forward pass."""
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AnomalyDetector:
    """Anomaly detector using autoencoder."""
    
    def __init__(self):
        """Initialize anomaly detector."""
        self.settings = get_settings()
        self.model: Optional[AnomalyAutoencoder] = None
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() and self.settings.ml_enable_gpu
            else "cpu"
        )
        self.model_path = Path(self.settings.ml_models_path) / "anomaly_detector_v1.pth"
        self.threshold = 0.1  # Reconstruction error threshold
    
    async def load_model(self) -> None:
        """Load trained model."""
        try:
            # Initialize model architecture
            self.model = AnomalyAutoencoder()
            logger.debug("AnomalyAutoencoder architecture created successfully")
            
            # Try to load trained weights if available
            if self.model_path.exists():
                try:
                    state_dict = torch.load(self.model_path, map_location=self.device)
                    self.model.load_state_dict(state_dict, strict=False)
                    logger.info("Loaded trained anomaly detector model", path=str(self.model_path))
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
                test_input = torch.zeros(1, 40, dtype=torch.float32).to(self.device)
                with torch.no_grad():
                    _ = self.model(test_input)
                logger.info("Anomaly detector model initialized and verified successfully")
            except Exception as test_error:
                logger.error("Model architecture test failed", error=str(test_error))
                raise
            
        except Exception as e:
            logger.error("Failed to initialize anomaly detector", error=str(e), exc_info=True)
            # Set to None so system can continue without ML classification
            self.model = None
            logger.warning("Anomaly detector disabled - continuing without ML classification")
    
    async def infer(
        self, packet: Dict[str, Any], flow: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Detect anomalies in traffic.
        
        Returns:
            Dict with threat_score, is_anomaly, and reconstruction_error
        """
        if not self.model:
            return {"threat_score": 0.0, "is_anomaly": False, "reconstruction_error": 0.0}
        
        try:
            # Extract flow features
            features = self._extract_flow_features(packet, flow)
            
            # Convert to tensor
            input_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0)
            input_tensor = input_tensor.to(self.device)
            
            # Run inference
            with torch.no_grad():
                reconstructed = self.model(input_tensor)
                reconstruction_error = torch.mean((input_tensor - reconstructed) ** 2).item()
            
            # Determine if anomaly
            is_anomaly = reconstruction_error > self.threshold
            threat_score = min(1.0, reconstruction_error / self.threshold)
            
            return {
                "threat_score": threat_score,
                "is_anomaly": is_anomaly,
                "reconstruction_error": reconstruction_error,
                "reason": "Anomaly detected" if is_anomaly else "Normal traffic",
            }
        
        except Exception as e:
            logger.error("Anomaly detector inference error", error=str(e), exc_info=True)
            return {"threat_score": 0.0, "is_anomaly": False, "reconstruction_error": 0.0}
    
    def _extract_flow_features(self, packet: Dict[str, Any], flow: Dict[str, Any]) -> list:
        """Extract flow-based features."""
        # Extract 40 features (simplified - would have more in production)
        features = [
            packet.get("length", 0) / 1500.0,  # Normalized packet size
            packet.get("payload_length", 0) / 1500.0,
            packet.get("src_port", 0) / 65535.0,
            packet.get("dst_port", 0) / 65535.0,
            packet.get("protocol", 0) / 255.0,
            flow.get("packet_count", 0) / 1000.0,
            flow.get("byte_count", 0) / 1000000.0,
        ]
        
        # Pad to 40 features (would extract more in production)
        features.extend([0.0] * (40 - len(features)))
        
        return features[:40]

