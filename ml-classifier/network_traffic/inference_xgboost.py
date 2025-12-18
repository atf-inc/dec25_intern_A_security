import xgboost as xgb
import joblib
import pandas as pd
import numpy as np
import os

class NetworkTrafficClassifier:
    def __init__(self):
        # Paths relative to this script
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(self.base_dir, 'model', 'xgboost_model.json')
        self.scaler_path = os.path.join(self.base_dir, 'model', 'scaler.pkl')
        self.encoder_path = os.path.join(self.base_dir, 'model', 'label_encoders.pkl')
        
        self.model = None
        self.scaler = None
        self.encoders = None
        self._load_artifacts()

    def _load_artifacts(self):
        """Loads the trained model, scaler, and encoders."""
        try:
            # Load XGBoost
            self.model = xgb.XGBClassifier()
            self.model.load_model(self.model_path)
            
            # Load Processors
            self.scaler = joblib.load(self.scaler_path)
            self.encoders = joblib.load(self.encoder_path)
            print("✅ Network Traffic Model Loaded Successfully")
        except Exception as e:
            print(f"❌ Error loading Network Model: {e}")
            print("Did you run train_xgboost.py first?")

    def predict_packet(self, packet_data):
        """
        packet_data: A dictionary containing the network features.
        """
        if self.model is None:
            return {"error": "Model not loaded"}

        # 1. Convert input to DataFrame
        if isinstance(packet_data, dict):
            df = pd.DataFrame([packet_data])
        else:
            df = packet_data.copy()

        # 2. ENCODE STRINGS
        # We must handle cases where the input string (e.g., a new protocol) 
        # was never seen during training. We map unknown values to 0.
        for col, encoder in self.encoders.items():
            if col in df.columns:
                # Get the known classes from the encoder
                known_classes = set(encoder.classes_)
                # Apply encoding safely
                df[col] = df[col].astype(str).apply(
                    lambda x: encoder.transform([x])[0] if x in known_classes else 0
                )

        # 3. CRITICAL: ALIGN COLUMNS
        # Ensure columns are in the EXACT order as training
        if hasattr(self.scaler, 'feature_names_in_'):
            try:
                # Reorder columns to match training
                df = df[self.scaler.feature_names_in_]
            except KeyError as e:
                return {"error": f"Missing required feature columns: {e}"}
        
        # 4. SCALE NUMBERS
        features_scaled = self.scaler.transform(df)

        # 5. PREDICT
        prob = self.model.predict_proba(features_scaled)[0][1] # Probability of Attack
        
        # 6. LOGIC
        if prob > 0.8:
            verdict = "MALICIOUS"
        elif prob > 0.4:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return {
            "verdict": verdict,
            "confidence": float(prob),
            "type": "Network Traffic"
        }

# --- TEST BLOCK ---
if __name__ == "__main__":
    print("Testing Inference Class...")
    classifier = NetworkTrafficClassifier()
    
    # --- SAMPLE PACKET (From UNSW-NB15 Dataset) ---
    # This represents a generic normal packet
    sample_packet = {
        'dur': 0.000011,
        'proto': 'udp',
        'service': '-',
        'state': 'INT',
        'spkts': 2,
        'dpkts': 0,
        'sbytes': 496,
        'dbytes': 0,
        'rate': 90909.0902,
        'sttl': 254,
        'dttl': 0,
        'sload': 180363632.0,
        'dload': 0.0,
        'sloss': 0,
        'dloss': 0,
        'sinpkt': 0.011,
        'dinpkt': 0.0,
        'sjit': 0.0,
        'djit': 0.0,
        'swin': 0,
        'stcpb': 0,
        'dtcpb': 0,
        'dwin': 0,
        'tcprtt': 0.0,
        'synack': 0.0,
        'ackdat': 0.0,
        'smean': 248,
        'dmean': 0,
        'trans_depth': 0,
        'response_body_len': 0,
        'ct_srv_src': 2,
        'ct_state_ttl': 2,
        'ct_dst_ltm': 1,
        'ct_src_dport_ltm': 1,
        'ct_dst_sport_ltm': 1,
        'ct_dst_src_ltm': 2,
        'is_ftp_login': 0,
        'ct_ftp_cmd': 0,
        'ct_flw_http_mthd': 0,
        'ct_src_ltm': 1,
        'ct_srv_dst': 2,
        'is_sm_ips_ports': 0
    }

    print("\n>>> Simulating Incoming Packet...")
    result = classifier.predict_packet(sample_packet)
    print("RESULT:", result)