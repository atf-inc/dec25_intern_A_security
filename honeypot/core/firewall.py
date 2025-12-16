import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
import joblib
import os
import logging

logger = logging.getLogger("firewall")

class FirewallModel:
    def __init__(self):
        self.pipeline = None
        self.is_trained = False
        self._train_model()

    def _train_model(self):
        """
        Trains a lightweight model on startup using embedded demo data.
        In a real prod environment, this would load a pre-trained model file.
        """
        logger.info("Training Firewall Model...")
        
        # 1. Dataset (Benign vs Malicious)
        # 0 = Benign, 1 = Malicious
        data = [
            # Benign (Normal traffic)
            ("admin", 0),
            ("user123", 0),
            ("login", 0),
            ("password", 0),
            ("search=laptop", 0),
            ("id=105", 0),
            ("page=1", 0),
            ("action=submit", 0),
            ("shubham", 0),
            ("hello world", 0),
            ("contact@example.com", 0),
            
            # Malicious (SQL Injection)
            ("' OR 1=1 --", 1),
            ("admin' --", 1),
            ("UNION SELECT 1,2,3", 1),
            ("1' ORDER BY 1--", 1),
            ("admin' #", 1),
            ("' OR '1'='1", 1),
            ("1; DROP TABLE users", 1),
            # Form-based SQLi (Noise resilience)
            ("username=admin' OR 1=1&password=123", 1),
            ("q=admin' OR 1=1", 1),
            
            # Malicious (XSS)
            ("<script>alert(1)</script>", 1),
            ("<img src=x onerror=alert(1)>", 1),
            ("javascript:alert('XSS')", 1),
            ("<body>", 1), # Suspicious in inputs
            ("search=<script>alert('XSS')</script>", 1),
        ]
        
        df = pd.DataFrame(data, columns=["payload", "label"])
        
        # 2. Create Pipeline
        # TF-IDF to convert text to numbers
        # Random Forest for classification
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(2, 4))), # Character n-grams catch code patterns well
            ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
        ])
        
        # 3. Train
        self.pipeline.fit(df['payload'], df['label'])
        self.is_trained = True
        logger.info("Firewall Model Trained Successfully.")

    def predict(self, text: str) -> bool:
        """
        Returns True if malicious, False if safe.
        """
        if not self.is_trained or not text:
            return False
            
        # Basic check for empty inputs being safe
        if len(text) < 2:
            return False
            
        # 0. Heuristic Safety Net (Hybrid Approach)
        # Ensure common demo attacks are ALWAYS caught, even if ML wavers.
        import re
        patterns = [
            r"(?i)(\bOR\b|\bUNION\b|\bSELECT\b).{0,10}(\bFROM\b|\bWHERE\b|\d=)",
            r"(?i)'\s*OR\s*\d=\d",
            r"(?i)<script",
            r"(?i)javascript:",
        ]
        for p in patterns:
            if re.search(p, text):
                logger.warning(f"Firewall HEURISTIC BLOCK: '{text}'")
                return True

        prediction = self.pipeline.predict([text])[0]
        proba = self.pipeline.predict_proba([text])[0][1] # Probability of being class 1 (Malicious)
        
        result = bool(prediction == 1)
        if result:
            logger.warning(f"Firewall BLOCKED: '{text}' (Confidence: {proba:.2f})")
        else:
            logger.info(f"Firewall ALLOWED: '{text}' (Confidence: {proba:.2f})")
            
        return result

# Singleton instance
firewall_model = FirewallModel()
