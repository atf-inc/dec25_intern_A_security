import pandas as pd
import numpy as np
import xgboost as xgb
import joblib
import os
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAIN_PATH = os.path.join(BASE_DIR, 'data', 'UNSW_NB15_training-set.csv')
TEST_PATH = os.path.join(BASE_DIR, 'data', 'UNSW_NB15_testing-set.csv')
MODEL_DIR = os.path.join(BASE_DIR, 'model')

if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)

def train_ids_model():
    print("\n" + "="*50)
    print(">>> 1. LOADING & COMBINING DATASETS")
    print("="*50)
    try:
        # Load both provided files
        df1 = pd.read_csv(TRAIN_PATH)
        df2 = pd.read_csv(TEST_PATH)
        print(f"File 1 loaded: {len(df1)} rows")
        print(f"File 2 loaded: {len(df2)} rows")
    except FileNotFoundError:
        print(f"❌ Error: CSV files not found in {os.path.join(BASE_DIR, 'data')}")
        return

    # Combine them into one big dataset
    full_df = pd.concat([df1, df2], axis=0)
    print(f"Total Data: {len(full_df)} rows")

    # Clean Data
    drop_cols = [c for c in ['id', 'attack_cat'] if c in full_df.columns]
    X = full_df.drop(columns=drop_cols + ['label'])
    y = full_df['label']

    print("\n>>> 2. PREPROCESSING")
    
    # A. Encode Categorical Strings
    encoders = {}
    for col in X.select_dtypes(include=['object']).columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        encoders[col] = le
    
    # Save Encoders
    joblib.dump(encoders, os.path.join(MODEL_DIR, 'label_encoders.pkl'))

    # B. Scale Numbers (0 to 1)
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Save Scaler
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))

    # --- THE CRITICAL FIX ---
    # Randomly split the combined data: 80% for Training, 20% for Testing
    # This ensures the model sees a mix of all traffic types during training
    print("\n>>> 3. SPLITTING DATA (80/20)")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training set: {len(X_train)}")
    print(f"Testing set:  {len(X_test)}")

    # --- TRAIN XGBOOST ---
    print("\n>>> 4. TRAINING XGBOOST (High Accuracy Mode)...")
    # Using slightly more aggressive parameters to match your original results
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,          # More trees
        learning_rate=0.1,         # Standard learning rate
        max_depth=10,              # Deeper trees to capture complex patterns
        use_label_encoder=False, 
        eval_metric='logloss',
        n_jobs=-1                  # Use all CPU cores
    )
    xgb_model.fit(X_train, y_train)

    # --- EVALUATE ---
    print("\n>>> 5. EVALUATION")
    preds = xgb_model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    
    print("-" * 30)
    print(f"🏆 FINAL ACCURACY: {acc:.2%}")
    print("-" * 30)
    print(classification_report(y_test, preds, target_names=['Safe', 'Malicious']))

    # --- SAVE MODEL ---
    model_save_path = os.path.join(MODEL_DIR, 'xgboost_model.json')
    xgb_model.save_model(model_save_path)
    print(f"\n💾 Model saved successfully to: {model_save_path}")

if __name__ == "__main__":
    train_ids_model()