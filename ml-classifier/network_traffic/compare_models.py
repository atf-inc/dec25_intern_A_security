import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import time

# ML Libraries
import xgboost as xgb
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import LinearSVC
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Deep Learning Libraries
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten, Dropout, LSTM

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRAIN_PATH = os.path.join(BASE_DIR, 'data', 'UNSW_NB15_training-set.csv')
TEST_PATH = os.path.join(BASE_DIR, 'data', 'UNSW_NB15_testing-set.csv')

# Plotting Style
sns.set_style("whitegrid")
plt.rcParams['font.family'] = 'sans-serif'

def run_comparison():
    print("="*60)
    print("🚀 MODEL COMPARISON SUITE (NB, SVM, XGB, LSTM, CNN)")
    print("="*60)

    # --- 1. LOAD & PREPROCESS DATA ---
    print(">>> Loading Data...")
    try:
        df1 = pd.read_csv(TRAIN_PATH)
        df2 = pd.read_csv(TEST_PATH)
        full_df = pd.concat([df1, df2], axis=0)
    except FileNotFoundError:
        print("❌ Error: CSV files not found. Check 'data' folder.")
        return

    # Drop ID and extra labels
    drop_cols = [c for c in ['id', 'attack_cat'] if c in full_df.columns]
    X = full_df.drop(columns=drop_cols + ['label'])
    y = full_df['label']

    # Encode Strings
    for col in X.select_dtypes(include=['object']).columns:
        X[col] = LabelEncoder().fit_transform(X[col].astype(str))

    # Scale Numbers
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    # Split (80% Train, 20% Test) - Ensuring Fair Comparison
    print(">>> Splitting Data (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Reshape for Deep Learning (Samples, Features, 1)
    X_train_dl = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
    X_test_dl = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)

    results = {}
    print(f"Training on {len(X_train)} samples, Testing on {len(X_test)} samples.\n")

    # --- 2. NAIVE BAYES ---
    print(f"[{'Naive Bayes':<15}] Training...")
    nb_model = GaussianNB()
    nb_model.fit(X_train, y_train)
    results['Naive Bayes'] = accuracy_score(y_test, nb_model.predict(X_test))
    print(f"   > Accuracy: {results['Naive Bayes']:.2%}")

    # --- 3. SVM (Linear) ---
    print(f"[{'SVM':<15}] Training (this might take a moment)...")
    svm_model = LinearSVC(dual=False)
    svm_model.fit(X_train, y_train)
    results['SVM'] = accuracy_score(y_test, svm_model.predict(X_test))
    print(f"   > Accuracy: {results['SVM']:.2%}")

    # --- 4. XGBOOST ---
    print(f"[{'XGBoost':<15}] Training...")
    xgb_model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
    xgb_model.fit(X_train, y_train)
    results['XGBoost'] = accuracy_score(y_test, xgb_model.predict(X_test))
    print(f"   > Accuracy: {results['XGBoost']:.2%}")

    # --- 5. LSTM ---
    print(f"[{'LSTM':<15}] Training (Deep Learning)...")
    lstm = Sequential([
        LSTM(64, input_shape=(X_train_dl.shape[1], 1)),
        Dropout(0.2),
        Dense(1, activation='sigmoid')
    ])
    lstm.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    # Training for just 2 epochs for demonstration speed
    lstm.fit(X_train_dl, y_train, epochs=2, batch_size=128, verbose=0)
    
    lstm_preds = (lstm.predict(X_test_dl, verbose=0) > 0.5).astype(int).flatten()
    results['LSTM'] = accuracy_score(y_test, lstm_preds)
    print(f"   > Accuracy: {results['LSTM']:.2%}")

    # --- 6. 1D-CNN ---
    print(f"[{'1D-CNN':<15}] Training (Deep Learning)...")
    cnn = Sequential([
        Conv1D(64, 3, activation='relu', input_shape=(X_train_dl.shape[1], 1)),
        MaxPooling1D(2),
        Flatten(),
        Dense(50, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    cnn.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    cnn.fit(X_train_dl, y_train, epochs=2, batch_size=128, verbose=0)
    
    cnn_preds = (cnn.predict(X_test_dl, verbose=0) > 0.5).astype(int).flatten()
    results['1D-CNN'] = accuracy_score(y_test, cnn_preds)
    print(f"   > Accuracy: {results['1D-CNN']:.2%}")

    # --- 7. VISUALIZATION ---
    print("\n>>> Generating Comparison Plot...")
    result_df = pd.DataFrame(list(results.items()), columns=['Model', 'Accuracy'])
    result_df = result_df.sort_values(by='Accuracy', ascending=False)

    plt.figure(figsize=(10, 6))
    ax = sns.barplot(x='Model', y='Accuracy', data=result_df, palette='viridis')
    plt.ylim(0.7, 1.0)
    plt.title('Network Intrusion Detection Model Comparison', fontsize=15)
    plt.ylabel('Accuracy Score')

    for p in ax.patches:
        ax.annotate(f'{p.get_height():.2%}',
                    (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='center',
                    xytext=(0, 9),
                    textcoords='offset points',
                    fontweight='bold')
    
    plt.tight_layout()
    plt.show() # This will open a popup window with the graph

if __name__ == "__main__":
    run_comparison()