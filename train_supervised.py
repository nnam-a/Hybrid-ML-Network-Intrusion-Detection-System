# 1. train_supervised_xgboost.py
from xgboost import XGBClassifier
import pandas as pd
import pickle
import numpy as np

df = pd.read_csv("cic_ids_2017_missing.csv")

# Binary label: BENIGN = 0, any attack = 1
df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)

features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
            'Flow Bytes/s', 'Flow Packets/s']

X = df[features].replace([np.inf, -np.inf], np.nan).fillna(0)
y = df['is_attack']

print("Training XGBoost (supervised) on all labeled data...")
model_xgb = XGBClassifier(
    n_estimators=800,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=10,          
    random_state=42,
    n_jobs=-1
)
model_xgb.fit(X, y)

with open("model_supervised_2.pkl", "wb") as f:
    pickle.dump((model_xgb, features), f)

print("XGBoost (supervised) saved → model_supervised_2.pkl")