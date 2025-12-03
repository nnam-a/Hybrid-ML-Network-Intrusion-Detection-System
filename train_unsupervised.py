from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import pickle
import numpy as np

# Load only Monday
try:
    df_benign = pd.read_csv("monday_clean.csv")
except:
    df = pd.read_csv("cic_ids_2017_full.csv")
    df_benign = df[df['Label'] == 'BENIGN']

features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Flow Bytes/s', 'Flow Packets/s'
]


X_benign = df_benign[features].replace([np.inf, -np.inf], np.nan).fillna(0)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_benign)

print("Training Isolation Forest (1000 trees, contamination=0.001)...")
model = IsolationForest(
    n_estimators=1000,
    contamination=0.001,      # expect 0.1 % anomalies in benign
    random_state=42,
    n_jobs=-1,         
)
model.fit(X_scaled)

with open("model_unsupervised.pkl", "wb") as f:
    pickle.dump((model, scaler, features), f)