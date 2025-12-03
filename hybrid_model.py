import pandas as pd
import numpy as np
import pickle

# Load testing dataset
df = pd.read_csv("Friday-WorkingHours_labeled2.csv")
#df = pd.read_csv("cic_ids_2017_missing.csv")

#features extracted
features = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Flow Bytes/s', 'Flow Packets/s'
]

X = df[features].replace([np.inf, -np.inf], np.nan).fillna(0)


print("Loading models...")
with open("model_supervised_2.pkl", "rb") as f: #model_supervised_2 exludes some attack flows for testing
    xgb, _ = pickle.load(f)

with open("model_unsupervised.pkl", "rb") as f:
    iso_forest, scaler, _ = pickle.load(f)

#XGBoost probability
xgb_prob = xgb.predict_proba(X)[:, 1]  #0 to 1 = benign to attack

#Isolation forest probability
X_scaled = scaler.transform(X)
raw_scores = iso_forest.decision_function(X_scaled)      # negative = anomaly
# Convert to probability 0–1 (higher = more anomalous)
unsup_prob = 1 / (1 + np.exp(raw_scores * 10))

# weighted avergage of confidence levels
df['hybrid_score'] = (1/3*xgb_prob + 2/3*unsup_prob) / 1
df['hybrid_anomaly'] = df['hybrid_score'] > 0.25    


print("\n" + "="*80)
print("           ML NETWORK INTRUSION DETECTION SYSTEM")
print("="*80)

for attack in ['BENIGN', 'DoS', 'Web Attack', 'PortScan', 'DoS Hulk', 'DoS slowhttptest', 'Infiltration']:
    subset = df[df['Label'] == attack]
    if len(subset) == 0:
        continue
    xgb_det = (xgb_prob[subset.index] > 0.5).mean() * 100
    iso_det = (unsup_prob[subset.index] > 0.3).mean() * 100
    hybrid_det = subset['hybrid_anomaly'].mean() * 100

    print(f"{attack:25} | Flows: {len(subset):7,} | "
          f"XGBoost: {xgb_det:6.2f}% | IsolationForest: {iso_det:6.2f}% | HYBRID: {hybrid_det:6.2f}%")

# Final stats
benign_fp = df[df['Label'] == 'BENIGN']['hybrid_anomaly'].mean() * 100
overall_dr = df[df['Label'] != 'BENIGN']['hybrid_anomaly'].mean() * 100

print(f"\nOVERALL ATTACK DETECTION RATE (Hybrid): {overall_dr:.2f}%")
print(f"BENIGN FALSE POSITIVE RATE (Hybrid)   : {benign_fp:.4f}%")
print("="*80)