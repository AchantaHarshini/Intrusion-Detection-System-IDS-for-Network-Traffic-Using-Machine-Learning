import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from imblearn.over_sampling import SMOTE
import joblib

print("🔹 Loading raw CSV file...")

# ================= LOAD RAW CSV =================
raw = pd.read_csv(
    "cicids2017_cleaned.csv",
    header=None,
    engine="python"
)

print("Raw shape:", raw.shape)

# ================= SPLIT SINGLE COLUMN =================
df = raw[0].str.split(",", expand=True)
print("After split shape:", df.shape)

# ================= SET COLUMN NAMES =================
columns = [
    "Destination Port","Flow Duration","Total Fwd Packets",
    "Total Length of Fwd Packets","Fwd Packet Length Max",
    "Fwd Packet Length Min","Fwd Packet Length Mean",
    "Fwd Packet Length Std","Bwd Packet Length Max",
    "Bwd Packet Length Min","Bwd Packet Length Mean",
    "Bwd Packet Length Std","Flow Bytes/s","Flow Packets/s",
    "Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min",
    "Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max",
    "Fwd IAT Min","Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std",
    "Bwd IAT Max","Bwd IAT Min","Fwd Header Length",
    "Bwd Header Length","Fwd Packets/s","Bwd Packets/s",
    "Min Packet Length","Max Packet Length","Packet Length Mean",
    "Packet Length Std","Packet Length Variance",
    "FIN Flag Count","PSH Flag Count","ACK Flag Count",
    "Average Packet Size","Subflow Fwd Bytes",
    "Init_Win_bytes_forward","Init_Win_bytes_backward",
    "act_data_pkt_fwd","min_seg_size_forward",
    "Active Mean","Active Max","Active Min",
    "Idle Mean","Idle Max","Idle Min","Attack Type"
]

df.columns = columns
print("✅ Columns assigned correctly")

# ================= CREATE LABEL =================
df["Is_Attack"] = (df["Attack Type"] != "Normal Traffic").astype(int)

# ================= FEATURES & TARGET =================
X = df.drop(columns=["Attack Type", "Is_Attack"])
y = df["Is_Attack"]
# AFTER you create X (training features)
feature_names = X.columns.tolist()

joblib.dump(feature_names, "feature_names.joblib")
print("✅ Feature names saved")


# Convert all features to numeric
X = X.apply(pd.to_numeric, errors="coerce")
X = X.fillna(0)

print("✅ Numeric features count:", X.shape[1])

if X.shape[1] == 0:
    raise Exception("❌ No numeric features found – dataset invalid")

# ================= TRAIN TEST SPLIT =================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

# ================= SCALING =================
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# ================= HANDLE IMBALANCE =================
smote = SMOTE(random_state=42)
X_train, y_train = smote.fit_resample(X_train, y_train)

# ================= RANDOM FOREST (SAFE SETTINGS) =================
rf = RandomForestClassifier(
    n_estimators=50,   # 🔥 reduced to avoid freeze
    random_state=42,
    n_jobs=1           # 🔥 prevents KeyboardInterrupt
)

print("🚀 Training Random Forest model...")
rf.fit(X_train, y_train)

# ================= SAVE MODEL =================
joblib.dump(rf, "random_forest_model.joblib")
joblib.dump(scaler, "scaler.joblib")

print("✅ Model and scaler saved successfully")

# ================= EVALUATION =================
y_pred = rf.predict(X_test)

print("\n📊 MODEL PERFORMANCE")
print("Accuracy :", round(accuracy_score(y_test, y_pred), 4))
print("Precision:", round(precision_score(y_test, y_pred), 4))
print("Recall   :", round(recall_score(y_test, y_pred), 4))
print("F1 Score :", round(f1_score(y_test, y_pred), 4))

print("\n🎉 TRAINING COMPLETE — PROJECT BACKEND READY")
