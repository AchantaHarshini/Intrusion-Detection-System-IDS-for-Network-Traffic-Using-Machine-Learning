from flask import Flask, request, jsonify, render_template,redirect
from flask_cors import CORS
import pandas as pd
import numpy as np
import os, math
from datetime import datetime
import joblib

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
LAST_UPLOADED_FILE = None

# ================= SAFE LOAD =================
def load_file_safe(filename):
    if not os.path.exists(filename):
        raise Exception(f"❌ File not found: {filename}")
    print(f"✅ Loaded: {filename}")
    return joblib.load(filename)

# ================= LOAD MODEL FILES =================
try:
    model         = load_file_safe("ids_model.pkl")
    label_encoder = load_file_safe("label_encoder.pkl")

    raw_feature_names = load_file_safe("feature_names.pkl")
    if hasattr(raw_feature_names, "tolist"):
        feature_names = raw_feature_names.tolist()
    elif isinstance(raw_feature_names, list):
        feature_names = raw_feature_names
    else:
        feature_names = list(raw_feature_names)

    scaler   = load_file_safe("scaler.pkl")
    selector = load_file_safe("selector.pkl")

    scaler_feature_names = list(scaler.feature_names_in_) if hasattr(scaler, "feature_names_in_") else None

    print(f"ℹ️  Scaler expects : {len(scaler_feature_names) if scaler_feature_names else '?'} features")
    print(f"ℹ️  Model expects  : {len(feature_names)} features")
    print(f"ℹ️  Known classes  : {list(label_encoder.classes_)}")

except Exception as e:
    print(e)
    exit()

# ================= LABEL ALIAS MAP =================
# Maps any external label → the closest known class in label_encoder
# Add more aliases here if new datasets use different names
LABEL_ALIAS = {
    # BENIGN variants → whatever the encoder calls "normal"
    "benign":           None,   # auto-detected below
    "normal":           None,
    "normal traffic":   None,
    "background":       None,
    # Attack variants
    "ddos":             None,
    "dos":              None,
    "dos hulk":         None,
    "dos goldeneye":    None,
    "dos slowloris":    None,
    "dos slowhttptest": None,
    "heartbleed":       None,
    "ftp-patator":      None,
    "ssh-patator":      None,
    "brute force":      None,
    "bruteforce":       None,
    "web attack":       None,
    "web attacks":      None,
    "infiltration":     None,
    "botnet":           None,
    "portscan":         None,
    "port scanning":    None,
    "port scan":        None,
}

def build_alias_map(known_classes):
    """
    Auto-build alias map by fuzzy-matching alias keys to known encoder classes.
    Normal/Benign aliases map to whichever known class looks like 'normal'.
    Attack aliases map to whichever known class looks like the attack name.
    """
    alias = {}
    known_lower = {k.lower().strip(): k for k in known_classes}

    # Find the "normal" class
    normal_class = None
    for k in known_classes:
        if "normal" in k.lower() or "benign" in k.lower():
            normal_class = k
            break
    if normal_class is None:
        normal_class = known_classes[0]  # fallback to first class

    print(f"ℹ️  Normal class identified as: '{normal_class}'")

    for raw_key in LABEL_ALIAS:
        # Try exact match first
        if raw_key in known_lower:
            alias[raw_key] = known_lower[raw_key]
            continue
        # Benign/normal → normal class
        if any(w in raw_key for w in ["benign", "normal", "background"]):
            alias[raw_key] = normal_class
            continue
        # Try partial match among known classes
        best = None
        for kl, kv in known_lower.items():
            if raw_key in kl or kl in raw_key:
                best = kv
                break
        alias[raw_key] = best if best else None

    return alias, normal_class

ALIAS_MAP, NORMAL_CLASS = build_alias_map(list(label_encoder.classes_))
print(f"ℹ️  Alias map built: {ALIAS_MAP}")

# ================= SANITIZE for JSON =================
def sanitize(obj):
    if isinstance(obj, float):
        return None if (math.isnan(obj) or math.isinf(obj)) else obj
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(v) for v in obj]
    if isinstance(obj, np.floating):
        v = float(obj)
        return None if (math.isnan(v) or math.isinf(v)) else v
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.ndarray):
        return sanitize(obj.tolist())
    return obj

# ================= CLEAN DATAFRAME =================
def clean_dataframe(df):
    df = df.copy()
    df.columns = df.columns.str.strip()
    for col in df.columns:
        if df[col].dtype == object:
            try:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            except:
                pass
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    float64_max  = np.finfo(np.float64).max / 2
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].clip(-float64_max, float64_max)
    df[numeric_cols] = df[numeric_cols].fillna(0)
    print(f"✅ Data cleaned — shape: {df.shape}")
    return df

# ================= SMART LABEL MAP =================
def map_label(x, known_classes, alias_map, normal_class):
    """
    Maps any incoming label to a known encoder class.
    Priority: exact → alias map → case-insensitive → partial → normal fallback
    """
    x_clean = str(x).strip()
    x_lower = x_clean.lower()

    # 1. Exact match
    if x_clean in known_classes:
        return x_clean

    # 2. Alias map (pre-built fuzzy map)
    if x_lower in alias_map and alias_map[x_lower] is not None:
        return alias_map[x_lower]

    # 3. Case-insensitive exact
    known_lower_map = {k.lower(): k for k in known_classes}
    if x_lower in known_lower_map:
        return known_lower_map[x_lower]

    # 4. Partial substring match
    for kl, kv in known_lower_map.items():
        if x_lower in kl or kl in x_lower:
            return kv

    # 5. Benign/normal heuristic — if label contains "benign" or "normal" → normal class
    if any(w in x_lower for w in ["benign", "normal", "background", "legitimate"]):
        print(f"  ℹ️  '{x_clean}' → normal class '{normal_class}'")
        return normal_class

    # 6. Last resort — normal class (so metrics aren't broken)
    print(f"  ⚠️  No match for '{x_clean}' → defaulting to '{normal_class}'")
    return normal_class

# ================= HOME =================
@app.route("/")
def home():
    return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return redirect("/user")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        return redirect("/")
    return render_template("register.html")


@app.route("/user")
def user():
    return render_template("user-dashboard.html")


@app.route("/admin")
def admin():
    return render_template("admin-dashboard.html")
# ================= UPLOAD =================
@app.route("/upload", methods=["POST"])
def upload():
    global LAST_UPLOADED_FILE
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file     = request.files["file"]
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    LAST_UPLOADED_FILE = filepath
    print("📁 Uploaded:", filepath)
    return jsonify({"message": "File uploaded successfully"})

# ================= PREDICT =================
@app.route("/predict", methods=["GET", "POST"])
def predict():
    global LAST_UPLOADED_FILE

    if not LAST_UPLOADED_FILE or not os.path.exists(LAST_UPLOADED_FILE):
        return jsonify({"error": "No dataset uploaded"}), 400

    try:
        print("\n========== NEW REQUEST ==========")
        print("📂 File:", LAST_UPLOADED_FILE)

        # ===== LOAD =====
        if LAST_UPLOADED_FILE.endswith(".csv"):
            df = pd.read_csv(LAST_UPLOADED_FILE, encoding="latin1")
        elif LAST_UPLOADED_FILE.endswith(".xlsx"):
            df = pd.read_excel(LAST_UPLOADED_FILE)
        else:
            return jsonify({"error": "Unsupported file format. Use .csv or .xlsx"}), 400

        df = clean_dataframe(df)
        print("📊 Columns:", df.columns.tolist())

        # ===== FIND LABEL COLUMN =====
        label_col = None
        for col in df.columns:
            cl = col.lower()
            if cl in ["label", "attack type", "attack_type"] or \
               "attack" in cl or "label" in cl:
                label_col = col
                break

        if label_col is None:
            return jsonify({"error": "Label column not found."}), 400

        print("✅ Label column:", label_col)

        # ===== MAP LABELS =====
        y_raw    = df[label_col].astype(str).str.strip()
        known    = list(label_encoder.classes_)

        unique_in_file = sorted(y_raw.unique())
        print(f"📋 Labels in file   : {unique_in_file}")
        print(f"📋 Known by encoder : {sorted(known)}")

        y_safe = y_raw.apply(lambda x: map_label(x, known, ALIAS_MAP, NORMAL_CLASS))

        print(f"📊 Mapped distribution:\n{y_safe.value_counts().to_string()}")

        # ✅ Verify all mapped labels are valid
        invalid = set(y_safe.unique()) - set(known)
        if invalid:
            return jsonify({"error": f"Label mapping failed for: {invalid}. Check label_encoder classes."}), 500

        y_true = label_encoder.transform(y_safe)

        # ===== FEATURES =====
        X = df.drop(columns=[label_col])
        X = X.select_dtypes(include=[np.number])

        if scaler_feature_names is not None:
            for col in scaler_feature_names:
                if col not in X.columns:
                    print(f"⚠️  Missing col → 0: {col}")
                    X[col] = 0
            X_for_scaler = X[scaler_feature_names]
        else:
            X_for_scaler = X

        X_for_scaler = X_for_scaler.replace([np.inf, -np.inf], np.nan).fillna(0)
        print(f"✅ Scaler input : {X_for_scaler.shape}")

        X_scaled   = scaler.transform(X_for_scaler)
        X_selected = selector.transform(X_scaled)
        print(f"✅ Post-select  : {X_selected.shape}")

        y_pred = model.predict(X_selected)

        # ===== METRICS =====
        acc  = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, average='weighted', zero_division=0)
        rec  = recall_score(y_true, y_pred, average='weighted', zero_division=0)
        f1   = f1_score(y_true, y_pred, average='weighted', zero_division=0)
        cm   = confusion_matrix(y_true, y_pred)

        print(f"📈 Accuracy={acc:.4f}  Precision={prec:.4f}  Recall={rec:.4f}  F1={f1:.4f}")

        # ===== ROC =====
        roc_data = None
        try:
            from sklearn.metrics import roc_curve, auc as sk_auc
            from sklearn.preprocessing import label_binarize

            n_classes = len(known)
            y_score   = model.predict_proba(X_selected) if hasattr(model, "predict_proba") else None

            if y_score is not None:
                if n_classes == 2:
                    fpr, tpr, _ = roc_curve(y_true, y_score[:, 1])
                    auc_val     = sk_auc(fpr, tpr)
                    roc_data    = [{"class": known[1],
                                    "fpr": [v if not math.isnan(v) else 0.0 for v in fpr.tolist()],
                                    "tpr": [v if not math.isnan(v) else 0.0 for v in tpr.tolist()],
                                    "auc": round(auc_val, 4) if not math.isnan(auc_val) else None}]
                else:
                    y_bin    = label_binarize(y_true, classes=list(range(n_classes)))
                    roc_data = []
                    for i, cls in enumerate(known):
                        if y_bin[:, i].sum() == 0: continue
                        fpr, tpr, _ = roc_curve(y_bin[:, i], y_score[:, i])
                        auc_val     = sk_auc(fpr, tpr)
                        roc_data.append({"class": cls,
                                         "fpr": [v if not math.isnan(v) else 0.0 for v in fpr.tolist()],
                                         "tpr": [v if not math.isnan(v) else 0.0 for v in tpr.tolist()],
                                         "auc": round(auc_val, 4) if not math.isnan(auc_val) else None})
        except Exception as re:
            print(f"⚠️  ROC skipped: {re}")

        # ===== DECODE & COUNT =====
        decoded      = label_encoder.inverse_transform(y_pred)
        attack_counts = pd.Series(decoded).value_counts().to_dict()

        # Identify normal count by the normal class name
        normal  = attack_counts.get(NORMAL_CLASS, 0)
        attacks = len(df) - normal

        present = sorted(set(y_true.tolist()) | set(y_pred.tolist()))
        class_names = label_encoder.inverse_transform(present).tolist()

        print("✅ Done")

        return jsonify(sanitize({
            "total_records":      len(df),
            "attacks_detected":   attacks,
            "normal_detected":    normal,
            "attack_types":       attack_counts,
            "metrics": {
                "accuracy":  round(acc,  4),
                "precision": round(prec, 4),
                "recall":    round(rec,  4),
                "f1":        round(f1,   4)
            },
            "confusion_matrix":   cm.tolist(),
            "class_names":        class_names,
            "roc_data":           roc_data,
            "label_distribution": y_safe.value_counts().to_dict(),
            "timestamp":          datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }))

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ================= RUN =================
if __name__ == "__main__":
    print("🚀 Running on http://127.0.0.1:5001")
    app.run(port=5001, debug=True)
