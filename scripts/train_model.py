from pathlib import Path
from datetime import datetime

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def main() -> None:
    rng = np.random.default_rng(42)
    X = rng.normal(loc=0.0, scale=1.0, size=(5000, 12))
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = IsolationForest(n_estimators=120, contamination=0.05, random_state=42)
    model.fit(Xs)
    out = Path("models/iforest_model.joblib")
    out.parent.mkdir(parents=True, exist_ok=True)
    metadata = {
        "trained_from": "synthetic_bootstrap",
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "sample_count": int(len(X)),
        "feature_count": int(X.shape[1]),
        "is_fitted": True,
    }
    joblib.dump({"scaler": scaler, "model": model, "metadata": metadata}, out)
    print(f"bootstrap model saved: {out}")
    print("note: synthetic bootstrap models are not used for live alert escalation")


if __name__ == "__main__":
    main()
