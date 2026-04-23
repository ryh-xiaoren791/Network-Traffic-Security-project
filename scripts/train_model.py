from pathlib import Path

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
    joblib.dump({"scaler": scaler, "model": model}, out)
    print(f"model saved: {out}")


if __name__ == "__main__":
    main()
