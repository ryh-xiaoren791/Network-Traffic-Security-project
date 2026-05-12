from pathlib import Path
from datetime import datetime

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class ModelEngine:
    def __init__(self, model_path: Path) -> None:
        self.model_path = model_path
        self.scaler = StandardScaler()
        self.model = IsolationForest(n_estimators=120, contamination=0.05, random_state=42)
        self._fitted = False
        self.metadata: dict[str, object] = {}
        self._load_or_init()

    def _load_or_init(self) -> None:
        if self.model_path.exists():
            payload = joblib.load(self.model_path)
            self.scaler = payload["scaler"]
            self.model = payload["model"]
            self.metadata = dict(payload.get("metadata") or {})
            self._fitted = bool(self.metadata.get("is_fitted", True))

    def can_score_live(self) -> bool:
        return self._fitted and str(self.metadata.get("trained_from", "")) == "real_traffic"

    def train(self, X: np.ndarray, *, trained_from: str = "real_traffic") -> None:
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        self._fitted = True
        self.metadata = {
            "trained_from": trained_from,
            "trained_at": datetime.now().isoformat(timespec="seconds"),
            "sample_count": int(len(X)),
            "feature_count": int(X.shape[1]) if getattr(X, "ndim", 0) >= 2 else 0,
            "is_fitted": True,
        }
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"scaler": self.scaler, "model": self.model, "metadata": self.metadata}, self.model_path)

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self.can_score_live():
            return np.zeros((len(X),), dtype=float)
        Xs = self.scaler.transform(X)
        raw = self.model.decision_function(Xs)
        return -raw
