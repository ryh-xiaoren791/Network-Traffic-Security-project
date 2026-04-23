from pathlib import Path

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
        self._load_or_init()

    def _load_or_init(self) -> None:
        if self.model_path.exists():
            payload = joblib.load(self.model_path)
            self.scaler = payload["scaler"]
            self.model = payload["model"]
            self._fitted = True

    def train(self, X: np.ndarray) -> None:
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        self._fitted = True
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"scaler": self.scaler, "model": self.model}, self.model_path)

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self._fitted:
            self.train(X)
        Xs = self.scaler.transform(X)
        raw = self.model.decision_function(Xs)
        return -raw
