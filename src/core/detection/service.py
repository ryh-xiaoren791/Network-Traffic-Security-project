from datetime import datetime
import hashlib
import ipaddress

import numpy as np

from src.core.detection.attack_knowledge import get_attack_knowledge
from src.core.detection.model_engine import ModelEngine
from src.core.detection.rule_engine import RuleEngine
from src.core.storage.db import Database, now_text
from src.core.whitelist_blacklist.service import ListService

IP_BUCKETS = 1000
MIN_MODEL_TRAIN_SAMPLES = 256


class DetectionService:
    def __init__(self, db: Database, list_service: ListService, model_engine: ModelEngine, rule_engine: RuleEngine) -> None:
        self.db = db
        self.list_service = list_service
        self.model_engine = model_engine
        self.rule_engine = rule_engine
        self.learning_until = 0.0
        self.learning_features: list[list[float]] = []

    @staticmethod
    def _to_vector(f: dict) -> list[float]:
        proto_map = {"TCP": 1, "UDP": 2, "ICMP": 3}
        return [
            DetectionService._ip_to_bucket(f.get("src_ip", "")),
            DetectionService._ip_to_bucket(f.get("dst_ip", "")),
            float(f["src_port"]),
            float(f["dst_port"]),
            float(proto_map.get(f["proto"], 0)),
            float(f["packet_rate"]),
            float(f["conn_freq"]),
            float(f["port_visits"]),
            float(f["session_duration"]),
            float(f["req_interval"]),
            float(f["conn_success_rate"]),
            float(f["avg_pkt_size"]),
        ]

    @staticmethod
    def _ip_to_bucket(ip_value: str) -> float:
        try:
            return float(int(ipaddress.ip_address(str(ip_value))) % IP_BUCKETS)
        except ValueError:
            digest = hashlib.blake2b(str(ip_value).encode("utf-8"), digest_size=8).digest()
            return float(int.from_bytes(digest, "big") % IP_BUCKETS)

    def start_learning(self, seconds: int) -> None:
        self.learning_until = datetime.now().timestamp() + seconds
        self.learning_features.clear()

    def in_learning(self) -> bool:
        return datetime.now().timestamp() < self.learning_until

    def learning_remaining_seconds(self) -> int:
        return max(0, int(self.learning_until - datetime.now().timestamp()))

    def _build_vectors(self, features: list[dict], use_model: bool):
        if not use_model:
            return None
        return np.array([self._to_vector(f) for f in features], dtype=float)

    def _consume_learning_window(self, vectors) -> bool:
        if not self.in_learning():
            return False
        if vectors is not None:
            self.learning_features.extend(vectors.tolist())
        return True

    def _train_learning_buffer_if_needed(self, use_model: bool) -> None:
        if not use_model or len(self.learning_features) < MIN_MODEL_TRAIN_SAMPLES:
            return
        X = np.array(self.learning_features, dtype=float)
        self.model_engine.train(X, trained_from="real_traffic")
        self.rule_engine.update_baseline(
            packet_rate_mean=float(np.mean(X[:, 5])),
            packet_rate_std=float(np.std(X[:, 5])),
            conn_freq_mean=float(np.mean(X[:, 6])),
            conn_freq_std=float(np.std(X[:, 6])),
        )
        self.learning_features.clear()

    def _score_features(self, features: list[dict], vectors, use_model: bool) -> tuple[bool, np.ndarray]:
        live_model_ready = bool(use_model and self.model_engine.can_score_live())
        if vectors is not None and live_model_ready:
            return True, self.model_engine.score(vectors)
        return live_model_ready, np.zeros((len(features),), dtype=float)

    def _classify_feature_target(
        self,
        feature: dict,
        classify_cache: dict[str, dict],
        enable_tracker_lookup: bool,
    ) -> dict:
        src_ip = str(feature.get("src_ip", ""))
        if src_ip not in classify_cache:
            classify_cache[src_ip] = self.list_service.classify_target(src_ip, enable_tracker_lookup=enable_tracker_lookup)
        return classify_cache[src_ip]

    def _evaluate_detection_result(self, feature: dict, model_score: float, live_model_ready: bool) -> tuple[str, str, str, str] | None:
        rr = self.rule_engine.detect(feature)
        level = rr["level"]
        is_loopback_pair = str(feature.get("src_ip", "")).startswith("127.") and str(feature.get("dst_ip", "")).startswith("127.")
        if live_model_ready and model_score >= 0.3 and level != "high":
            level = "medium"
        if live_model_ready and model_score >= 0.55:
            level = "high"
        category = rr["category"] if rr["matched"] else "访问与流量类"
        sub = rr["sub_category"] if rr["matched"] else "流量类型异常"
        reason = "；".join(rr["reasons"]) if rr["reasons"] else f"模型异常分数{model_score:.3f}"
        if is_loopback_pair and level == "high":
            level = "medium"
            category = "本机回环通信"
            sub = "本地回环高频通信"
            reason = f"{reason}；回环流量降级处理"
        should_alert = bool(rr["matched"]) or (live_model_ready and model_score >= 0.55)
        if not should_alert:
            return None
        return level, category, sub, reason

    def _build_alert(self, feature: dict, source: str, level: str, category: str, sub: str, reason: str, score: float) -> dict:
        is_offline = source == "offline"
        knowledge = {"type": "", "description": "", "mitigation": ""} if is_offline else get_attack_knowledge(sub)
        return {
            "ts": now_text(),
            "src_ip": feature["src_ip"],
            "dst_ip": feature["dst_ip"],
            "src_port": int(feature.get("src_port", 0)),
            "dst_port": int(feature.get("dst_port", 0)),
            "proto": str(feature.get("proto", "")),
            "process_name": feature.get("process_name", ""),
            "process_id": int(feature.get("process_id", 0)),
            "category": category,
            "sub_category": sub,
            "level": level,
            "attack_type": knowledge["type"],
            "attack_desc": knowledge["description"],
            "mitigation": knowledge["mitigation"],
            "reason": reason,
            "score": float(score),
            "source": source,
        }

    @staticmethod
    def _alert_to_row(alert: dict) -> tuple:
        return (
            alert["ts"],
            alert["src_ip"],
            alert["dst_ip"],
            alert.get("src_port", 0),
            alert.get("dst_port", 0),
            alert.get("proto", ""),
            alert.get("process_name", ""),
            alert.get("process_id", 0),
            alert["category"],
            alert["sub_category"],
            alert["level"],
            alert.get("attack_type", ""),
            alert.get("attack_desc", ""),
            alert.get("mitigation", ""),
            alert["reason"],
            alert["score"],
            alert.get("source", "live"),
        )

    def process(self, features: list[dict], source: str = "live", db_commit: bool = True) -> list[dict]:
        if not features:
            return []
        use_model = source != "offline"
        vectors = self._build_vectors(features, use_model)
        if self._consume_learning_window(vectors):
            return []
        self._train_learning_buffer_if_needed(use_model)
        live_model_ready, scores = self._score_features(features, vectors, use_model)
        out: list[dict] = []
        alert_rows: list[tuple] = []
        classify_cache: dict[str, dict] = {}
        enable_tracker_lookup = source != "offline"
        for idx, feature in enumerate(features):
            list_result = self._classify_feature_target(feature, classify_cache, enable_tracker_lookup)
            list_type = list_result["list_type"]
            if list_type == "white":
                continue
            if list_type == "black":
                if list_result["source"] == "privacy_tracker":
                    level = "medium"
                    category, sub, reason = "隐私与追踪防护", "隐私追踪拦截", list_result["remark"]
                else:
                    level = "high"
                    category, sub, reason = "安全策略与权限类", "策略违规操作", "命中黑名单"
            else:
                detected = self._evaluate_detection_result(feature, float(scores[idx]), live_model_ready)
                if detected is None:
                    continue
                level, category, sub, reason = detected
            alert = self._build_alert(feature, source, level, category, sub, reason, float(scores[idx]))
            out.append(alert)
            alert_rows.append(self._alert_to_row(alert))
        if alert_rows:
            self._save_alert_rows(alert_rows, out, commit=db_commit)
        return out

    def _save_alert_rows(self, rows: list[tuple], alerts: list[dict] | None = None, commit: bool = True) -> None:
        c = self.db.conn.cursor()
        c.executemany(
            """
            INSERT INTO alerts(ts, src_ip, dst_ip, src_port, dst_port, proto, process_name, process_id, category, sub_category, level, attack_type, attack_desc, mitigation, reason, score, handled, source)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)
            """,
            rows,
        )
        if alerts:
            self.db.upsert_flow_risk_summary(alerts, commit=False)
        if commit:
            self.db.conn.commit()
