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

    def process(self, features: list[dict], source: str = "live", db_commit: bool = True) -> list[dict]:
        if not features:
            return []
        use_model = source != "offline"
        vectors = np.array([self._to_vector(f) for f in features], dtype=float) if use_model else None
        if self.in_learning():
            if vectors is not None:
                self.learning_features.extend(vectors.tolist())
            return []
        if use_model and self.learning_features:
            X = np.array(self.learning_features, dtype=float)
            self.model_engine.train(X)
            self.rule_engine.update_baseline(
                packet_rate_mean=float(np.mean(X[:, 5])),
                packet_rate_std=float(np.std(X[:, 5])),
                conn_freq_mean=float(np.mean(X[:, 6])),
                conn_freq_std=float(np.std(X[:, 6])),
            )
            self.learning_features.clear()
        scores = self.model_engine.score(vectors) if vectors is not None else np.zeros((len(features),), dtype=float)
        out: list[dict] = []
        alert_rows: list[tuple] = []
        classify_cache: dict[str, dict] = {}
        enable_tracker_lookup = source != "offline"
        for idx, f in enumerate(features):
            src_ip = str(f.get("src_ip", ""))
            if src_ip in classify_cache:
                list_result = classify_cache[src_ip]
            else:
                list_result = self.list_service.classify_target(src_ip, enable_tracker_lookup=enable_tracker_lookup)
                classify_cache[src_ip] = list_result
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
                rr = self.rule_engine.detect(f)
                model_score = float(scores[idx])
                level = rr["level"]
                is_loopback_pair = str(f.get("src_ip", "")).startswith("127.") and str(f.get("dst_ip", "")).startswith("127.")
                if use_model and model_score >= 0.3 and level != "high":
                    level = "medium"
                if use_model and model_score >= 0.55:
                    level = "high"
                category = rr["category"] if rr["matched"] else "访问与流量类"
                sub = rr["sub_category"] if rr["matched"] else "流量类型异常"
                reason = "；".join(rr["reasons"]) if rr["reasons"] else f"模型异常分数{model_score:.3f}"
                if is_loopback_pair and level == "high":
                    level = "medium"
                    category = "本机回环通信"
                    sub = "本地回环高频通信"
                    reason = f"{reason}；回环流量降级处理"
                should_alert = bool(rr["matched"]) or (use_model and model_score >= 0.55)
                if not should_alert:
                    continue
            is_offline = source == "offline"
            knowledge = {"type": "", "description": "", "mitigation": ""} if is_offline else get_attack_knowledge(sub)
            alert = {
                "ts": now_text(),
                "src_ip": f["src_ip"],
                "dst_ip": f["dst_ip"],
                "src_port": int(f.get("src_port", 0)),
                "dst_port": int(f.get("dst_port", 0)),
                "proto": str(f.get("proto", "")),
                "process_name": f.get("process_name", ""),
                "process_id": int(f.get("process_id", 0)),
                "category": category,
                "sub_category": sub,
                "level": level,
                "attack_type": knowledge["type"],
                "attack_desc": knowledge["description"],
                "mitigation": knowledge["mitigation"],
                "reason": reason,
                "score": float(scores[idx]),
                "source": source,
            }
            out.append(alert)
            alert_rows.append(
                (
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
            )
        if alert_rows:
            self._save_alert_rows(alert_rows, commit=db_commit)
        return out

    def _save_alert_rows(self, rows: list[tuple], commit: bool = True) -> None:
        c = self.db.conn.cursor()
        c.executemany(
            """
            INSERT INTO alerts(ts, src_ip, dst_ip, src_port, dst_port, proto, process_name, process_id, category, sub_category, level, attack_type, attack_desc, mitigation, reason, score, handled, source)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)
            """,
            rows,
        )
        if commit:
            self.db.conn.commit()
