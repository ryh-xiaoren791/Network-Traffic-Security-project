from dataclasses import dataclass
from pathlib import Path


@dataclass
class AppConfig:
    app_name: str = "AI Windows 终端流量异常检测系统"
    host: str = "127.0.0.1"
    port: int = 17890
    refresh_seconds: int = 10
    baseline_fast_seconds: int = 30
    baseline_standard_seconds: int = 180
    session_timeout_seconds: int = 60
    db_path: Path = Path("data/system.db")
    model_path: Path = Path("models/iforest_model.joblib")
    capture_batch_size: int = 400
    capture_batch_timeout: float = 0.2
    offline_mode_default: str = "balanced"
    offline_packet_query_limit: int = 5000
    offline_use_duckdb: bool = True
    offline_duckdb_path: Path = Path("data/offline_packets.duckdb")
    offline_batch_size: int = 5000
    offline_raw_hex_preview_bytes: int = 0
    offline_store_raw_hex: bool = False
    offline_store_packets: bool = False
    offline_enable_app_meta: bool = False
    offline_enable_detection: bool = False
    offline_balanced_batch_size: int = 4000
    offline_balanced_raw_hex_preview_bytes: int = 128
    offline_balanced_store_raw_hex: bool = True
    offline_balanced_store_packets: bool = True
    offline_balanced_enable_app_meta: bool = True
    offline_balanced_enable_detection: bool = True
    offline_balanced_cpu_limit_percent: int = 70
    offline_balanced_commit_interval_batches: int = 16
    offline_balanced_detection_flush_interval_batches: int = 2
    offline_speed_batch_size: int = 5000
    offline_speed_raw_hex_preview_bytes: int = 0
    offline_speed_store_raw_hex: bool = False
    offline_speed_store_packets: bool = False
    offline_speed_enable_app_meta: bool = False
    offline_speed_enable_detection: bool = False
    offline_detect_batch_size: int = 3000
    offline_detect_raw_hex_preview_bytes: int = 256
    offline_detect_store_raw_hex: bool = True
    offline_detect_store_packets: bool = True
    offline_detect_enable_app_meta: bool = True
    offline_detect_enable_detection: bool = True
    offline_extreme_batch_size: int = 7000
    offline_extreme_raw_hex_preview_bytes: int = 8
    offline_extreme_store_raw_hex: bool = True
    offline_extreme_store_packets: bool = True
    offline_extreme_enable_app_meta: bool = True
    offline_extreme_enable_detection: bool = False
    offline_extreme_cpu_limit_percent: int = 0
    offline_extreme_commit_interval_batches: int = 64
    offline_extreme_detection_flush_interval_batches: int = 8
    offline_defer_secondary_indexes: bool = True
    sqlite_retention_days: int = 30
    default_admin_username: str = "admin"
    default_admin_password: str = "Admin@123456"
    default_guest_username: str = "user"
    default_guest_password: str = "User@123456"


CONFIG = AppConfig()
