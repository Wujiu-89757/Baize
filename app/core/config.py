"""全局配置。所有值均可通过环境变量覆盖（BAIZE_ 前缀）。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # 项目根目录


def _env(name: str, default: str) -> str:
    return os.environ.get(f"BAIZE_{name}", default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(f"BAIZE_{name}", str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(f"BAIZE_{name}", str(default)))
    except ValueError:
        return default


@dataclass
class Settings:
    # --- 应用 ---
    app_name: str = "白泽流量分析平台"
    version: str = "0.1"
    engine_version: str = "baize-engine-0.1"
    debug: bool = _env("DEBUG", "false").lower() == "true"

    # --- 路径 ---
    base_dir: Path = BASE_DIR
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", str(BASE_DIR / "data"))))
    upload_dir: Path = field(default_factory=lambda: Path(_env("UPLOAD_DIR", str(BASE_DIR / "data" / "uploads"))))
    storage_dir: Path = field(default_factory=lambda: Path(_env("STORAGE_DIR", str(BASE_DIR / "data" / "storage"))))
    report_dir: Path = field(default_factory=lambda: Path(_env("REPORT_DIR", str(BASE_DIR / "data" / "reports"))))
    strategy_dir: Path = field(default_factory=lambda: Path(_env("STRATEGY_DIR", str(BASE_DIR / "strategies"))))

    # --- 数据库 ---
    db_url: str = _env("DB_URL", f"sqlite:///{BASE_DIR / 'data' / 'baize.db'}")

    # --- 上传 ---
    # 默认 512 MB：解析链当前会一次性把所有包载入内存，2 GB 上传字节上限未经基准验证，
    # 不宜承诺可处理 2 GB。可通过 BAIZE_MAX_UPLOAD_SIZE 调整。
    max_upload_size: int = _env_int("MAX_UPLOAD_SIZE", 512 * 1024 * 1024)
    allowed_extensions: tuple = (".pcap", ".pcapng")

    # --- 评分 (文档 8.4) ---
    severity_multipliers: dict = field(default_factory=lambda: {
        "info": 0.25, "low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0,
    })
    score_normalization_cap: float = _env_float("SCORE_CAP", 200.0)   # 原始分求和上限
    per_strategy_score_cap: float = _env_float("STRATEGY_SCORE_CAP", 100.0)

    # --- 正则安全 (文档 6.4) ---
    regex_max_length: int = _env_int("REGEX_MAX_LENGTH", 200)
    regex_timeout_seconds: float = _env_float("REGEX_TIMEOUT", 1.0)

    # --- 分析任务 ---
    worker_concurrency: int = _env_int("WORKER_CONCURRENCY", 2)
    task_retry_limit: int = _env_int("TASK_RETRY_LIMIT", 2)
    syn_scan_windows: tuple = (1, 10, 60, 300)  # 文档 6.2.1: 窗口不应写死

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.upload_dir, self.storage_dir, self.report_dir):
            d.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()
