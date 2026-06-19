"""
InstaGuard - 共享工具模块

提供配置管理、哈希工具、日志记录、APK 文件操作等基础功能。
所有模块通过本文件共享基础设施。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import json
import hashlib
import logging
import tempfile
import shutil
import zipfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
from threading import Lock

# ─── Constants ────────────────────────────────────────────────────────────────

APP_NAME = "InstaGuard"
APP_VERSION = "1.0.0"

# Default paths (relative to app data directory)
CONFIG_DIR: str = ""
CACHE_DIR: str = ""
DB_DIR: str = ""

# Database file paths (set by init_paths)
MEMORY_DB_PATH: str = ""
EXPERIENCE_DB_PATH: str = ""
CONFIG_FILE_PATH: str = ""


def init_paths(base_dir: Optional[str] = None) -> None:
    """
    初始化全局路径。Android 上使用 app 私有目录，桌面使用 ~/.instaguard/。

    Args:
        base_dir: 可选的基础目录，None 则自动检测
    """
    global CONFIG_DIR, CACHE_DIR, DB_DIR
    global MEMORY_DB_PATH, EXPERIENCE_DB_PATH, CONFIG_FILE_PATH

    if base_dir is None:
        # 尝试使用 Kivy 的 user_data_dir
        try:
            from kivy.utils import platform
            if platform == "android":
                from android.storage import app_storage_path
                base_dir = app_storage_path()
            else:
                base_dir = os.path.join(str(Path.home()), ".instaguard")
        except ImportError:
            base_dir = os.path.join(str(Path.home()), ".instaguard")

    CONFIG_DIR = base_dir
    CACHE_DIR = os.path.join(base_dir, "cache")
    DB_DIR = os.path.join(base_dir, "db")

    for d in [CONFIG_DIR, CACHE_DIR, DB_DIR]:
        os.makedirs(d, exist_ok=True)

    MEMORY_DB_PATH = os.path.join(DB_DIR, "memory.db")
    EXPERIENCE_DB_PATH = os.path.join(DB_DIR, "experience.db")
    CONFIG_FILE_PATH = os.path.join(CONFIG_DIR, "config.json")


# ─── Logging ──────────────────────────────────────────────────────────────────

class Logger:
    """统一日志管理，支持文件和控制台输出。"""

    _instance: Optional["Logger"] = None
    _lock: Lock = Lock()

    def __new__(cls) -> "Logger":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True

        self.logger = logging.getLogger(APP_NAME)
        self.logger.setLevel(logging.DEBUG)

        # 控制台 handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter(
            "[%(levelname)s] %(asctime)s - %(message)s",
            datefmt="%H:%M:%S"
        ))
        self.logger.addHandler(ch)

        # 文件 handler（延迟添加，等路径初始化）
        self._file_handler: Optional[logging.FileHandler] = None

    def setup_file_logging(self, log_dir: Optional[str] = None) -> None:
        """添加文件日志输出。"""
        if self._file_handler:
            return
        d = log_dir or os.path.join(CONFIG_DIR, "logs") if CONFIG_DIR else tempfile.gettempdir()
        os.makedirs(d, exist_ok=True)
        log_file = os.path.join(d, f"instaguard_{datetime.now():%Y%m%d}.log")
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s"
        ))
        self.logger.addHandler(fh)
        self._file_handler = fh
        self.info(f"日志文件: {log_file}")

    def debug(self, msg: str, *args: Any) -> None:
        self.logger.debug(msg, *args)

    def info(self, msg: str, *args: Any) -> None:
        self.logger.info(msg, *args)

    def warning(self, msg: str, *args: Any) -> None:
        self.logger.warning(msg, *args)

    def error(self, msg: str, *args: Any) -> None:
        self.logger.error(msg, *args)

    def exception(self, msg: str, *args: Any) -> None:
        self.logger.exception(msg, *args)


log = Logger()


# ─── Config Manager ───────────────────────────────────────────────────────────

@dataclass
class ProviderConfig:
    """单个 AI 供应商配置。"""
    name: str                          # 供应商名称
    display_name: str = ""             # 显示名称
    default_endpoint: str = ""         # 默认 API 端点
    api_keys: List[str] = field(default_factory=list)  # API Key 列表（支持轮询）
    models: List[str] = field(default_factory=list)    # 可用模型列表
    active_model: str = ""             # 当前选中的模型
    enabled: bool = True               # 是否启用
    key_index: int = 0                 # 当前使用的 Key 索引（轮询）
    extra_headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 60                  # 请求超时（秒）

    def get_current_key(self) -> str:
        """获取当前轮询的 API Key。"""
        if not self.api_keys:
            return ""
        self.key_index = self.key_index % len(self.api_keys)
        key = self.api_keys[self.key_index]
        self.key_index += 1
        return key

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProviderConfig":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class Config:
    """
    JSON 配置文件管理器。支持界面修改和手动编辑。

    Usage:
        cfg = Config()
        cfg.load()
        providers = cfg.get_providers()
    """

    _instance: Optional["Config"] = None
    _lock: Lock = Lock()

    # 供应商默认端口映射表
    DEFAULT_PROVIDERS: Dict[str, Dict[str, Any]] = {
        "openai": {
            "display_name": "OpenAI",
            "default_endpoint": "https://api.openai.com/v1",
            "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        },
        "ollama": {
            "display_name": "Ollama",
            "default_endpoint": "http://localhost:11434/v1",
            "models": ["llama3", "mistral", "codellama", "gemma2"],
        },
        "anthropic": {
            "display_name": "Anthropic",
            "default_endpoint": "https://api.anthropic.com/v1",
            "models": ["claude-3-5-sonnet", "claude-3-opus", "claude-3-haiku"],
        },
        "deepseek": {
            "display_name": "DeepSeek",
            "default_endpoint": "https://api.deepseek.com/v1",
            "models": ["deepseek-chat", "deepseek-reasoner"],
        },
        "minimax": {
            "display_name": "MiniMax",
            "default_endpoint": "https://api.minimax.chat/v1",
            "models": ["abab6.5s-chat", "mimo"],
        },
        "glm": {
            "display_name": "智谱 GLM",
            "default_endpoint": "https://open.bigmodel.cn/api/paas/v4",
            "models": ["glm-4-plus", "glm-4-flash", "glm-4v-plus"],
        },
        "custom": {
            "display_name": "自定义",
            "default_endpoint": "",
            "models": [],
        },
    }

    def __new__(cls) -> "Config":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._loaded = False
        return cls._instance

    def __init__(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        self._data: Dict[str, Any] = {}
        self._providers: Dict[str, ProviderConfig] = {}

    def load(self, path: Optional[str] = None) -> None:
        """从 JSON 文件加载配置。"""
        filepath = path or CONFIG_FILE_PATH
        if filepath and os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
                # 解析供应商配置
                for name, pdata in self._data.get("providers", {}).items():
                    self._providers[name] = ProviderConfig.from_dict(pdata)
                log.info(f"配置已加载: {filepath}")
            except (json.JSONDecodeError, IOError) as e:
                log.warning(f"配置加载失败: {e}，使用默认配置")
                self._init_defaults()
        else:
            log.info("配置文件不存在，使用默认配置")
            self._init_defaults()

    def _init_defaults(self) -> None:
        """初始化默认配置（含所有预设供应商）。"""
        self._providers = {}
        for name, defaults in self.DEFAULT_PROVIDERS.items():
            self._providers[name] = ProviderConfig(
                name=name,
                display_name=defaults["display_name"],
                default_endpoint=defaults["default_endpoint"],
                models=defaults.get("models", []),
            )
        self._data["settings"] = {
            "memory_similarity_threshold": 0.85,
            "max_apk_size_mb": 500,
            "repair_backup_enabled": True,
            "voice_input_enabled": True,
            "language": "zh",
        }

    def save(self, path: Optional[str] = None) -> None:
        """保存配置到 JSON 文件。"""
        filepath = path or CONFIG_FILE_PATH
        if not filepath:
            log.error("配置路径未初始化")
            return
        self._data["providers"] = {n: p.to_dict() for n, p in self._providers.items()}
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
            log.info(f"配置已保存: {filepath}")
        except IOError as e:
            log.error(f"配置保存失败: {e}")

    def get_provider(self, name: str) -> Optional[ProviderConfig]:
        """获取指定供应商配置。"""
        return self._providers.get(name)

    def get_providers(self) -> Dict[str, ProviderConfig]:
        """获取所有供应商配置。"""
        return self._providers

    def get_enabled_providers(self) -> Dict[str, ProviderConfig]:
        """获取所有已启用的供应商。"""
        return {n: p for n, p in self._providers.items() if p.enabled}

    def add_provider(self, name: str, config: ProviderConfig) -> None:
        """添加或更新供应商。"""
        self._providers[name] = config

    def remove_provider(self, name: str) -> bool:
        """移除供应商（不允许移除预设）。"""
        if name in self.DEFAULT_PROVIDERS and name != "custom":
            log.warning(f"不能移除预设供应商: {name}")
            return False
        return self._providers.pop(name, None) is not None

    def get_setting(self, key: str, default: Any = None) -> Any:
        """获取设置项。"""
        return self._data.get("settings", {}).get(key, default)

    def set_setting(self, key: str, value: Any) -> None:
        """设置配置项。"""
        if "settings" not in self._data:
            self._data["settings"] = {}
        self._data["settings"][key] = value

    def get_default_endpoint(self, provider_name: str) -> str:
        """获取供应商的默认端点/端口。"""
        defaults = self.DEFAULT_PROVIDERS.get(provider_name.lower(), {})
        return defaults.get("default_endpoint", "")


# ─── Hash Utilities ───────────────────────────────────────────────────────────

class HashUtils:
    """哈希工具：生成问题指纹、特征哈希。"""

    @staticmethod
    def fingerprint(text: str, algorithm: str = "sha256") -> str:
        """
        为风险生成问题指纹（特征哈希）。

        Args:
            text: 风险描述文本
            algorithm: 哈希算法

        Returns:
            十六进制哈希字符串
        """
        h = hashlib.new(algorithm)
        h.update(text.encode("utf-8", errors="replace"))
        return h.hexdigest()

    @staticmethod
    def feature_hash(features: Dict[str, Any]) -> str:
        """
        从特征字典生成一致的特征哈希。用于错误经验库匹配。

        Args:
            features: 特征字典（如 {"error_type": "ParseError", "apk_size": 50000000}）

        Returns:
            特征哈希字符串
        """
        # 对 key 排序保证一致性
        canonical = json.dumps(features, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    @staticmethod
    def similarity(hash1: str, hash2: str) -> float:
        """
        计算两个哈希的相似度（基于汉明距离）。

        Args:
            hash1, hash2: 十六进制哈希字符串

        Returns:
            相似度 (0.0 - 1.0)
        """
        if len(hash1) != len(hash2):
            min_len = min(len(hash1), len(hash2))
            hash1 = hash1[:min_len]
            hash2 = hash2[:min_len]

        try:
            b1 = int(hash1, 16)
            b2 = int(hash2, 16)
            # 汉明距离
            xor = b1 ^ b2
            bits = xor.bit_length()
            max_bits = len(hash1) * 4
            return 1.0 - (bits / max_bits)
        except ValueError:
            return 0.0


# ─── APK Utilities ────────────────────────────────────────────────────────────

class APKUtils:
    """APK 文件操作辅助工具。"""

    @staticmethod
    def is_valid_apk(filepath: str) -> bool:
        """检查是否是有效的 APK/ZIP 文件。"""
        if not os.path.exists(filepath):
            return False
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                # 检查是否包含 AndroidManifest.xml 或 classes.dex
                names = zf.namelist()
                has_manifest = any("AndroidManifest.xml" in n for n in names)
                has_dex = any(n.endswith(".dex") for n in names)
                return has_manifest or has_dex
        except (zipfile.BadZipFile, IOError):
            return False

    @staticmethod
    def get_file_size_mb(filepath: str) -> float:
        """获取文件大小（MB）。"""
        try:
            return os.path.getsize(filepath) / (1024 * 1024)
        except OSError:
            return 0.0

    @staticmethod
    def create_backup(filepath: str) -> Optional[str]:
        """创建 APK 备份。返回备份路径。"""
        if not os.path.exists(filepath):
            return None
        backup_path = filepath + f".backup_{int(time.time())}"
        try:
            shutil.copy2(filepath, backup_path)
            log.info(f"备份已创建: {backup_path}")
            return backup_path
        except IOError as e:
            log.error(f"创建备份失败: {e}")
            return None

    @staticmethod
    def extract_files(apk_path: str, target_dir: str,
                       patterns: Optional[List[str]] = None) -> Dict[str, str]:
        """
        从 APK 中提取匹配 pattern 的文件。

        Args:
            apk_path: APK 文件路径
            target_dir: 提取目标目录
            patterns: 文件名匹配模式列表（如 ["AndroidManifest.xml", "*.SF"]）

        Returns:
            {文件名: 提取路径} 字典
        """
        extracted: Dict[str, str] = {}
        os.makedirs(target_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if patterns:
                        if not any(
                            name == p or (p.startswith("*") and name.endswith(p[1:]))
                            or (p.endswith("*") and name.startswith(p[:-1]))
                            or (p == "*")
                            for p in patterns
                        ):
                            continue
                    try:
                        safe_name = name.replace("/", "_").replace("\\", "_")
                        dest = os.path.join(target_dir, safe_name)
                        with zf.open(name) as src, open(dest, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        extracted[name] = dest
                    except Exception as e:
                        log.debug(f"提取文件失败 {name}: {e}")
            return extracted
        except Exception as e:
            log.error(f"APK 解压失败: {e}")
            return extracted

    @staticmethod
    def list_entries(apk_path: str, limit: int = 1000) -> List[str]:
        """列出 APK 中的条目名称。"""
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                return zf.namelist()[:limit]
        except Exception as e:
            log.error(f"列出条目失败: {e}")
            return []

    @staticmethod
    def read_entry(apk_path: str, entry_name: str) -> Optional[bytes]:
        """读取 APK 中指定条目的内容。"""
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                return zf.read(entry_name)
        except Exception as e:
            log.debug(f"读取条目失败 {entry_name}: {e}")
            return None


# ─── Exception Helpers ────────────────────────────────────────────────────────

def capture_error_context(exc: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    捕获完整的错误上下文，用于经验库学习。

    Args:
        exc: 异常对象
        context: 额外的上下文信息

    Returns:
        错误上下文字典
    """
    import traceback
    error_info: Dict[str, Any] = {
        "exception_type": type(exc).__name__,
        "message": str(exc),
        "traceback": traceback.format_exc(),
        "timestamp": datetime.now().isoformat(),
    }
    if context:
        error_info["context"] = context
    return error_info


# ─── Decorators ───────────────────────────────────────────────────────────────

def safe_execute(default_return: Any = None, log_errors: bool = True):
    """
    装饰器：安全执行函数，捕获所有异常。

    Args:
        default_return: 异常时的默认返回值
        log_errors: 是否记录错误日志
    """
    def decorator(func):
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_errors:
                    log.exception(f"{func.__name__} 执行失败: {e}")
                return default_return
        return wrapper
    return decorator


# ─── Initialization ───────────────────────────────────────────────────────────

def initialize(base_dir: Optional[str] = None) -> None:
    """
    初始化 InstaGuard 运行环境。

    Args:
        base_dir: 应用数据基础目录
    """
    init_paths(base_dir)
    log.setup_file_logging()
    log.info(f"{APP_NAME} v{APP_VERSION} 初始化完成")
    log.info(f"配置目录: {CONFIG_DIR}")
    log.info(f"数据库目录: {DB_DIR}")


# 自动初始化路径（预加载时）
init_paths()
