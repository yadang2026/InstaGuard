"""
InstaGuard - 多 AI 供应商管理器

管理多个 AI 供应商的 API Key、端点、模型选择与自动端口匹配。
支持 Key 轮询、故障自动切换、Ollama 本地服务检测。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import time
import json
import socket
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from threading import Lock

from utils import (
    log, Config, ProviderConfig, safe_execute, capture_error_context,
)

# 尝试导入 openai 库
try:
    from openai import OpenAI, APIError, APITimeoutError, APIConnectionError
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    log.warning("openai 库未安装，AI 功能不可用。请运行: pip install openai")

# Anthropic 适配器
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


# ─── 通用 OpenAI 兼容适配器 ──────────────────────────────────────────────────

class OpenAICompatibleClient:
    """
    统一客户端：使用 openai 库调用不同供应商（兼容 Ollama、DeepSeek、GLM 等）。
    非完全兼容的 API（如 Anthropic 原生）使用适配器。
    """

    def __init__(self, provider: ProviderConfig):
        self.provider = provider
        self._client: Optional[Any] = None
        self._last_key: str = ""
        self._failures: Dict[str, int] = {}
        self._lock = Lock()

    def _get_client(self) -> Any:
        """获取或创建 OpenAI 客户端。"""
        if not OPENAI_AVAILABLE:
            raise RuntimeError("openai 库未安装")

        api_key = self.provider.get_current_key()
        base_url = self.provider.default_endpoint

        # 如果 Key 变了或还没创建，重新创建客户端
        if api_key != self._last_key or self._client is None:
            self._client = OpenAI(
                api_key=api_key,
                base_url=base_url,
                timeout=self.provider.timeout,
                default_headers=self.provider.extra_headers,
            )
            self._last_key = api_key

        return self._client

    def chat(self, messages: List[Dict[str, str]], **kwargs: Any) -> Optional[str]:
        """
        发送聊天请求。

        Args:
            messages: 消息列表 [{"role": "user", "content": "..."}]
            **kwargs: 额外参数（model, temperature, max_tokens 等）

        Returns:
            AI 回复文本，失败返回 None
        """
        model = kwargs.pop("model", self.provider.active_model or self.provider.models[0] if self.provider.models else "gpt-3.5-turbo")

        max_retries = len(self.provider.api_keys) if self.provider.api_keys else 1
        for attempt in range(max_retries):
            try:
                client = self._get_client()
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    **kwargs,
                )
                return response.choices[0].message.content

            except (APITimeoutError, APIConnectionError) as e:
                log.warning(f"[{self.provider.name}] 连接失败 (尝试 {attempt+1}/{max_retries}): {e}")
                # 自动切换到下一个 Key
                if attempt < max_retries - 1:
                    self._last_key = ""  # 强制重建客户端
                    time.sleep(1)
                    continue
                return None

            except APIError as e:
                log.error(f"[{self.provider.name}] API 错误: {e}")
                return None

            except Exception as e:
                log.exception(f"[{self.provider.name}] 未知错误: {e}")
                return None

        return None


# ─── Anthropic 适配器 ────────────────────────────────────────────────────────

class AnthropicAdapter:
    """
    Anthropic API 适配器 — 将 OpenAI 格式的消息转换为 Anthropic 原生格式。
    同时兼容通过 OpenAI 兼容端点访问 Anthropic 模型（如 OpenRouter）。
    """

    def __init__(self, provider: ProviderConfig):
        self.provider = provider
        self._client: Optional[Any] = None
        self._last_key: str = ""

    def _get_client(self) -> Any:
        if not ANTHROPIC_AVAILABLE:
            raise RuntimeError("anthropic 库未安装")

        api_key = self.provider.get_current_key()
        if api_key != self._last_key or self._client is None:
            self._client = anthropic.Anthropic(
                api_key=api_key,
                base_url=self.provider.default_endpoint or None,
                timeout=self.provider.timeout,
            )
            self._last_key = api_key
        return self._client

    def _convert_messages(self, messages: List[Dict[str, str]]) -> tuple:
        """将 OpenAI 格式的消息转换为 Anthropic 格式。"""
        system_msg = ""
        converted = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                system_msg = content
            else:
                converted.append({"role": role, "content": content})

        return system_msg, converted

    def chat(self, messages: List[Dict[str, str]], **kwargs: Any) -> Optional[str]:
        """发送聊天请求。"""
        if not ANTHROPIC_AVAILABLE:
            log.error("anthropic 库未安装，无法使用 Anthropic API")
            return None

        model = kwargs.pop("model", self.provider.active_model or "claude-3-5-sonnet-20241022")
        system_msg, converted = self._convert_messages(messages)
        max_tokens = kwargs.pop("max_tokens", 4096)

        max_retries = max(len(self.provider.api_keys), 1)
        for attempt in range(max_retries):
            try:
                client = self._get_client()
                msg = client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    system=system_msg or anthropic.NOT_GIVEN,
                    messages=converted,
                    **kwargs,
                )
                return msg.content[0].text

            except Exception as e:
                log.warning(f"[Anthropic] 请求失败 (尝试 {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    self._last_key = ""
                    time.sleep(1)
                    continue
                return None

        return None


# ─── Provider Manager ─────────────────────────────────────────────────────────

class ProviderManager:
    """
    多 AI 供应商管理器。

    功能：
    - 管理多个供应商的 API Key、端点、模型
    - 支持 Key 轮询和故障自动切换
    - 自动检测 Ollama 本地服务
    - 模型选择时自动匹配端口
    """

    _instance: Optional["ProviderManager"] = None
    _lock: Lock = Lock()

    # Ollama 可能的端口列表
    OLLAMA_PORTS: List[int] = [11434, 11435, 8080, 8000]

    def __new__(cls) -> "ProviderManager":
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

        self.config = Config()
        self._clients: Dict[str, Any] = {}
        self._ollama_available: Optional[bool] = None

    def initialize(self) -> None:
        """初始化并加载配置。"""
        self.config.load()
        log.info(f"ProviderManager 初始化完成，已加载 {len(self.config.get_providers())} 个供应商")

    # ─── Ollama 检测 ──────────────────────────────────────────────────────

    def detect_ollama(self) -> Dict[str, Any]:
        """
        检测本地 Ollama 服务是否运行。自动探测已知端口。

        Returns:
            {"available": bool, "endpoint": str, "models": [...], "message": str}
        """
        for port in self.OLLAMA_PORTS:
            endpoint = f"http://localhost:{port}"
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()

                if result == 0:
                    # 端口可达，尝试获取模型列表
                    self._ollama_available = True
                    models = self._fetch_ollama_models(endpoint)
                    log.info(f"Ollama 检测成功: {endpoint}")
                    return {
                        "available": True,
                        "endpoint": f"{endpoint}/v1",
                        "models": models,
                        "message": f"Ollama 服务运行中 ({endpoint})",
                    }
            except Exception:
                continue

        self._ollama_available = False
        return {
            "available": False,
            "endpoint": "",
            "models": [],
            "message": "未检测到 Ollama 服务。请先启动 Ollama: ollama serve",
        }

    def _fetch_ollama_models(self, base_url: str) -> List[str]:
        """从 Ollama API 获取可用模型列表。"""
        try:
            import urllib.request
            url = f"{base_url}/api/tags"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            log.debug(f"获取 Ollama 模型列表失败: {e}")
            return []

    # ─── 供应商管理 ───────────────────────────────────────────────────────

    def get_provider(self, name: str) -> Optional[ProviderConfig]:
        """获取供应商配置。"""
        return self.config.get_provider(name)

    def get_all_providers(self) -> Dict[str, ProviderConfig]:
        """获取所有供应商。"""
        return self.config.get_providers()

    def get_enabled_providers(self) -> Dict[str, ProviderConfig]:
        """获取所有已启用的供应商。"""
        return self.config.get_enabled_providers()

    def add_api_key(self, provider_name: str, api_key: str) -> bool:
        """
        添加 API Key 到指定供应商。

        Args:
            provider_name: 供应商名称
            api_key: API Key

        Returns:
            是否添加成功
        """
        provider = self.config.get_provider(provider_name)
        if not provider:
            # 自动创建供应商
            defaults = Config.DEFAULT_PROVIDERS.get(provider_name.lower(), {})
            provider = ProviderConfig(
                name=provider_name,
                display_name=defaults.get("display_name", provider_name),
                default_endpoint=defaults.get("default_endpoint", ""),
                models=defaults.get("models", []),
            )
            self.config.add_provider(provider_name, provider)

        if api_key and api_key not in provider.api_keys:
            provider.api_keys.append(api_key)
            provider.enabled = True
            self.config.save()
            log.info(f"[{provider_name}] API Key 已添加")
            return True
        return False

    def remove_api_key(self, provider_name: str, key_index: int) -> bool:
        """移除指定索引的 API Key。"""
        provider = self.config.get_provider(provider_name)
        if not provider or key_index >= len(provider.api_keys):
            return False
        provider.api_keys.pop(key_index)
        self.config.save()
        return True

    def set_active_model(self, provider_name: str, model: str) -> bool:
        """
        设置供应商的活跃模型。自动匹配默认端口。

        Args:
            provider_name: 供应商名称
            model: 模型名称

        Returns:
            是否设置成功
        """
        provider = self.config.get_provider(provider_name)
        if not provider:
            return False

        provider.active_model = model

        # 自动填入默认端点
        if not provider.default_endpoint:
            provider.default_endpoint = self.config.get_default_endpoint(provider_name)

        # 如果是 Ollama，自动检测
        if provider_name.lower() == "ollama":
            ollama_status = self.detect_ollama()
            if ollama_status["available"]:
                provider.default_endpoint = ollama_status["endpoint"]

        self.config.save()
        log.info(f"[{provider_name}] 活跃模型 -> {model}, 端点 -> {provider.default_endpoint}")
        return True

    def set_endpoint(self, provider_name: str, endpoint: str) -> bool:
        """手动设置供应商端点。"""
        provider = self.config.get_provider(provider_name)
        if not provider:
            return False
        provider.default_endpoint = endpoint
        self.config.save()
        return True

    def toggle_provider(self, provider_name: str) -> Optional[bool]:
        """切换供应商启用状态。返回新状态。"""
        provider = self.config.get_provider(provider_name)
        if not provider:
            return None
        provider.enabled = not provider.enabled
        self.config.save()
        return provider.enabled

    # ─── AI 调用 ──────────────────────────────────────────────────────────

    def chat(
        self,
        messages: List[Dict[str, str]],
        provider_name: Optional[str] = None,
        model: Optional[str] = None,
        fallback: bool = True,
        **kwargs: Any,
    ) -> Optional[str]:
        """
        发送聊天请求，支持故障自动切换。

        Args:
            messages: 消息列表
            provider_name: 指定供应商（None 则使用第一个启用的）
            model: 指定模型（None 则使用供应商活跃模型）
            fallback: 是否在失败时自动切换到下一个可用供应商
            **kwargs: 额外 LLM 参数

        Returns:
            AI 回复文本，全部失败返回 None
        """
        # 确定供应商列表
        if provider_name:
            providers = [self.config.get_provider(provider_name)]
            providers = [p for p in providers if p and p.enabled]
        else:
            providers = list(self.config.get_enabled_providers().values())

        if not providers:
            log.error("没有可用的 AI 供应商")
            return None

        if not fallback:
            providers = providers[:1]

        for provider in providers:
            if not provider.api_keys and provider.name != "ollama":
                log.debug(f"[{provider.name}] 无 API Key，跳过")
                continue

            use_model = model or provider.active_model or (provider.models[0] if provider.models else None)
            if not use_model:
                log.debug(f"[{provider.name}] 无可用模型，跳过")
                continue

            log.info(f"[{provider.name}] 尝试调用 {use_model}")

            # 根据供应商类型选择客户端
            result = self._call_provider(provider, messages, model=use_model, **kwargs)
            if result:
                return result

        log.error("所有供应商调用均失败")
        return None

    def _call_provider(
        self, provider: ProviderConfig, messages: List[Dict[str, str]], **kwargs: Any
    ) -> Optional[str]:
        """调用单个供应商。"""
        name_lower = provider.name.lower()

        # Anthropic 原生 API
        if name_lower == "anthropic" and ANTHROPIC_AVAILABLE:
            client = self._get_or_create_client(provider, "anthropic")
            if client is None:
                client = AnthropicAdapter(provider)
                self._clients[f"{provider.name}_anthropic"] = client
            return client.chat(messages, **kwargs)

        # OpenAI 兼容供应商
        client = self._get_or_create_client(provider, "openai_compat")
        if client is None:
            client = OpenAICompatibleClient(provider)
            self._clients[f"{provider.name}_openai_compat"] = client
        return client.chat(messages, **kwargs)

    def _get_or_create_client(self, provider: ProviderConfig, client_type: str) -> Optional[Any]:
        """获取或创建客户端缓存。"""
        key = f"{provider.name}_{client_type}"
        return self._clients.get(key)

    def clear_client_cache(self, provider_name: Optional[str] = None) -> None:
        """清除客户端缓存（Key 轮换后调用）。"""
        if provider_name:
            keys_to_remove = [k for k in self._clients if k.startswith(provider_name)]
            for k in keys_to_remove:
                del self._clients[k]
        else:
            self._clients.clear()


# ─── 便捷函数 ─────────────────────────────────────────────────────────────────

def get_provider_manager() -> ProviderManager:
    """获取 ProviderManager 单例。"""
    pm = ProviderManager()
    pm.initialize()
    return pm
