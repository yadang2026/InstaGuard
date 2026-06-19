"""
test_provider_manager.py - 测试 ProviderManager 多 AI 供应商管理器。

测试覆盖：
- ProviderManager 单例模式
- get_all_providers / get_enabled_providers
- add_api_key / remove_api_key
- set_active_model / set_endpoint
- toggle_provider
- get_default_endpoint
- detect_ollama（mock socket）
"""
from unittest.mock import patch, MagicMock

from provider_manager import ProviderManager
from utils import Config


class TestProviderManagerSingleton:
    """ProviderManager 单例模式测试。"""

    def test_singleton(self):
        """测试 ProviderManager 是单例。"""
        pm1 = ProviderManager()
        pm2 = ProviderManager()
        assert pm1 is pm2


class TestGetAllProviders:
    """获取供应商列表测试。"""

    def test_get_all_providers(self, test_config):
        """测试获取所有供应商——含预设供应商。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        providers = pm.get_all_providers()
        assert "openai" in providers
        assert "deepseek" in providers

    def test_get_enabled_providers(self, test_config):
        """测试获取已启用供应商。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        enabled = pm.get_enabled_providers()
        assert len(enabled) > 0


class TestAddAPIKey:
    """add_api_key 测试。"""

    def test_add_api_key_to_existing_provider(self, test_config):
        """测试向已有供应商添加 API Key。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        result = pm.add_api_key("openai", "sk-test-key-12345")
        assert result is True
        provider = test_config.get_provider("openai")
        assert "sk-test-key-12345" in provider.api_keys

    def test_add_api_key_creates_provider(self, test_config):
        """测试自动创建不存在的供应商。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        result = pm.add_api_key("new_provider", "test-key")
        assert result is True
        assert test_config.get_provider("new_provider") is not None

    def test_add_duplicate_key(self, test_config):
        """测试重复添加相同的 Key 不生效。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        pm.add_api_key("openai", "sk-duplicate")
        provider = test_config.get_provider("openai")
        key_count = len(provider.api_keys)
        pm.add_api_key("openai", "sk-duplicate")
        assert len(provider.api_keys) == key_count


class TestRemoveAPIKey:
    """remove_api_key 测试。"""

    def test_remove_api_key(self, test_config):
        """测试移除 API Key。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        pm.add_api_key("openai", "sk-to-remove")
        provider = test_config.get_provider("openai")
        assert "sk-to-remove" in provider.api_keys

        result = pm.remove_api_key("openai", provider.api_keys.index("sk-to-remove"))
        assert result is True

    def test_remove_invalid_index(self, test_config):
        """测试移除无效索引返回 False。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        result = pm.remove_api_key("openai", 999)
        assert result is False


class TestSetActiveModel:
    """set_active_model 测试。"""

    def test_set_active_model(self, test_config):
        """测试设置活跃模型。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        result = pm.set_active_model("openai", "gpt-4o-mini")
        assert result is True
        provider = test_config.get_provider("openai")
        assert provider.active_model == "gpt-4o-mini"

    def test_set_active_model_nonexistent(self, test_config):
        """测试对不存在的供应商设置模型返回 False。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        result = pm.set_active_model("nonexistent", "some-model")
        assert result is False

    def test_set_endpoint(self, test_config):
        """测试手动设置端点。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        result = pm.set_endpoint("openai", "https://custom.endpoint/v1")
        assert result is True
        assert test_config.get_provider("openai").default_endpoint == "https://custom.endpoint/v1"


class TestToggleProvider:
    """toggle_provider 测试。"""

    def test_toggle_enabled_provider(self, test_config):
        """测试切换供应商启用状态。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        # 默认启用
        assert test_config.get_provider("openai").enabled is True
        new_state = pm.toggle_provider("openai")
        assert new_state is False
        assert test_config.get_provider("openai").enabled is False

    def test_toggle_nonexistent_provider(self, test_config):
        """测试切换不存在的供应商返回 None。"""
        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        result = pm.toggle_provider("nonexistent")
        assert result is None


class TestDetectOllama:
    """detect_ollama 测试（mock socket）。"""

    @patch("socket.socket")
    def test_ollama_detected(self, mock_socket_class, test_config):
        """测试检测到 Ollama 服务。"""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0  # 端口可达
        mock_socket_class.return_value = mock_sock

        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        # mock _fetch_ollama_models
        with patch.object(pm, "_fetch_ollama_models", return_value=["llama3", "mistral"]):
            result = pm.detect_ollama()

        assert result["available"] is True
        assert "models" in result
        assert "llama3" in result["models"]

    @patch("socket.socket")
    def test_ollama_not_detected(self, mock_socket_class, test_config):
        """测试未检测到 Ollama 服务。"""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # 端口不可达
        mock_socket_class.return_value = mock_sock

        pm = ProviderManager()
        pm._initialized = False
        pm.__init__()
        pm.config = test_config

        result = pm.detect_ollama()
        assert result["available"] is False


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
