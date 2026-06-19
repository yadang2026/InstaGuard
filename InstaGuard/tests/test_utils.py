"""
test_utils.py - 测试 utils.py 中的所有核心功能。

测试覆盖：
- init_paths 路径初始化
- Config 单例模式
- Config 配置加载/保存
- Config 默认供应商配置
- Config 供应商增删改查
- HashUtils 指纹生成、特征哈希、相似度计算
- APKUtils APK 有效性检测
- safe_execute 装饰器
- capture_error_context 错误上下文捕获
"""
import os
import json
import hashlib
import zipfile
from unittest.mock import patch, mock_open, MagicMock

from utils import (
    init_paths, Config, ProviderConfig,
    HashUtils, APKUtils,
    safe_execute, capture_error_context,
    CONFIG_DIR, CACHE_DIR, DB_DIR,
    MEMORY_DB_PATH, EXPERIENCE_DB_PATH, CONFIG_FILE_PATH,
)


class TestInitPaths:
    """路径初始化测试。"""

    def test_init_paths(self, temp_dir):
        """测试路径初始化后全局变量正确设置。"""
        init_paths(temp_dir)
        # 目录应被创建
        assert os.path.isdir(temp_dir)
        assert os.path.isdir(os.path.join(temp_dir, "cache"))
        assert os.path.isdir(os.path.join(temp_dir, "db"))


class TestConfigSingleton:
    """Config 单例模式测试。"""

    def test_config_singleton(self):
        """测试 Config 是单例模式。"""
        c1 = Config()
        c2 = Config()
        assert c1 is c2

    def test_config_singleton_forced_new(self):
        """测试重新创建 Config 实例仍是同一个。"""
        c1 = Config()
        c2 = Config()
        assert c1 is c2


class TestConfigLoadSave:
    """Config 加载和保存测试。"""

    def test_config_load_defaults(self, test_config):
        """测试加载默认配置。"""
        providers = test_config.get_providers()
        assert "openai" in providers
        assert "ollama" in providers
        assert "anthropic" in providers
        assert "deepseek" in providers

    def test_config_save_and_load(self, temp_dir):
        """测试保存和重新加载配置。"""
        init_paths(temp_dir)
        c1 = Config()
        c1._loaded = False
        c1.__init__()
        c1._init_defaults()
        c1.save()

        # 模拟新实例加载
        c2 = Config()
        c2._loaded = False
        c2.__init__()
        c2.load()
        providers = c2.get_providers()
        assert "openai" in providers

    def test_config_settings(self, test_config):
        """测试配置项的读写。"""
        test_config.set_setting("test_key", "test_value")
        assert test_config.get_setting("test_key") == "test_value"
        # 默认值
        assert test_config.get_setting("nonexistent", "default") == "default"
        # 默认设置存在
        assert test_config.get_setting("language") == "zh"


class TestConfigDefaultProviders:
    """默认供应商配置测试。"""

    def test_default_providers_exist(self, test_config):
        """测试所有默认供应商均已初始化。"""
        providers = test_config.get_providers()
        expected = ["openai", "ollama", "anthropic", "deepseek", "minimax", "glm", "custom"]
        for name in expected:
            assert name in providers, f"供应商 {name} 缺失"

    def test_provider_has_models(self, test_config):
        """测试供应商配置包含模型列表。"""
        openai = test_config.get_provider("openai")
        assert openai is not None
        assert len(openai.models) >= 1
        assert "gpt-4o" in openai.models

    def test_provider_default_endpoint(self, test_config):
        """测试供应商有默认端点。"""
        openai = test_config.get_provider("openai")
        assert openai.default_endpoint == "https://api.openai.com/v1"

    def test_get_default_endpoint(self, test_config):
        """测试获取默认端口方法。"""
        assert test_config.get_default_endpoint("openai") == "https://api.openai.com/v1"
        assert test_config.get_default_endpoint("ollama") == "http://localhost:11434/v1"
        assert test_config.get_default_endpoint("nonexistent") == ""


class TestConfigProviderCRUD:
    """Config 供应商增删改查测试。"""

    def test_add_provider(self, test_config):
        """测试添加新供应商。"""
        new_provider = ProviderConfig(
            name="test_provider",
            display_name="Test",
            default_endpoint="https://test.api",
            models=["model-a"],
        )
        test_config.add_provider("test_provider", new_provider)
        assert test_config.get_provider("test_provider") is not None

    def test_remove_custom_provider(self, test_config):
        """测试移除自定义供应商。"""
        new_provider = ProviderConfig(name="my_custom")
        test_config.add_provider("my_custom", new_provider)
        assert test_config.remove_provider("my_custom") is True
        assert test_config.get_provider("my_custom") is None

    def test_remove_preset_provider_forbidden(self, test_config):
        """测试不能移除预设供应商。"""
        assert test_config.remove_provider("openai") is False
        assert test_config.get_provider("openai") is not None

    def test_get_enabled_providers(self, test_config):
        """测试获取已启用供应商。"""
        all_enabled = test_config.get_enabled_providers()
        # 默认全部启用
        assert len(all_enabled) >= 6

    def test_get_setting_default(self, test_config):
        """测试获取设置的默认值。"""
        assert test_config.get_setting("memory_similarity_threshold") == 0.85
        assert test_config.get_setting("repair_backup_enabled") is True


class TestHashFingerprint:
    """HashUtils 指纹生成测试。"""

    def test_fingerprint_sha256(self):
        """测试 SHA256 指纹生成。"""
        fp = HashUtils.fingerprint("test risk description")
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA256 输出 64 个十六进制字符

    def test_fingerprint_deterministic(self):
        """测试相同输入产生相同指纹。"""
        fp1 = HashUtils.fingerprint("same text")
        fp2 = HashUtils.fingerprint("same text")
        assert fp1 == fp2

    def test_fingerprint_different_inputs(self):
        """测试不同输入产生不同指纹。"""
        fp1 = HashUtils.fingerprint("text A")
        fp2 = HashUtils.fingerprint("text B")
        assert fp1 != fp2

    def test_fingerprint_with_chinese(self):
        """测试中文文本的指纹生成。"""
        fp = HashUtils.fingerprint("应用声明了 CAMERA 权限")
        assert isinstance(fp, str)
        assert len(fp) == 64


class TestHashFeatureHash:
    """HashUtils 特征哈希测试。"""

    def test_feature_hash_consistency(self):
        """测试特征哈希的一致性——相同特征生成相同哈希。"""
        features = {"error_type": "ParseError", "apk_size": 50000000}
        h1 = HashUtils.feature_hash(features)
        # 不同的 key 顺序但相同内容
        features2 = {"apk_size": 50000000, "error_type": "ParseError"}
        h2 = HashUtils.feature_hash(features2)
        assert h1 == h2

    def test_feature_hash_length(self):
        """测试特征哈希长度（16 字符）。"""
        features = {"error_type": "TimeoutError"}
        h = HashUtils.feature_hash(features)
        assert len(h) == 16


class TestHashSimilarity:
    """HashUtils 相似度计算测试。"""

    def test_similarity_identical(self):
        """测试相同哈希的相似度为 1.0。"""
        h = HashUtils.fingerprint("test")
        assert HashUtils.similarity(h, h) == 1.0

    def test_similarity_different_lengths(self):
        """测试不同长度哈希的相似度计算。"""
        short = "abc123"
        long = "abc123def456"
        sim = HashUtils.similarity(short, long)
        assert 0.0 <= sim <= 1.0

    def test_similarity_invalid_input(self):
        """测试无效输入返回 0.0。"""
        assert HashUtils.similarity("nothexg", "abcdef12") == 0.0


class TestAPKUtilsIsValid:
    """APKUtils APK 有效性检测测试。"""

    def test_file_not_exists(self):
        """测试不存在文件返回 False。"""
        assert APKUtils.is_valid_apk("/nonexistent/file.apk") is False

    def test_valid_apk_with_manifest(self, temp_dir):
        """测试含 AndroidManifest.xml 的有效 APK。"""
        apk_path = os.path.join(temp_dir, "test.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
        assert APKUtils.is_valid_apk(apk_path) is True

    def test_valid_apk_with_dex(self, temp_dir):
        """测试含 classes.dex 的有效 APK（无 Manifest）。"""
        apk_path = os.path.join(temp_dir, "test_dex.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("classes.dex", b"\x00")
        assert APKUtils.is_valid_apk(apk_path) is True

    @patch("utils.zipfile.ZipFile")
    def test_invalid_zip(self, mock_zipfile):
        """测试损坏的 ZIP 文件返回 False。"""
        from zipfile import BadZipFile
        mock_zipfile.side_effect = BadZipFile
        assert APKUtils.is_valid_apk("/tmp/bad.apk") is False


class TestSafeExecuteDecorator:
    """safe_execute 装饰器测试。"""

    def test_safe_execute_normal(self):
        """测试正常执行返回原值。"""
        @safe_execute(default_return=None)
        def add(a, b):
            return a + b
        assert add(2, 3) == 5

    def test_safe_execute_exception(self):
        """测试异常时返回默认值。"""
        @safe_execute(default_return="FALLBACK")
        def failing_func():
            raise ValueError("测试异常")
        assert failing_func() == "FALLBACK"

    def test_safe_execute_exception_no_log(self):
        """测试 log_errors=False 时不记录日志。"""
        @safe_execute(default_return=None, log_errors=False)
        def failing_func():
            raise RuntimeError("静默异常")
        assert failing_func() is None


class TestCaptureErrorContext:
    """capture_error_context 测试。"""

    def test_capture_exception(self):
        """测试捕获异常上下文。"""
        try:
            raise ValueError("测试错误消息")
        except ValueError as e:
            ctx = capture_error_context(e)
        assert ctx["exception_type"] == "ValueError"
        assert ctx["message"] == "测试错误消息"
        assert "traceback" in ctx
        assert "timestamp" in ctx

    def test_capture_with_context(self):
        """测试带额外上下文的捕获。"""
        try:
            raise RuntimeError("运行时错误")
        except RuntimeError as e:
            ctx = capture_error_context(e, context={"apk_path": "/tmp/test.apk"})
        assert ctx["context"]["apk_path"] == "/tmp/test.apk"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
