"""InstaGuard 测试套件 - 共享 fixtures 和配置。"""
import pytest
import os
import sys
import tempfile
from pathlib import Path

# 将项目根目录加入 Python 路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import init_paths, Config


@pytest.fixture
def temp_dir():
    """临时目录 fixture，测试结束后自动清理。"""
    with tempfile.TemporaryDirectory() as tmp:
        yield tmp


@pytest.fixture
def test_config(temp_dir):
    """提供独立的 Config 单例用于测试。"""
    init_paths(temp_dir)
    config = Config()
    config._loaded = False
    config.__init__()
    config._init_defaults()
    return config


@pytest.fixture
def sample_risk():
    """标准的 RiskItem 示例，用于各模块测试。"""
    from scanner import RiskItem
    return RiskItem(
        id="RISK-001",
        category="permission",
        severity="high",
        title="危险权限: CAMERA",
        description="应用声明了 CAMERA 权限，可能被用于偷拍",
        fingerprint="abc123",
        evidence="android.permission.CAMERA",
        recommendation="检查 CAMERA 权限的使用场景，确认其必要性",
    )


@pytest.fixture
def sample_scan_result(sample_risk):
    """标准的 ScanResult 示例（含一个风险项）。"""
    from scanner import ScanResult
    result = ScanResult(
        apk_path="/tmp/test.apk",
        package_name="com.example.test",
        version_name="1.0",
        version_code="1",
        file_size_mb=10.5,
    )
    result.add_risk(sample_risk)
    return result
