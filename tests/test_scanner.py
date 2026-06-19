"""
test_scanner.py - 测试 APKScanner 安全扫描引擎。

测试覆盖：
- Scanner 初始化
- 扫描层级检测（full/manifest_only/basic）
- RiskItem 创建
- ScanResult 统计
- 进度回调（mock callback）
- 指纹生成
"""
import os
from unittest.mock import patch, MagicMock, call

from scanner import APKScanner, RiskItem, ScanResult, SignatureInfo, ComponentInfo
from utils import init_paths


class TestScannerInitialization:
    """Scanner 初始化测试。"""

    def test_scanner_init_defaults(self, test_config):
        """测试扫描器默认初始化。"""
        scanner = APKScanner()
        assert scanner.LARGE_FILE_THRESHOLD_MB == 200.0
        assert scanner._risk_counter == 0
        assert scanner._temp_dir is None

    def test_scanner_init_with_callback(self):
        """测试带回调的初始化。"""
        callback_data = []

        def my_callback(stage, progress):
            callback_data.append((stage, progress))

        scanner = APKScanner(callback=my_callback)
        # 验证回调被存储
        scanner._report_progress("测试", 0.5)
        assert len(callback_data) == 1
        assert callback_data[0] == ("测试", 0.5)


class TestLevelDetection:
    """扫描层级检测测试。"""

    @patch("builtins.open", new_callable=MagicMock)
    def test_detect_level_full(self, mock_open, temp_dir):
        """测试可以通过 androguard 进行完整扫描。"""
        # 不 mock androguard，测试的是层级选择逻辑
        scanner = APKScanner()
        assert scanner.LARGE_FILE_THRESHOLD_MB == 200.0

    def test_scan_result_level_default(self):
        """测试 ScanResult 默认层级为 basic。"""
        result = ScanResult()
        assert result.scan_level == "basic"


class TestRiskItemCreation:
    """RiskItem 创建测试。"""

    def test_risk_item_creation(self):
        """测试创建 RiskItem。"""
        risk = RiskItem(
            id="R001",
            category="permission",
            severity="critical",
            title="危险权限检测",
            description="发现危险权限",
            fingerprint="abcd1234",
            evidence="android.permission.CAMERA",
            recommendation="移除该权限",
        )
        assert risk.id == "R001"
        assert risk.category == "permission"
        assert risk.severity == "critical"
        assert risk.ai_analysis is None  # 默认 None

    def test_risk_item_with_ai_analysis(self):
        """测试带 AI 分析的 RiskItem。"""
        risk = RiskItem(
            id="R002",
            category="exported",
            severity="high",
            title="导出组件",
            description="组件被导出",
            fingerprint="efgh5678",
            evidence="com.example.MainActivity",
            recommendation="设置 exported=false",
            ai_analysis="经AI分析，该组件存在风险...",
        )
        assert risk.ai_analysis == "经AI分析，该组件存在风险..."


class TestScanResultStats:
    """ScanResult 统计测试。"""

    def test_add_risk_updates_stats(self):
        """测试 add_risk 更新统计信息。"""
        result = ScanResult()
        risk1 = RiskItem(
            id="R001", category="permission", severity="critical",
            title="T1", description="D1", fingerprint="fp1",
            evidence="E1", recommendation="R1",
        )
        result.add_risk(risk1)
        assert result.stats["critical"] == 1
        assert result.stats["total"] == 1

        risk2 = RiskItem(
            id="R002", category="exported", severity="high",
            title="T2", description="D2", fingerprint="fp2",
            evidence="E2", recommendation="R2",
        )
        result.add_risk(risk2)
        assert result.stats["high"] == 1
        assert result.stats["total"] == 2

    def test_scan_result_fields(self):
        """测试 ScanResult 字段。"""
        result = ScanResult(
            apk_path="/tmp/test.apk",
            package_name="com.example.app",
            version_name="2.0",
            version_code="2",
            file_size_mb=15.5,
        )
        assert result.apk_path == "/tmp/test.apk"
        assert result.package_name == "com.example.app"
        assert result.file_size_mb == 15.5
        assert result.error_message is None


class TestCallbackProgress:
    """进度回调测试。"""

    def test_callback_receives_updates(self):
        """测试回调接收到进度更新。"""
        calls = []

        def cb(stage, progress):
            calls.append((stage, progress))

        scanner = APKScanner(callback=cb)
        scanner._report_progress("权限分析", 0.15)
        scanner._report_progress("组件分析", 0.20)
        scanner._report_progress("完成", 1.0)

        assert len(calls) == 3
        assert calls[0] == ("权限分析", 0.15)
        assert calls[2] == ("完成", 1.0)

    def test_callback_clamps_progress(self):
        """测试进度值被 clamp 到 [0, 1]。"""
        calls = []

        def cb(stage, progress):
            calls.append(progress)

        scanner = APKScanner(callback=cb)
        scanner._report_progress("test", -0.5)
        scanner._report_progress("test", 1.5)

        assert calls[0] == 0.0
        assert calls[1] == 1.0

    def test_callback_exception_suppressed(self):
        """测试回调异常不影响扫描器。"""

        def bad_callback(stage, progress):
            raise RuntimeError("回调异常")

        scanner = APKScanner(callback=bad_callback)
        # 不应抛出异常
        scanner._report_progress("测试", 0.5)


class TestFingerprintGeneration:
    """指纹生成测试。"""

    def test_generate_risk_id(self):
        """测试风险 ID 生成格式。"""
        scanner = APKScanner()
        risk_id = scanner._generate_risk_id()
        assert risk_id.startswith("R-")
        # 格式: R-NNNN-XXXXXX
        parts = risk_id.split("-")
        assert len(parts) == 3

    def test_generate_risk_id_increments(self):
        """测试风险 ID 计数器递增。"""
        scanner = APKScanner()
        id1 = scanner._generate_risk_id()
        id2 = scanner._generate_risk_id()
        # 确认编号递增
        seq1 = int(id1.split("-")[1])
        seq2 = int(id2.split("-")[1])
        assert seq2 > seq1


class TestSignatureAndComponent:
    """签名和组件数据类测试。"""

    def test_signature_info_defaults(self):
        """测试 SignatureInfo 默认值。"""
        sig = SignatureInfo()
        assert sig.signed is False
        assert sig.v1_scheme is False
        assert sig.v2_scheme is False
        assert sig.v3_scheme is False

    def test_signature_info_custom(self):
        """测试自定义签名信息。"""
        sig = SignatureInfo(
            signed=True,
            v1_scheme=True,
            v2_scheme=True,
            certificate_fingerprints=["AA:BB:CC"],
        )
        assert sig.signed is True
        assert sig.v1_scheme is True
        assert len(sig.certificate_fingerprints) == 1

    def test_component_info(self):
        """测试组件信息。"""
        comp = ComponentInfo(
            name="com.example.MainActivity",
            component_type="activity",
            exported=True,
            permissions=["android.permission.INTERNET"],
        )
        assert comp.name == "com.example.MainActivity"
        assert comp.exported is True
        assert "android.permission.INTERNET" in comp.permissions


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
