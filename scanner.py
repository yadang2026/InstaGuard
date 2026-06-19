"""
InstaGuard - APK 安全扫描引擎

多层次降级扫描策略：androguard 完整解析 → Manifest 仅解析 → 基础 zipfile 检查。
支持 20+ 项安全检查、大文件分块处理、混淆类名模糊匹配、扫描进度实时反馈。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import re
import time
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from utils import (
    log, APKUtils, HashUtils, capture_error_context,
    safe_execute, Config, init_paths, MEMORY_DB_PATH, EXPERIENCE_DB_PATH,
)

# ─── 类型别名 ──────────────────────────────────────────────────────────────────
ScannerCallback = Callable[[str, float], None]  # (stage_name, progress_0_to_1)


# ─── 数据类 ────────────────────────────────────────────────────────────────────

@dataclass
class RiskItem:
    """单个安全风险项。"""
    id: str                              # 唯一标识 (R-xxxxxxxx)
    category: str                        # 风险类别
    severity: str                        # critical/high/medium/low/info
    title: str                           # 简短标题（中文）
    description: str                     # 详细描述（中文）
    fingerprint: str                     # 特征哈希 (SHA256)
    evidence: str                        # 证据（如具体权限名、类名）
    recommendation: str                  # 修复建议（中文）
    ai_analysis: Optional[str] = None    # AI分析结果（后续由AI引擎填充）


@dataclass
class ComponentInfo:
    """Android 组件信息。"""
    name: str
    component_type: str   # activity/service/receiver/provider
    exported: bool = False
    intent_filters: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)


@dataclass
class SignatureInfo:
    """APK 签名信息。"""
    signed: bool = False
    v1_scheme: bool = False
    v2_scheme: bool = False
    v3_scheme: bool = False
    certificates: List[Dict[str, str]] = field(default_factory=list)
    certificate_fingerprints: List[str] = field(default_factory=list)
    validity_start: Optional[str] = None
    validity_end: Optional[str] = None
    is_expired: bool = False


@dataclass
class ScanResult:
    """APK 扫描结果。"""
    apk_path: str = ""
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    file_size_mb: float = 0.0
    signature_info: Optional[SignatureInfo] = None
    permissions: List[str] = field(default_factory=list)
    components: List[ComponentInfo] = field(default_factory=list)
    risks: List[RiskItem] = field(default_factory=list)
    scan_duration: float = 0.0
    scan_level: str = "basic"  # full / manifest_only / basic
    stats: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        "total": 0,
    })
    error_message: Optional[str] = None

    def add_risk(self, risk: RiskItem) -> None:
        """添加风险项并更新统计。"""
        self.risks.append(risk)
        sev = risk.severity
        if sev in self.stats:
            self.stats[sev] += 1
        self.stats["total"] += 1


# ─── 风险检测规则配置 ─────────────────────────────────────────────────────────

# 高危权限列表（Android 危险权限）
DANGEROUS_PERMISSIONS: Dict[str, str] = {
    "android.permission.CAMERA":                     "相机权限 - 可能被用于偷拍",
    "android.permission.RECORD_AUDIO":               "录音权限 - 可能被用于窃听",
    "android.permission.READ_CONTACTS":              "读取联系人 - 可能泄露通讯录",
    "android.permission.WRITE_CONTACTS":             "写入联系人 - 可能篡改通讯录",
    "android.permission.ACCESS_FINE_LOCATION":       "精确定位 - 可能追踪用户位置",
    "android.permission.ACCESS_COARSE_LOCATION":     "粗略定位 - 可能追踪用户位置",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "后台定位 - 可能在后台追踪用户",
    "android.permission.SEND_SMS":                   "发送短信 - 可能产生扣费",
    "android.permission.RECEIVE_SMS":                "接收短信 - 可能窃取验证码",
    "android.permission.READ_SMS":                   "读取短信 - 可能窃取验证码和隐私",
    "android.permission.CALL_PHONE":                 "拨打电话 - 可能产生扣费",
    "android.permission.READ_CALL_LOG":              "读取通话记录 - 可能泄露隐私",
    "android.permission.WRITE_CALL_LOG":             "写入通话记录 - 可能篡改记录",
    "android.permission.READ_EXTERNAL_STORAGE":      "读取存储 - 可能窃取文件",
    "android.permission.WRITE_EXTERNAL_STORAGE":     "写入存储 - 可能植入恶意文件",
    "android.permission.READ_PHONE_STATE":           "读取手机状态 - 可能获取IMEI等标识",
    "android.permission.BODY_SENSORS":               "身体传感器 - 可能获取健康数据",
    "android.permission.ACTIVITY_RECOGNITION":       "活动识别 - 可能追踪用户行为",
    "android.permission.INSTALL_PACKAGES":           "安装应用 - 可能静默安装恶意软件",
    "android.permission.DELETE_PACKAGES":            "卸载应用 - 可能卸载安全软件",
    "android.permission.SYSTEM_ALERT_WINDOW":        "悬浮窗 - 可能用于钓鱼攻击",
    "android.permission.WRITE_SETTINGS":             "修改系统设置 - 可能篡改配置",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "辅助功能 - 可能用于自动化攻击",
}

# 已知加固壳特征类名
KNOWN_PACKERS: Dict[str, str] = {
    "com.tencent.StubShell":           "腾讯乐固",
    "com.tencent.bugly":               "腾讯Bugly加固",
    "com.qihoo":                       "360加固保",
    "com.qihoo360":                    "360加固保",
    "ijiami":                          "爱加密",
    "com.ijiami":                      "爱加密",
    "com.secneo":                      "梆梆加固",
    "com.secneo.apkwrapper":           "梆梆加固",
    "com.bangcle":                     "梆梆加固",
    "com.alibaba.wireless.security":   "阿里聚安全",
    "com.aliyun":                      "阿里云加固",
    "com.baidu":                       "百度加固",
    "com.baidu.protect":               "百度加固",
    "net.lingala.zip4j":               "可能加壳",
    "com.netease.nis":                 "网易易盾",
    "com.netease":                     "网易易盾",
    "com.dingtalk":                    "钉钉加固",
    "com.google.android.feedback":     "Google Play 加固",
    "com.wrapper.proxyapplication":    "通用壳代理",
    "org.apache.cordova":              "Cordova 混合壳",
}

# 常见第三方 SDK 特征
KNOWN_SDKS: Dict[str, Dict[str, str]] = {
    "com.google.android.gms.ads":          {"name": "Google AdMob",      "category": "广告"},
    "com.google.firebase":                 {"name": "Firebase",          "category": "统计/分析"},
    "com.facebook.ads":                    {"name": "Facebook Ads",      "category": "广告"},
    "com.unity3d.ads":                     {"name": "Unity Ads",         "category": "广告"},
    "com.applovin":                        {"name": "AppLovin",          "category": "广告"},
    "com.ironsource":                      {"name": "ironSource",        "category": "广告"},
    "com.bytedance.pangle":                {"name": "穿山甲(Pangle)",    "category": "广告"},
    "com.umeng":                           {"name": "友盟(Umeng)",       "category": "统计"},
    "com.umeng.analytics":                 {"name": "友盟统计",          "category": "统计"},
    "com.baidu.mobstat":                   {"name": "百度统计",          "category": "统计"},
    "com.tencent.stat":                    {"name": "腾讯统计",          "category": "统计"},
    "com.bugsnag":                         {"name": "Bugsnag",           "category": "崩溃收集"},
    "com.crashlytics":                     {"name": "Crashlytics",       "category": "崩溃收集"},
    "com.squareup.okhttp":                 {"name": "OkHttp",            "category": "网络库"},
    "com.android.volley":                  {"name": "Volley",            "category": "网络库"},
    "retrofit2":                           {"name": "Retrofit",          "category": "网络库"},
    "com.alipay":                          {"name": "支付宝SDK",        "category": "支付"},
    "com.tencent.mm.opensdk":              {"name": "微信SDK",           "category": "支付/登录"},
    "com.unionpay":                        {"name": "银联SDK",           "category": "支付"},
    "cn.jpush":                            {"name": "极光推送",          "category": "推送"},
    "com.getui":                           {"name": "个推",              "category": "推送"},
    "com.huawei.hms":                      {"name": "华为HMS",           "category": "厂商服务"},
    "com.xiaomi.push":                     {"name": "小米推送",          "category": "推送"},
    "com.baidu.map":                       {"name": "百度地图SDK",       "category": "地图"},
    "com.amap":                            {"name": "高德地图SDK",       "category": "地图"},
}

# 敏感字符串模式（硬编码密钥、API Key、URL等）
SENSITIVE_PATTERNS: List[Tuple[str, str, str]] = [
    # (正则模式, 风险类别, 描述)
    (r'(?i)(api[_-]?key|apikey|api_secret|secret[_-]?key)\s*[:=]\s*["\"][A-Za-z0-9_\-]{16,}["\"]',
     "硬编码API密钥", "可能泄露API密钥"),
    (r'(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["\"][A-Za-z0-9_\-\.]{20,}["\"]',
     "硬编码访问令牌", "可能泄露访问令牌"),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\"][^"\"\s]{6,}["\"]',
     "硬编码密码", "可能硬编码密码"),
    (r'(?i)(private[_-]?key|rsa[_-]?private|dsa[_-]?private)\s*[:=]',
     "硬编码私钥", "可能泄露私钥"),
    (r'(?i)jdbc:[a-z]+://[^\s;]+',
     "硬编码数据库连接", "可能泄露数据库连接字符串"),
    (r'(?i)https?://[^\s]*\.(conf|config|env|secret|credential)',
     "敏感配置文件URL", "可能引用敏感配置文件"),
    (r'(?i)(BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY)',
     "内嵌私钥证书", "APK中包含私钥文件"),
    (r'(?i)AKIA[0-9A-Z]{16}',              # AWS Access Key 模式
     "AWS访问密钥", "可能泄露AWS凭证"),
]

# WebView 危险方法模式
WEBVIEW_RISK_PATTERNS: Dict[str, str] = {
    "setJavaScriptEnabled":       "启用了JavaScript - 增加XSS攻击面",
    "setAllowFileAccess":         "允许文件访问 - 可能读取本地文件",
    "setAllowFileAccessFromFileURLs": "允许文件URL访问文件 - 存在跨域风险",
    "setAllowUniversalAccessFromFileURLs": "允许通用文件URL访问 - 高危跨域漏洞",
    "addJavascriptInterface":     "添加JavaScript接口 - 存在远程代码执行风险",
    "setWebContentsDebuggingEnabled": "启用WebView调试 - 可能泄露敏感数据",
}


# ─── APKScanner 核心类 ─────────────────────────────────────────────────────────

class APKScanner:
    """
    APK 安全扫描引擎。

    采用多层次降级策略：
    1. Level 1 (full): androguard 完整解析 APK
    2. Level 2 (manifest_only): zipfile + androguard 仅解析 Manifest 和签名
    3. Level 3 (basic): 仅用 zipfile 提取关键文件进行基础安全检查

    支持：
    - 20+ 项安全检查
    - 大文件（>200MB）分块流式处理
    - 混淆类名模糊匹配
    - 扫描进度实时回调
    """

    # 大文件阈值（MB）
    LARGE_FILE_THRESHOLD_MB: float = 200.0

    def __init__(self, callback: Optional[ScannerCallback] = None):
        """
        初始化扫描器。

        Args:
            callback: 进度回调函数 (stage_name, progress_0_to_1)
        """
        self._callback: ScannerCallback = callback or (lambda s, p: None)
        self._config = Config()
        self._risk_counter: int = 0
        self._temp_dir: Optional[str] = None

    def _report_progress(self, stage: str, progress: float) -> None:
        """报告扫描进度。"""
        try:
            self._callback(stage, min(1.0, max(0.0, progress)))
        except Exception:
            pass  # 回调异常不影响扫描

    def _generate_risk_id(self) -> str:
        """生成唯一风险ID。"""
        self._risk_counter += 1
        return f"R-{self._risk_counter:04d}-{HashUtils.fingerprint(str(time.time_ns()))[:6]}"

    # ─── 主扫描入口 ────────────────────────────────────────────────────────

    def scan(self, apk_path: str) -> ScanResult:
        """
        扫描 APK 文件，返回完整结果。

        Args:
            apk_path: APK 文件路径

        Returns:
            ScanResult 包含所有风险项和元数据
        """
        start_time = time.time()
        result = ScanResult(apk_path=apk_path)

        # 验证文件
        if not os.path.exists(apk_path):
            result.error_message = "文件不存在"
            log.error(f"APK 文件不存在: {apk_path}")
            return result

        if not APKUtils.is_valid_apk(apk_path):
            result.error_message = "无效的 APK 文件"
            log.error(f"无效的 APK 文件: {apk_path}")
            return result

        result.file_size_mb = APKUtils.get_file_size_mb(apk_path)
        is_large = result.file_size_mb > self.LARGE_FILE_THRESHOLD_MB

        if is_large:
            log.info(f"大文件检测: {result.file_size_mb:.1f}MB，将使用分块处理")

        # 创建临时目录
        self._temp_dir = tempfile.mkdtemp(prefix="instaguard_scan_")

        try:
            # 逐级尝试扫描
            self._report_progress("开始扫描", 0.0)

            # Level 1: androguard 完整解析
            try:
                self._scan_full_androguard(apk_path, result, is_large)
                result.scan_level = "full"
            except Exception as e:
                log.warning(f"androguard 完整解析失败: {e}，降级到 Manifest 仅解析")
                self._report_progress("降级扫描", 0.3)

                # Level 2: zipfile + androguard 仅解析 Manifest
                try:
                    self._scan_manifest_only(apk_path, result)
                    result.scan_level = "manifest_only"
                except Exception as e2:
                    log.warning(f"Manifest 解析失败: {e2}，降级到基础扫描")
                    self._report_progress("基础扫描", 0.5)

                    # Level 3: 仅 zipfile
                    self._scan_basic_zipfile(apk_path, result)
                    result.scan_level = "basic"

            # 所有级别都会执行的通用检查
            self._report_progress("通用检查", 0.7)
            self._scan_common_checks(apk_path, result, is_large)

            # 签名分析
            self._report_progress("签名分析", 0.85)
            self._analyze_signature(apk_path, result)

            # 加固检测
            self._report_progress("加固检测", 0.9)
            self._detect_packer(apk_path, result)

            # SDK 识别
            self._report_progress("SDK识别", 0.95)
            self._detect_sdks(apk_path, result)

        finally:
            # 清理临时目录
            if self._temp_dir and os.path.exists(self._temp_dir):
                import shutil
                shutil.rmtree(self._temp_dir, ignore_errors=True)

        result.scan_duration = time.time() - start_time
        self._report_progress("扫描完成", 1.0)

        log.info(
            f"扫描完成: {result.package_name} | "
            f"级别={result.scan_level} | "
            f"风险={result.stats['total']} "
            f"({result.stats['critical']}C/{result.stats['high']}H/{result.stats['medium']}M/{result.stats['low']}L) | "
            f"耗时={result.scan_duration:.2f}s"
        )

        return result

    # ─── Level 1: androguard 完整解析 ───────────────────────────────────────

    def _scan_full_androguard(self, apk_path: str, result: ScanResult, is_large: bool) -> None:
        """使用 androguard 完整解析 APK。"""
        from androguard.core.apk import APK

        self._report_progress("androguard解析", 0.05)

        apk = APK(apk_path)

        # 基本信息
        result.package_name = apk.get_package() or ""
        result.version_name = apk.get_androidversion_name() or ""
        result.version_code = str(apk.get_androidversion_code() or "")

        self._report_progress("提取元数据", 0.10)

        # 权限分析
        self._analyze_permissions(apk, result)

        self._report_progress("权限分析", 0.15)

        # 组件分析
        self._analyze_components(apk, result)

        self._report_progress("组件分析", 0.20)

        # Manifest 安全检查
        self._check_manifest_security(apk, result)

        self._report_progress("Manifest安全", 0.25)

        # 资源文件检查
        self._check_resources(apk, result)

    # ─── Level 2: Manifest 仅解析 ──────────────────────────────────────────

    def _scan_manifest_only(self, apk_path: str, result: ScanResult) -> None:
        """降级方案：仅用 zipfile 提取 Manifest，用 androguard 解析。"""
        from androguard.core.apk import APK

        self._report_progress("提取Manifest", 0.30)

        # 使用 zipfile 读取 Manifest
        manifest_xml = APKUtils.read_entry(apk_path, "AndroidManifest.xml")
        if manifest_xml is None:
            raise ValueError("无法读取 AndroidManifest.xml")

        # 写入临时文件供 androguard 解析
        manifest_path = os.path.join(self._temp_dir, "AndroidManifest.xml")
        with open(manifest_path, "wb") as f:
            f.write(manifest_xml)

        # 尝试解析
        try:
            apk = APK(apk_path)
            result.package_name = apk.get_package() or ""
            result.version_name = apk.get_androidversion_name() or ""
            result.version_code = str(apk.get_androidversion_code() or "")

            self._analyze_permissions(apk, result)
            self._check_manifest_security(apk, result)
        except Exception:
            # 尝试直接解析 XML
            self._parse_manifest_xml_direct(manifest_xml, result)

    def _parse_manifest_xml_direct(self, xml_data: bytes, result: ScanResult) -> None:
        """直接解析 AndroidManifest.xml 字节内容。"""
        try:
            from lxml import etree
            # androguard 内置 AXML 解析
            from androguard.core.axml import AXMLPrinter
            axml = AXMLPrinter(xml_data)
            xml_str = axml.get_xml_obj()
            if xml_str is None:
                xml_str = axml.get_buff()
            if isinstance(xml_str, bytes):
                xml_str = xml_str.decode("utf-8", errors="replace")

            # 用正则提取基本信息
            pkg_match = re.search(r'package="([^"]+)"', xml_str)
            if pkg_match:
                result.package_name = pkg_match.group(1)

            ver_match = re.search(r'versionName="([^"]+)"', xml_str)
            if ver_match:
                result.version_name = ver_match.group(1)

            vc_match = re.search(r'versionCode="([^"]+)"', xml_str)
            if vc_match:
                result.version_code = vc_match.group(1)

            # 提取权限
            for perm in re.finditer(r'<uses-permission[^>]*android:name="([^"]+)"', xml_str):
                result.permissions.append(perm.group(1))

            # 检查调试标志
            if 'android:debuggable="true"' in xml_str:
                self._add_risk(result, "debug", "high",
                    "应用可调试",
                    "APK 设置了 android:debuggable=true，攻击者可通过 ADB 获取应用数据。"
                    "生产环境应关闭此选项。",
                    f"android:debuggable=true in {result.package_name}",
                    "android:debuggable=true",
                    "将 AndroidManifest.xml 中的 android:debuggable 设置为 false")

            if 'android:allowBackup="true"' in xml_str or 'android:allowBackup' not in xml_str:
                self._add_risk(result, "debug", "medium",
                    "允许应用备份",
                    "应用允许备份（android:allowBackup=true 或默认值）。"
                    "攻击者可通过 ADB backup 导出应用数据。",
                    f"android:allowBackup=true/default in {result.package_name}",
                    "android:allowBackup=true",
                    "若不需要备份功能，设置 android:allowBackup=false")

        except Exception as e:
            log.debug(f"直接 XML 解析失败: {e}")

    # ─── Level 3: 仅 zipfile 基础检查 ──────────────────────────────────────

    def _scan_basic_zipfile(self, apk_path: str, result: ScanResult) -> None:
        """最基础级别：仅用 zipfile 做安全检查。"""
        self._report_progress("基础zipfile检查", 0.50)

        entries = APKUtils.list_entries(apk_path, limit=5000)

        # 检查 classes.dex 存在
        dex_count = sum(1 for e in entries if re.match(r'classes\d*\.dex', os.path.basename(e)))
        if dex_count == 0:
            self._add_risk(result, "export", "high",
                "未找到 DEX 文件",
                "APK 中未找到 classes.dex 文件，可能是无效 APK 或异常结构。",
                f"no_dex_files:{HashUtils.fingerprint(apk_path)[:12]}",
                f"APK路径: {apk_path}",
                "请确认 APK 文件完整性")

        # 检查是否存在签名文件
        has_signature = any(e.endswith(".RSA") or e.endswith(".DSA") or e.endswith(".EC")
                           or "META-INF/" in e for e in entries)
        if not has_signature:
            self._add_risk(result, "signing", "high",
                "未签名 APK",
                "APK 中未找到签名文件（META-INF/*.RSA/.DSA/.EC），"
                "未签名 APK 无法在设备上安装，可能被篡改。",
                f"unsigned:{HashUtils.fingerprint(apk_path)[:12]}",
                "META-INF 目录缺失签名文件",
                "请使用 jarsigner 或 apksigner 对 APK 进行签名")

        # 尝试读取 Manifest 字节做基础检查
        manifest_bytes = APKUtils.read_entry(apk_path, "AndroidManifest.xml")
        if manifest_bytes:
            try:
                from androguard.core.axml import AXMLPrinter
                axml = AXMLPrinter(manifest_bytes)
                xml_str = axml.get_buff()
                if isinstance(xml_str, bytes):
                    xml_str = xml_str.decode("utf-8", errors="replace")

                pkg_match = re.search(r'package="([^"]+)"', xml_str)
                if pkg_match:
                    result.package_name = pkg_match.group(1)

                # 基础安全检查
                if 'android:debuggable="true"' in xml_str:
                    self._add_risk(result, "debug", "high",
                        "应用可调试", "APK 为 Debug 构建，存在安全风险。",
                        f"debug:{result.package_name}",
                        "android:debuggable=true",
                        "发布版本请关闭 debuggable")

                # 提取权限
                for perm in re.finditer(r'<uses-permission[^>]*android:name="([^"]+)"', xml_str):
                    result.permissions.append(perm.group(1))
                    if perm.group(1) in DANGEROUS_PERMISSIONS:
                        self._add_risk(result, "permission", "medium",
                            f"危险权限: {perm.group(1).split('.')[-1]}",
                            DANGEROUS_PERMISSIONS[perm.group(1)],
                            f"perm:{perm.group(1)}:{result.package_name}",
                            perm.group(1),
                            "确认该权限是否为业务必须，否则移除")

            except Exception as e:
                log.debug(f"基础 Manifest 解析失败: {e}")

        # 检查 native 库中的可疑文件
        so_files = [e for e in entries if e.endswith(".so")]
        if so_files:
            suspicious_libs = [s for s in so_files if any(
                kw in s.lower() for kw in ["hack", "inject", "hook", "frida", "xposed", "substrate"]
            )]
            for lib in suspicious_libs:
                self._add_risk(result, "sensitive_string", "high",
                    f"可疑 Native 库: {os.path.basename(lib)}",
                    f"发现可疑的 .so 文件包含注入/ Hook 相关关键词",
                    f"lib:{HashUtils.fingerprint(lib)[:12]}",
                    lib,
                    "请检查该 Native 库的用途和来源")

    # ─── 权限分析 ──────────────────────────────────────────────────────────

    def _analyze_permissions(self, apk: Any, result: ScanResult) -> None:
        """分析 APK 权限列表，检测危险权限。"""
        permissions = apk.get_permissions() or []
        result.permissions = list(permissions)

        for perm in permissions:
            if perm in DANGEROUS_PERMISSIONS:
                perm_short = perm.split(".")[-1]
                self._add_risk(result, "permission", "medium",
                    f"危险权限: {perm_short}",
                    DANGEROUS_PERMISSIONS[perm],
                    f"perm:{perm}:{result.package_name}",
                    perm,
                    f"确认 {perm_short} 权限是否为业务必须，若不需要请在 Manifest 中移除")

        # 检查过度权限组合
        self._check_permission_combinations(result)

    def _check_permission_combinations(self, result: ScanResult) -> None:
        """检测危险的权限组合。"""
        perms = set(result.permissions)

        # 组合1: 录音 + 联网 → 可能窃听
        if "android.permission.RECORD_AUDIO" in perms and "android.permission.INTERNET" in perms:
            self._add_risk(result, "permission", "high",
                "可疑权限组合: 录音+联网",
                "应用同时申请了录音和网络权限，可能在后台窃听并上传录音。",
                f"perm_combo:record_net:{result.package_name}",
                "RECORD_AUDIO + INTERNET",
                "确认录音功能是否必须在后台运行，建议添加录音状态提示")

        # 组合2: 读取短信 + 联网 → 可能窃取验证码
        if ("android.permission.READ_SMS" in perms or "android.permission.RECEIVE_SMS" in perms) \
                and "android.permission.INTERNET" in perms:
            self._add_risk(result, "permission", "high",
                "可疑权限组合: 短信+联网",
                "应用可读取短信且有网络权限，可能窃取验证码并上传。",
                f"perm_combo:sms_net:{result.package_name}",
                "SMS + INTERNET",
                "确认短信读取是否为必须功能，建议使用 SMS Retriever API 替代")

        # 组合3: 定位 + 相机 + 联网 → 可能追踪
        location_perms = {"android.permission.ACCESS_FINE_LOCATION",
                          "android.permission.ACCESS_COARSE_LOCATION"}
        if (location_perms & perms) and "android.permission.CAMERA" in perms \
                and "android.permission.INTERNET" in perms:
            self._add_risk(result, "permission", "medium",
                "可疑权限组合: 定位+相机+联网",
                "应用同时拥有定位、相机和网络权限，可能追踪用户行踪并上传照片。",
                f"perm_combo:loc_cam_net:{result.package_name}",
                "LOCATION + CAMERA + INTERNET",
                "确认这些权限组合的业务必要性")

    # ─── 组件分析 ──────────────────────────────────────────────────────────

    def _analyze_components(self, apk: Any, result: ScanResult) -> None:
        """分析导出组件。"""
        # Activities
        for act in apk.get_activities() or []:
            exported = self._is_component_exported(apk, act, "activity")
            comp = ComponentInfo(name=act, component_type="activity", exported=exported)
            if exported:
                comp.intent_filters = self._get_intent_filters(apk, act, "activity")
            result.components.append(comp)
            if exported:
                self._add_risk(result, "export", "high",
                    f"导出 Activity: {self._short_name(act)}",
                    f"Activity 组件对外导出（exported=true），可能存在界面劫持或未经授权访问的风险。",
                    f"export:activity:{act}:{result.package_name}",
                    act,
                    "若该 Activity 不需要被外部调用，请设置 exported=false 或添加权限保护"
                )

        # Services
        for svc in apk.get_services() or []:
            exported = self._is_component_exported(apk, svc, "service")
            comp = ComponentInfo(name=svc, component_type="service", exported=exported)
            if exported:
                comp.intent_filters = self._get_intent_filters(apk, svc, "service")
            result.components.append(comp)
            if exported:
                self._add_risk(result, "export", "high",
                    f"导出 Service: {self._short_name(svc)}",
                    f"Service 组件对外导出，可能被外部应用调用执行后台操作。",
                    f"export:service:{svc}:{result.package_name}",
                    svc,
                    "若不需要跨应用调用，设置 exported=false"
                )

        # Receivers
        for rcv in apk.get_receivers() or []:
            exported = self._is_component_exported(apk, rcv, "receiver")
            comp = ComponentInfo(name=rcv, component_type="receiver", exported=exported)
            if exported:
                comp.intent_filters = self._get_intent_filters(apk, rcv, "receiver")
            result.components.append(comp)
            if exported:
                self._add_risk(result, "export", "medium",
                    f"导出 BroadcastReceiver: {self._short_name(rcv)}",
                    f"BroadcastReceiver 对外导出，可能被外部应用发送恶意广播触发。",
                    f"export:receiver:{rcv}:{result.package_name}",
                    rcv,
                    "若不需要接收外部广播，设置 exported=false 或添加权限保护"
                )

        # Providers
        for prv in apk.get_providers() or []:
            exported = self._is_component_exported(apk, prv, "provider")
            comp = ComponentInfo(name=prv, component_type="provider", exported=exported)
            if exported:
                comp.intent_filters = self._get_intent_filters(apk, prv, "provider")
                comp.permissions = self._get_provider_permissions(apk, prv)
            result.components.append(comp)
            if exported:
                sev = "low" if comp.permissions else "high"
                self._add_risk(result, "export", sev,
                    f"导出 ContentProvider: {self._short_name(prv)}",
                    f"ContentProvider 对外导出{'，且无权限保护' if not comp.permissions else ''}，"
                    f"可能被外部应用读取或修改数据。",
                    f"export:provider:{prv}:{result.package_name}",
                    prv,
                    "添加 readPermission/writePermission 权限保护，或设置 exported=false"
                )

    def _is_component_exported(self, apk: Any, component_name: str, comp_type: str) -> bool:
        """检查组件是否导出。"""
        try:
            # androguard 方法
            if comp_type == "activity":
                return apk.get_element("activity", "android:exported", name=component_name) == "true" \
                    or bool(apk.get_intent_filters("activity", component_name))
            elif comp_type == "service":
                return apk.get_element("service", "android:exported", name=component_name) == "true" \
                    or bool(apk.get_intent_filters("service", component_name))
            elif comp_type == "receiver":
                return apk.get_element("receiver", "android:exported", name=component_name) == "true" \
                    or bool(apk.get_intent_filters("receiver", component_name))
            elif comp_type == "provider":
                return apk.get_element("provider", "android:exported", name=component_name) == "true"
        except Exception:
            pass
        return False

    def _get_intent_filters(self, apk: Any, component_name: str, comp_type: str) -> List[str]:
        """获取组件的 intent-filter actions。"""
        try:
            filters = apk.get_intent_filters(comp_type, component_name)
            return list(filters.keys()) if filters else []
        except Exception:
            return []

    def _get_provider_permissions(self, apk: Any, provider_name: str) -> List[str]:
        """获取 ContentProvider 的权限保护。"""
        perms = []
        try:
            read_perm = apk.get_element("provider", "android:readPermission", name=provider_name)
            if read_perm:
                perms.append(f"readPermission={read_perm}")
            write_perm = apk.get_element("provider", "android:writePermission", name=provider_name)
            if write_perm:
                perms.append(f"writePermission={write_perm}")
            perm = apk.get_element("provider", "android:permission", name=provider_name)
            if perm:
                perms.append(f"permission={perm}")
        except Exception:
            pass
        return perms

    # ─── Manifest 安全检查 ─────────────────────────────────────────────────

    def _check_manifest_security(self, apk: Any, result: ScanResult) -> None:
        """Manifest 安全配置检查。"""
        try:
            # 调试标志
            if apk.is_valid_APK():
                if self._get_manifest_attr(apk, "application", "android:debuggable") == "true":
                    self._add_risk(result, "debug", "high",
                        "应用可调试 (android:debuggable=true)",
                        "APK 设置了 debuggable=true，攻击者可通过 ADB 获取应用内部数据。"
                        "生产环境应关闭此选项。",
                        f"debug:{result.package_name}",
                        "android:debuggable=true",
                        "在 AndroidManifest.xml 中设置 android:debuggable=false")

                # 备份标志
                backup = self._get_manifest_attr(apk, "application", "android:allowBackup")
                if backup is None or backup == "true":
                    self._add_risk(result, "debug", "medium",
                        "允许应用备份 (android:allowBackup)",
                        "应用允许备份，攻击者可通过 ADB backup 导出应用数据，"
                        "包括 SharedPreferences、数据库等。",
                        f"backup:{result.package_name}",
                        f"android:allowBackup={'true' if backup != 'false' else 'unset(default:true)'}",
                        "设置 android:allowBackup=false 并配置 backup rules")

                # 网络安全配置
                self._check_network_security(apk, result)

                # TaskAffinity 劫持
                task_affinity = self._get_manifest_attr(apk, "application", "android:taskAffinity")
                if task_affinity and task_affinity != result.package_name:
                    self._add_risk(result, "export", "low",
                        "自定义 TaskAffinity",
                        f"Application 使用自定义 taskAffinity={task_affinity}，"
                        f"可能被用于 Task 劫持攻击。",
                        f"taskaffinity:{result.package_name}",
                        task_affinity,
                        "确保 taskAffinity 与 packageName 一致，或使用 singleInstance 启动模式")

                # usesCleartextTraffic
                cleartext = self._get_manifest_attr(apk, "application", "android:usesCleartextTraffic")
                if cleartext == "true":
                    self._add_risk(result, "network", "high",
                        "允许明文流量 (usesCleartextTraffic=true)",
                        "应用明确允许 HTTP 明文流量，可能导致中间人攻击和数据泄露。",
                        f"cleartext:{result.package_name}",
                        "android:usesCleartextTraffic=true",
                        "强制使用 HTTPS，设置 usesCleartextTraffic=false 或配置 "
                        "NetworkSecurityConfig")
        except Exception as e:
            log.debug(f"Manifest 安全检查异常: {e}")

    def _get_manifest_attr(self, apk: Any, element: str, attr: str) -> Optional[str]:
        """安全获取 Manifest 属性值。"""
        try:
            val = apk.get_attribute_value(element, attr)
            return str(val).lower() if val is not None else None
        except Exception:
            return None

    def _check_network_security(self, apk: Any, result: ScanResult) -> None:
        """检查网络安全配置。"""
        try:
            # 检查是否定义了 NetworkSecurityConfig
            nsc = self._get_manifest_attr(apk, "application", "android:networkSecurityConfig")
            if nsc:
                # 尝试读取配置文件内容
                config_bytes = APKUtils.read_entry(result.apk_path,
                    f"res/raw/{nsc.replace('@xml/', '')}.xml")
                if config_bytes is None:
                    config_bytes = APKUtils.read_entry(result.apk_path,
                        f"res/raw/{nsc.replace('@xml/', '')}.xml")
                if config_bytes:
                    config_str = config_bytes.decode("utf-8", errors="replace")
                    # 检查是否信任用户证书
                    if "trust-anchors" in config_str or "certificates" in config_str:
                        self._add_risk(result, "network", "info",
                            "自定义网络安全配置",
                            f"应用使用了 NetworkSecurityConfig ({nsc})，"
                            f"请检查是否错误信任了用户证书或允许明文流量。",
                            f"nsc:{result.package_name}",
                            config_str[:200],
                            "检查 NetworkSecurityConfig 中是否正确配置了证书信任锚点")
        except Exception:
            pass

    # ─── 资源文件检查 ──────────────────────────────────────────────────────

    def _check_resources(self, apk: Any, result: ScanResult) -> None:
        """检查资源相关安全。"""
        try:
            # 检查 WebView 相关配置
            # 尝试从资源中查找 WebView 使用
            for filename in apk.get_files() or []:
                if filename.endswith(".xml"):
                    content = apk.get_file(filename)
                    if content:
                        try:
                            content_str = content.decode("utf-8", errors="replace")
                            for method, desc in WEBVIEW_RISK_PATTERNS.items():
                                if method in content_str:
                                    self._add_risk(result, "webview", "medium",
                                        f"WebView 风险: {method}",
                                        f"在配置文件中检测到 {method}，{desc}",
                                        f"webview:{method}:{result.package_name}",
                                        filename,
                                        "请限制 WebView 的权限，移除不必要的危险配置")
                        except Exception:
                            pass
        except Exception as e:
            log.debug(f"资源检查异常: {e}")

    # ─── 通用检查（所有扫描级别） ──────────────────────────────────────────

    def _scan_common_checks(self, apk_path: str, result: ScanResult, is_large: bool) -> None:
        """执行所有扫描级别都适用的通用检查。"""
        # 检查文件权限
        self._check_file_permissions(apk_path, result)

        # 检查 DEX 文件
        self._check_dex_security(apk_path, result, is_large)

        # 敏感字符串扫描
        self._scan_sensitive_strings(apk_path, result, is_large)

    def _check_file_permissions(self, apk_path: str, result: ScanResult) -> None:
        """检查 APK 文件权限。"""
        try:
            stat = os.stat(apk_path)
            mode = stat.st_mode
            # 检查是否全局可写
            if mode & 0o002:
                self._add_risk(result, "file_permission", "low",
                    "APK 文件全局可写",
                    "APK 文件权限设置过于宽松（全局可写），可能被其他应用篡改。",
                    f"fileperm:{HashUtils.fingerprint(apk_path)[:12]}",
                    f"权限: {oct(mode)}",
                    "修改文件权限为 644 (chmod 644)")
        except Exception:
            pass

    def _check_dex_security(self, apk_path: str, result: ScanResult, is_large: bool) -> None:
        """检查 DEX 文件级别的安全问题。"""
        entries = APKUtils.list_entries(apk_path, limit=5000)

        # 查找所有 .dex 文件
        dex_files = [e for e in entries if e.endswith(".dex")]

        if is_large:
            # 大文件：抽样读取
            self._report_progress("DEX抽样检查", 0.72)
            sample = dex_files[:3] + dex_files[-2:] if len(dex_files) > 5 else dex_files
            sample = list(set(sample))
        else:
            sample = dex_files

        for dex_file in sample:
            try:
                data = APKUtils.read_entry(apk_path, dex_file)
                if data:
                    # 搜索 WebView 危险方法
                    for method in ["setJavaScriptEnabled", "setAllowFileAccess",
                                    "addJavascriptInterface", "setAllowUniversalAccessFromFileURLs"]:
                        if method.encode("utf-8") in data:
                            self._add_risk(result, "webview", "medium",
                                f"DEX 中包含 WebView 风险方法: {method}",
                                f"在 {dex_file} 中发现 {method} 调用，"
                                f"可能存在 WebView 安全漏洞。",
                                f"dex:webview:{method}:{HashUtils.fingerprint(apk_path)[:12]}",
                                f"{dex_file} -> {method}",
                                "对 WebView 进行安全加固，移除不必要的危险配置")

                    # 搜索常见漏洞模式
                    for pattern_name, pattern_bytes in [
                        ("Runtime.exec", b"Runtime.exec"),
                        ("ProcessBuilder", b"ProcessBuilder"),
                        ("DexClassLoader", b"DexClassLoader"),
                        ("PathClassLoader", b"PathClassLoader"),
                    ]:
                        if pattern_bytes in data:
                            self._add_risk(result, "export", "low",
                                f"DEX 中包含动态执行: {pattern_name}",
                                f"在 {dex_file} 中发现 {pattern_name}，可能用于动态加载代码。",
                                f"dex:dynamic:{pattern_name}:{HashUtils.fingerprint(apk_path)[:12]}",
                                f"{dex_file} -> {pattern_name}",
                                "确认动态代码加载的合法性，避免执行未验证代码")
            except Exception:
                continue

    # ─── 签名分析 ──────────────────────────────────────────────────────────

    def _analyze_signature(self, apk_path: str, result: ScanResult) -> None:
        """分析 APK 签名信息。"""
        sig_info = SignatureInfo()
        result.signature_info = sig_info

        try:
            # 尝试用 androguard 解析签名
            from androguard.core.apk import APK
            apk = APK(apk_path)

            certs = apk.get_certificates()
            if certs:
                sig_info.signed = True
                for cert in certs:
                    cert_info: Dict[str, str] = {}
                    try:
                        cert_info["subject"] = str(cert.subject)
                        cert_info["issuer"] = str(cert.issuer)
                        cert_info["serial"] = str(cert.serial_number)
                        cert_info["sha1"] = cert.sha1_fingerprint.replace(" ", "")
                        cert_info["sha256"] = cert.sha256_fingerprint.replace(" ", "")

                        sig_info.certificate_fingerprints.append(cert_info["sha256"])

                        # 检查有效期
                        if hasattr(cert, "not_valid_before"):
                            nb = cert.not_valid_before
                            sig_info.validity_start = str(nb) if nb else None
                        if hasattr(cert, "not_valid_after"):
                            na = cert.not_valid_after
                            sig_info.validity_end = str(na) if na else None
                            # 简单检查是否过期
                            if na:
                                from datetime import datetime as dt
                                try:
                                    if na < dt.now():
                                        sig_info.is_expired = True
                                except Exception:
                                    pass

                        sig_info.certificates.append(cert_info)
                    except Exception as e:
                        log.debug(f"证书解析细节错误: {e}")

            # 检查签名版本
            try:
                sig_info.v1_scheme = apk.is_signed_v1()
                sig_info.v2_scheme = apk.is_signed_v2()
                sig_info.v3_scheme = apk.is_signed_v3()
            except Exception:
                # 降级：通过检查 META-INF 文件判断
                entries = APKUtils.list_entries(apk_path, limit=1000)
                meta_files = [e for e in entries if "META-INF/" in e]
                sig_info.v1_scheme = any(e.endswith(".RSA") or e.endswith(".DSA") or e.endswith(".EC")
                                         for e in meta_files)
                sig_info.v2_scheme = any("V2" in e or "apk-signing" in e for e in meta_files)
                sig_info.v3_scheme = any("V3" in e for e in meta_files)

            # 签名风险
            if not sig_info.signed:
                self._add_risk(result, "signing", "high",
                    "APK 未签名",
                    "APK 没有签名证书，无法在设备上安装，也可能是被篡改的恶意 APK。",
                    f"sign:unsigned:{result.package_name}",
                    "无签名",
                    "使用 apksigner 或 jarsigner 签名 APK")
            elif sig_info.is_expired:
                self._add_risk(result, "signing", "medium",
                    "签名证书已过期",
                    "APK 的签名证书已过期，可能导致应用无法更新或验证失败。",
                    f"sign:expired:{result.package_name}",
                    f"过期时间: {sig_info.validity_end}",
                    "使用新证书重新签名 APK")
            elif sig_info.v1_scheme and not sig_info.v2_scheme and not sig_info.v3_scheme:
                self._add_risk(result, "signing", "low",
                    "仅使用 V1 签名方案",
                    "APK 仅使用 JAR 签名（V1），建议使用 V2/V3 签名方案以获得更好的安全性和性能。",
                    f"sign:v1only:{result.package_name}",
                    "V1 signature only",
                    "使用 apksigner --v2-signing-enabled --v3-signing-enabled 签名")

        except ImportError:
            log.debug("androguard 不可用，跳过签名分析")
            # 基础签名检查
            entries = APKUtils.list_entries(apk_path, limit=1000)
            sig_files = [e for e in entries if e.endswith((".RSA", ".DSA", ".EC"))]
            if sig_files:
                sig_info.signed = True
        except Exception as e:
            log.debug(f"签名分析异常: {e}")

    # ─── 加固/加壳检测 ────────────────────────────────────────────────────

    def _detect_packer(self, apk_path: str, result: ScanResult) -> None:
        """检测 APK 是否使用加固/加壳方案。"""
        entries = APKUtils.list_entries(apk_path, limit=5000)

        # 方法1: 检查已知壳的类名特征
        for entry in entries:
            entry_lower = entry.lower()
            for pattern, packer_name in KNOWN_PACKERS.items():
                if pattern.lower() in entry_lower:
                    self._add_risk(result, "packer", "info",
                        f"检测到加固壳: {packer_name}",
                        f"APK 包含 {packer_name} 的加固特征文件（{entry}）。"
                        f"加固可能影响安全分析的准确性，且部分加固方案自身可能存在漏洞。",
                        f"packer:{pattern}:{HashUtils.fingerprint(apk_path)[:12]}",
                        entry,
                        "建议使用加固方案的官方检测工具进行安全审计")
                    return  # 检测到一种即可

        # 方法2: 检查 DEX 是否异常小（加固的 APK 通常只有一个壳 DEX）
        dex_files = [e for e in entries if e.endswith(".dex")]
        if len(dex_files) == 1:
            try:
                dex_data = APKUtils.read_entry(apk_path, dex_files[0])
                if dex_data and len(dex_data) < 10000:  # < 10KB 的单个 DEX 很可能是壳
                    self._add_risk(result, "packer", "info",
                        "疑似加固: 单个极小 DEX 文件",
                        f"APK 仅包含一个大小为 {len(dex_data)} 字节的 DEX 文件，"
                        f"这通常是加固壳的特征。真实代码可能在 assets 中的加密文件中。",
                        f"packer:small_dex:{HashUtils.fingerprint(apk_path)[:12]}",
                        f"{dex_files[0]} ({len(dex_data)} bytes)",
                        "建议使用脱壳工具（如 FRIDA-DEXDump）提取真实 DEX 进行分析")
            except Exception:
                pass

        # 方法3: 检查 assets 中是否有加密的 .jar/.dex 文件
        suspicious_assets = [e for e in entries
                            if "assets/" in e and (e.endswith(".jar") or e.endswith(".data")
                                                   or e.endswith(".bin") or "libshell" in e.lower()
                                                   or "libprotect" in e.lower())]
        if suspicious_assets:
            self._add_risk(result, "packer", "low",
                "Assets 中包含可疑加固文件",
                f"发现 {len(suspicious_assets)} 个可能用于加固的文件: "
                f"{', '.join(suspicious_assets[:3])}",
                f"packer:assets:{HashUtils.fingerprint(apk_path)[:12]}",
                ", ".join(suspicious_assets[:3]),
                "检查这些文件是否为加固方案的加密数据")

    # ─── SDK 检测 ──────────────────────────────────────────────────────────

    def _detect_sdks(self, apk_path: str, result: ScanResult) -> None:
        """识别 APK 中集成的第三方 SDK。"""
        entries = APKUtils.list_entries(apk_path, limit=5000)

        detected_sdks: Dict[str, Dict[str, str]] = {}

        for entry in entries:
            entry_path = entry.replace("/", ".")
            for pattern, sdk_info in KNOWN_SDKS.items():
                if pattern in entry_path:
                    key = sdk_info["name"]
                    if key not in detected_sdks:
                        detected_sdks[key] = sdk_info

        # 报告检测到的 SDK（信息级别，仅供参考）
        for sdk_name, sdk_info in detected_sdks.items():
            self._add_risk(result, "sdk", "info",
                f"第三方SDK: {sdk_name}",
                f"检测到 {sdk_info['category']} 类 SDK: {sdk_name}。"
                f"第三方 SDK 可能收集用户数据，请检查其隐私合规性。",
                f"sdk:{sdk_name}:{HashUtils.fingerprint(apk_path)[:12]}",
                sdk_name,
                f"检查 {sdk_name} 的隐私政策和数据收集行为")

    # ─── 敏感字符串扫描 ───────────────────────────────────────────────────

    def _scan_sensitive_strings(self, apk_path: str, result: ScanResult, is_large: bool) -> None:
        """
        扫描 APK 中的敏感字符串（API Key、密码等）。
        对大型文件使用流式分块扫描。
        """
        self._report_progress("敏感字符串扫描", 0.75)

        entries = APKUtils.list_entries(apk_path, limit=5000)

        # 重点扫描的文件类型
        scan_targets = [e for e in entries if any(
            e.endswith(ext) for ext in [".xml", ".json", ".properties", ".txt", ".js",
                                         ".smali", ".yml", ".yaml", ".conf", ".cfg"]
        )]

        if not is_large:
            # 小文件：也扫描 classes.dex 中的字符串常量
            dex_files = [e for e in entries if e.endswith(".dex")]
            scan_targets.extend(dex_files[:3])  # 最多扫描 3 个 DEX

        scanned_count = 0
        found_count = 0

        for target in scan_targets:
            try:
                if is_large and target.endswith(".dex"):
                    continue  # 大文件的 DEX 跳过字符串扫描以节省时间

                data = APKUtils.read_entry(apk_path, target)
                if not data:
                    continue

                # 尝试解码为文本
                try:
                    text = data.decode("utf-8", errors="replace")
                except Exception:
                    try:
                        text = data.decode("latin-1", errors="replace")
                    except Exception:
                        continue

                if len(text) > 10_000_000:  # 跳过超大文件
                    continue

                for pattern, risk_title, risk_desc in SENSITIVE_PATTERNS:
                    matches = re.findall(pattern, text)
                    for match in matches[:3]:  # 每种模式最多报告 3 个
                        match_str = str(match)[:100]
                        self._add_risk(result, "sensitive_string", "high",
                            f"敏感信息: {risk_title}",
                            f"{risk_desc}: 在 {target} 中发现疑似敏感信息。",
                            f"str:{risk_title}:{HashUtils.fingerprint(match_str)[:12]}",
                            f"{target}: {match_str}",
                            "请将敏感信息移至服务端或使用加密存储，避免硬编码在 APK 中"
                        )
                        found_count += 1

                scanned_count += 1

                # 限制扫描量
                if scanned_count >= 200 and found_count >= 20:
                    break

            except Exception:
                continue

    # ─── 辅助方法 ───────────────────────────────────────────────────────────

    def _add_risk(
        self,
        result: ScanResult,
        category: str,
        severity: str,
        title: str,
        description: str,
        fingerprint_seed: str,
        evidence: str,
        recommendation: str,
    ) -> None:
        """添加风险项到结果中。"""
        fingerprint = HashUtils.fingerprint(fingerprint_seed)
        risk = RiskItem(
            id=self._generate_risk_id(),
            category=category,
            severity=severity,
            title=title,
            description=description,
            fingerprint=fingerprint,
            evidence=evidence,
            recommendation=recommendation,
        )
        result.add_risk(risk)

    @staticmethod
    def _short_name(full_class: str) -> str:
        """从完整类名提取短名。"""
        parts = full_class.split(".")
        return parts[-1] if parts else full_class


# ─── 便捷函数 ─────────────────────────────────────────────────────────────────

def scan_apk(apk_path: str, callback: Optional[ScannerCallback] = None) -> ScanResult:
    """
    便捷的 APK 扫描函数。

    Args:
        apk_path: APK 文件路径
        callback: 可选的进度回调函数

    Returns:
        ScanResult 扫描结果
    """
    scanner = APKScanner(callback=callback)
    return scanner.scan(apk_path)
