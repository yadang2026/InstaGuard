"""
InstaGuard - 修复模板库

预置 15+ 条常见 Android 安全问题修复模板。
支持按类别、关键词搜索，可被 AI 分析和经验库补充。

Author: InstaGuard Team
Version: 1.0.0
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from utils import log


# ─── 修复模板数据类 ──────────────────────────────────────────────────────────

@dataclass
class RepairTemplate:
    """单个修复模板。"""
    template_id: str                            # 模板唯一 ID
    category: str                               # 适用风险类别
    title: str                                  # 模板标题（中文）
    description: str                            # 模板详细描述
    modify_target: str                          # 修改目标: "manifest" / "smali" / "resource" / "binary" / "manual"
    file_pattern: str = ""                      # 目标文件名匹配（如 "AndroidManifest.xml"）
    xpath: str = ""                             # XML 修改的 XPath（如适用）
    search_pattern: str = ""                    # 搜索/替换模式（正则或文本）
    replacement: str = ""                       # 替换内容
    risk_level: str = "medium"                  # 操作风险等级
    reversible: bool = True                     # 是否可逆
    requires_resign: bool = True                # 是否需要重新签名
    ai_enhancement: Optional[str] = None        # AI 增强建议
    tags: List[str] = field(default_factory=list)  # 标签

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典。"""
        return {
            "template_id": self.template_id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "modify_target": self.modify_target,
            "file_pattern": self.file_pattern,
            "risk_level": self.risk_level,
            "reversible": self.reversible,
            "requires_resign": self.requires_resign,
            "tags": self.tags,
        }


# ─── 预置模板数据 ────────────────────────────────────────────────────────────

# 15+ 条预置修复模板（中文）
BUILTIN_TEMPLATES: List[Dict[str, Any]] = [
    {
        "template_id": "TPL001",
        "category": "debuggable",
        "title": "移除调试标志",
        "description": (
            "将 AndroidManifest.xml 中 <application> 标签的 android:debuggable 属性设为 false，"
            "或直接删除该属性。发布版本应始终禁用调试模式，以防止攻击者通过 ADB 获取应用敏感信息。"
        ),
        "modify_target": "manifest",
        "file_pattern": "AndroidManifest.xml",
        "xpath": "//application/@android:debuggable",
        "search_pattern": r'android:debuggable="true"',
        "replacement": r'android:debuggable="false"',
        "risk_level": "low",
        "reversible": True,
        "requires_resign": True,
        "tags": ["调试", "debug", "安全配置"],
    },
    {
        "template_id": "TPL002",
        "category": "backup",
        "title": "禁用应用备份",
        "description": (
            "将 AndroidManifest.xml 中 <application> 标签的 android:allowBackup 属性设为 false，"
            "防止应用数据通过 ADB backup 被导出，保护用户隐私数据不被泄露。"
        ),
        "modify_target": "manifest",
        "file_pattern": "AndroidManifest.xml",
        "xpath": "//application/@android:allowBackup",
        "search_pattern": r'android:allowBackup="true"',
        "replacement": r'android:allowBackup="false"',
        "risk_level": "low",
        "reversible": True,
        "requires_resign": True,
        "tags": ["备份", "backup", "数据安全"],
    },
    {
        "template_id": "TPL003",
        "category": "permission",
        "title": "移除多余权限",
        "description": (
            "检查 AndroidManifest.xml 中声明的危险权限（如 CAMERA、LOCATION、READ_CONTACTS 等），"
            "删除应用实际未使用的权限声明。遵循最小权限原则，减少攻击面。"
        ),
        "modify_target": "manifest",
        "file_pattern": "AndroidManifest.xml",
        "risk_level": "medium",
        "reversible": True,
        "requires_resign": True,
        "tags": ["权限", "permission", "最小权限"],
    },
    {
        "template_id": "TPL004",
        "category": "exported",
        "title": "设置组件 exported=false",
        "description": (
            "为非必要导出的 Activity、Service、BroadcastReceiver、ContentProvider 组件"
            "添加 android:exported=\"false\" 属性，防止外部应用未经授权调用组件。"
        ),
        "modify_target": "manifest",
        "file_pattern": "AndroidManifest.xml",
        "risk_level": "medium",
        "reversible": True,
        "requires_resign": True,
        "tags": ["导出", "exported", "组件安全"],
    },
    {
        "template_id": "TPL005",
        "category": "network_security",
        "title": "启用网络安全配置",
        "description": (
            "在 res/xml/ 目录下创建 network_security_config.xml 文件，并在 AndroidManifest.xml 中"
            "通过 android:networkSecurityConfig 属性引用。配置可信 CA、证书固定和明文流量策略。"
        ),
        "modify_target": "resource",
        "file_pattern": "network_security_config.xml",
        "risk_level": "low",
        "reversible": True,
        "requires_resign": True,
        "tags": ["网络安全", "SSL", "证书"],
    },
    {
        "template_id": "TPL006",
        "category": "webview",
        "title": "加固 WebView 安全",
        "description": (
            "在不必要的场景禁用 JavaScript（setJavaScriptEnabled(false)），禁止文件访问"
            "（setAllowFileAccess(false)），禁止 File 协议（setAllowFileAccessFromFileURLs(false)），"
            "启用安全浏览模式。防止 WebView 中的 XSS 攻击和本地文件泄露。"
        ),
        "modify_target": "smali",
        "file_pattern": "*.smali",
        "risk_level": "medium",
        "reversible": True,
        "requires_resign": True,
        "tags": ["WebView", "XSS", "JavaScript"],
    },
    {
        "template_id": "TPL007",
        "category": "hardcoded_key",
        "title": "移除硬编码密钥",
        "description": (
            "注释或移除代码中硬编码的 API Key、AES Key、Token 等敏感信息。"
            "建议使用 Android Keystore、环境变量或服务端下发的方式管理密钥。"
            "此模板标记代码位置，需人工确认后修改。"
        ),
        "modify_target": "smali",
        "file_pattern": "*.smali",
        "risk_level": "high",
        "reversible": True,
        "requires_resign": True,
        "tags": ["硬编码", "密钥", "敏感信息"],
    },
    {
        "template_id": "TPL008",
        "category": "obfuscation",
        "title": "启用代码混淆",
        "description": (
            "在 proguard-rules.pro 中启用代码混淆（-obfuscationdictionary、-dontshrink 等配置），"
            "使反编译后的代码难以阅读。在 build.gradle 中确保 minifyEnabled 为 true。"
            "建议同时启用资源压缩（shrinkResources）。"
        ),
        "modify_target": "resource",
        "file_pattern": "proguard-rules.pro",
        "risk_level": "low",
        "reversible": True,
        "requires_resign": True,
        "tags": ["混淆", "ProGuard", "R8"],
    },
    {
        "template_id": "TPL009",
        "category": "signature",
        "title": "修复 APK 签名",
        "description": (
            "检测到 APK 签名异常或缺失。需要使用 apksigner 或 jarsigner 重新签名。"
            "签名前建议备份原始 APK。注意：重新签名后应用签名将改变，可能影响应用更新。"
        ),
        "modify_target": "binary",
        "risk_level": "high",
        "reversible": False,
        "requires_resign": True,
        "tags": ["签名", "signature", "V1/V2"],
    },
    {
        "template_id": "TPL010",
        "category": "intent_filter",
        "title": "为导出组件添加权限验证",
        "description": (
            "对于设置了 android:exported=\"true\" 且包含 intent-filter 的组件，"
            "添加 android:permission 属性要求调用方持有特定权限，或通过代码中 checkCallingPermission() 验证。"
        ),
        "modify_target": "manifest",
        "file_pattern": "AndroidManifest.xml",
        "risk_level": "medium",
        "reversible": True,
        "requires_resign": True,
        "tags": ["intent-filter", "权限", "组件安全"],
    },
    {
        "template_id": "TPL011",
        "category": "cleartext_traffic",
        "title": "禁止明文流量",
        "description": (
            "在 AndroidManifest.xml 的 <application> 标签中设置 android:usesCleartextTraffic=\"false\"，"
            "禁止应用使用 HTTP 明文流量，强制所有网络通信使用 HTTPS。"
        ),
        "modify_target": "manifest",
        "file_pattern": "AndroidManifest.xml",
        "xpath": "//application/@android:usesCleartextTraffic",
        "search_pattern": r'android:usesCleartextTraffic="true"',
        "replacement": r'android:usesCleartextTraffic="false"',
        "risk_level": "low",
        "reversible": True,
        "requires_resign": True,
        "tags": ["明文", "HTTP", "HTTPS", "网络安全"],
    },
    {
        "template_id": "TPL012",
        "category": "ssl_pinning",
        "title": "SSL 证书锁定",
        "description": (
            "建议在应用中添加 SSL Certificate Pinning（证书锁定），防止中间人攻击。"
            "可以通过 network_security_config.xml 配置 <pin-set>，"
            "或使用 OkHttp 的 CertificatePinner。注意定期更新证书指纹。"
        ),
        "modify_target": "resource",
        "file_pattern": "network_security_config.xml",
        "risk_level": "low",
        "reversible": True,
        "requires_resign": True,
        "tags": ["SSL Pinning", "证书锁定", "中间人攻击"],
    },
    {
        "template_id": "TPL013",
        "category": "test_component",
        "title": "移除测试组件",
        "description": (
            "删除仅用于开发测试的导出 Activity、Service 或 BroadcastReceiver 组件，"
            "这些组件可能暴露敏感调试接口。从 AndroidManifest.xml 中移除对应声明。"
        ),
        "modify_target": "manifest",
        "file_pattern": "AndroidManifest.xml",
        "risk_level": "high",
        "reversible": True,
        "requires_resign": True,
        "tags": ["测试", "test", "调试组件"],
    },
    {
        "template_id": "TPL014",
        "category": "provider_permission",
        "title": "ContentProvider 访问权限",
        "description": (
            "为导出的 ContentProvider 添加 android:readPermission 和 android:writePermission 属性，"
            "设置适当的访问权限级别（如 signature），防止数据被第三方应用读取或篡改。"
        ),
        "modify_target": "manifest",
        "file_pattern": "AndroidManifest.xml",
        "risk_level": "medium",
        "reversible": True,
        "requires_resign": True,
        "tags": ["ContentProvider", "permission", "数据安全"],
    },
    {
        "template_id": "TPL015",
        "category": "log_leak",
        "title": "清理日志泄露",
        "description": (
            "移除生产环境中可能泄露敏感信息的 Log 输出（Log.d/Log.e/Log.w 等）。"
            "检查是否输出了用户 Token、密码、手机号、身份证号等敏感数据。"
            "建议使用 ProGuard 的 -assumenosideeffects 配置在编译时移除日志。"
        ),
        "modify_target": "smali",
        "file_pattern": "*.smali",
        "risk_level": "medium",
        "reversible": True,
        "requires_resign": True,
        "tags": ["日志", "敏感信息", "Log"],
    },
    {
        "template_id": "TPL016",
        "category": "root_detection",
        "title": "添加 Root 检测",
        "description": (
            "建议添加 Root 环境检测逻辑，检查 su 二进制文件、Magisk、SuperSU 等常见 Root 工具的存在。"
            "检测到 Root 环境后可限制敏感功能使用或给出安全提示。"
        ),
        "modify_target": "smali",
        "file_pattern": "*.smali",
        "risk_level": "low",
        "reversible": True,
        "requires_resign": True,
        "tags": ["Root", "越狱检测", "环境安全"],
    },
    {
        "template_id": "TPL017",
        "category": "emulator_detection",
        "title": "添加模拟器检测",
        "description": (
            "建议添加模拟器环境检测逻辑，检查 Build.FINGERPRINT、Build.HARDWARE、"
            "TelephonyManager.getDeviceId() 等特征值，防止应用在模拟器中运行遭受逆向分析。"
        ),
        "modify_target": "smali",
        "file_pattern": "*.smali",
        "risk_level": "low",
        "reversible": True,
        "requires_resign": True,
        "tags": ["模拟器", "逆向防护", "环境检测"],
    },
]

# ─── 模板注册表 ──────────────────────────────────────────────────────────────

class TemplateRegistry:
    """
    修复模板注册表。

    管理所有预置和用户自定义的修复模板。
    支持按类别、关键词搜索。
    """

    def __init__(self):
        self._templates: Dict[str, RepairTemplate] = {}
        self._load_builtin_templates()

    def _load_builtin_templates(self) -> None:
        """加载预置模板。"""
        for tmpl_data in BUILTIN_TEMPLATES:
            template = RepairTemplate(**tmpl_data)
            self._templates[template.template_id] = template
        log.info(f"已加载 {len(self._templates)} 条预置修复模板")

    def get_template(self, template_id: str) -> Optional[RepairTemplate]:
        """
        根据模板 ID 获取修复模板。

        Args:
            template_id: 模板唯一 ID

        Returns:
            RepairTemplate 或 None
        """
        return self._templates.get(template_id)

    def get_templates_for_category(self, category: str) -> List[RepairTemplate]:
        """
        获取指定风险类别的所有模板。

        Args:
            category: 风险类别（如 "debuggable", "permission"）

        Returns:
            匹配的模板列表
        """
        cat_lower = category.lower()
        return [
            t for t in self._templates.values()
            if t.category.lower() == cat_lower
        ]

    def get_all_templates(self) -> List[RepairTemplate]:
        """
        获取所有模板。

        Returns:
            所有模板列表
        """
        return list(self._templates.values())

    def search_templates(self, query: str) -> List[RepairTemplate]:
        """
        按关键词搜索模板。

        搜索范围：标题、描述、类别、标签。

        Args:
            query: 搜索关键词

        Returns:
            匹配的模板列表（按相关度排序）
        """
        query_lower = query.lower()
        results: List[RepairTemplate] = []

        for template in self._templates.values():
            score = 0
            # 标题精确匹配
            if query_lower in template.title.lower():
                score += 10
            # 类别匹配
            if query_lower in template.category.lower():
                score += 8
            # 描述匹配
            if query_lower in template.description.lower():
                score += 3
            # 标签匹配
            for tag in template.tags:
                if query_lower in tag.lower():
                    score += 5
                    break

            if score > 0:
                results.append(template)

        # 按得分降序排列
        results.sort(key=lambda t: (
            10 if query_lower in t.title.lower() else 0,
            8 if query_lower in t.category.lower() else 0,
        ), reverse=True)

        return results

    def add_template(self, template: RepairTemplate) -> bool:
        """
        添加自定义模板。

        Args:
            template: 修复模板对象

        Returns:
            是否添加成功
        """
        if template.template_id in self._templates:
            log.warning(f"模板 ID 已存在: {template.template_id}")
            return False
        self._templates[template.template_id] = template
        log.info(f"已添加自定义模板: {template.template_id} - {template.title}")
        return True

    def remove_template(self, template_id: str) -> bool:
        """
        移除模板（仅允许移除自定义模板）。

        Args:
            template_id: 模板 ID

        Returns:
            是否移除成功
        """
        if template_id.startswith("TPL") and template_id[3:].isdigit():
            log.warning(f"不能移除预置模板: {template_id}")
            return False
        if template_id in self._templates:
            del self._templates[template_id]
            log.info(f"已移除模板: {template_id}")
            return True
        return False

    def get_categories(self) -> List[str]:
        """
        获取所有风险类别。

        Returns:
            去重后的类别列表
        """
        return sorted(set(t.category for t in self._templates.values()))

    def get_template_count(self) -> int:
        """获取模板总数。"""
        return len(self._templates)


# ─── 全局实例 ─────────────────────────────────────────────────────────────────

_template_registry: Optional[TemplateRegistry] = None


def get_template_registry() -> TemplateRegistry:
    """获取 TemplateRegistry 单例。"""
    global _template_registry
    if _template_registry is None:
        _template_registry = TemplateRegistry()
    return _template_registry
