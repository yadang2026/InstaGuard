"""
InstaGuard - 智能助手与自主执行引擎

理解自然语言指令，自主规划并执行安全扫描、分析与修复任务。
内置命令系统，支持对话记忆和连续追问。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import re
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils import log, Config, APKUtils, HashUtils, ProviderConfig
from provider_manager import get_provider_manager, ProviderManager
from scanner import RiskItem, ScanResult
from memory import MemoryDB
from experience import ExperienceDB
from ai_analyzer import AIAnalyzer
from repair_templates import get_template_registry, RepairTemplate
from executor import RepairExecutor, RepairPlan, RepairAction
from subagent import SubAgentManager, SubAgentTask
from web_search import WebSearchEngine, SearchResult, get_search_engine


# ─── 对话消息数据结构 ─────────────────────────────────────────────────────────

@dataclass
class ConversationMessage:
    """单条对话消息。"""
    role: str                                   # "user" / "assistant" / "system"
    content: str                                # 消息内容
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {"role": self.role, "content": self.content, "timestamp": self.timestamp}


# ─── ScanResult 辅助函数 ──────────────────────────────────────────────────────

def _get_risk_count(result: ScanResult, severity: str) -> int:
    """从 ScanResult.stats 安全获取严重程度计数。"""
    if hasattr(result, 'stats') and isinstance(result.stats, dict):
        return result.stats.get(severity, 0)
    return 0


def _get_risk_by_id(result: ScanResult, risk_id: str) -> Optional[RiskItem]:
    """根据 ID 查找风险项。"""
    for risk in result.risks:
        if risk.id == risk_id:
            return risk
    return None


def _ensure_risk_attrs(risk: RiskItem) -> None:
    """确保 RiskItem 具有修复所需的动态属性。"""
    if not hasattr(risk, 'repair_template_id'):
        setattr(risk, 'repair_template_id', None)
    if not hasattr(risk, 'repairable'):
        setattr(risk, 'repairable', True)


# ─── 智能助手 ─────────────────────────────────────────────────────────────────

class InstaGuardAgent:
    """
    InstaGuard 智能助手。

    功能：
    1. 理解自然语言指令，自主规划并执行任务
    2. 调用所有内部功能：扫描、分析、修复、记忆管理、供应商切换
    3. 执行危险操作前展示计划并请求确认
    4. 对话有记忆，支持连续追问和复杂任务流
    5. 内置命令系统
    """

    # 最大对话历史保留轮数
    MAX_HISTORY = 20

    # 危险操作关键词（需要确认）
    DANGEROUS_OPERATIONS = [
        "fix", "repair", "修复", "修改", "删除", "delete",
        "签名", "sign", "执行", "execute",
    ]

    def __init__(self):
        # 对话历史
        self._conversation_history: List[ConversationMessage] = []

        # 当前状态
        self._current_scan_result: Optional[ScanResult] = None
        self._current_repair_plan: Optional[RepairPlan] = None
        self._pending_confirmation: Optional[Dict[str, Any]] = None

        # 内部组件
        self._provider_manager: Optional[ProviderManager] = None
        self._ai_analyzer: Optional[AIAnalyzer] = None
        self._repair_executor: Optional[RepairExecutor] = None
        self._memory_db: Optional[MemoryDB] = None
        self._experience_db: Optional[ExperienceDB] = None
        self._template_registry = get_template_registry()
        self._config = Config()

        # 子代理和联网搜索（懒加载）
        self._subagent_manager: Optional[SubAgentManager] = None
        self._search_engine: Optional[WebSearchEngine] = None

        # 命令注册表
        self._commands: Dict[str, Tuple[Callable, str, str]] = self._build_commands()

        # 是否需要在危险操作前确认
        self._require_confirmation = True

        log.info("InstaGuardAgent 初始化完成")

    # ─── 属性（懒加载） ────────────────────────────────────────────────────

    @property
    def provider_manager(self) -> ProviderManager:
        if self._provider_manager is None:
            self._provider_manager = get_provider_manager()
        return self._provider_manager

    @property
    def ai_analyzer(self) -> AIAnalyzer:
        if self._ai_analyzer is None:
            self._ai_analyzer = AIAnalyzer()
        return self._ai_analyzer

    @property
    def repair_executor(self) -> RepairExecutor:
        if self._repair_executor is None:
            self._repair_executor = RepairExecutor()
        return self._repair_executor

    @property
    def memory_db(self) -> MemoryDB:
        if self._memory_db is None:
            self._memory_db = MemoryDB()
        return self._memory_db

    @property
    def experience_db(self) -> ExperienceDB:
        if self._experience_db is None:
            self._experience_db = ExperienceDB()
        return self._experience_db

    @property
    def subagent_manager(self) -> SubAgentManager:
        """懒加载子代理管理器。"""
        if self._subagent_manager is None:
            self._subagent_manager = SubAgentManager(agent_ref=self)
            log.info("子代理管理器已初始化")
        return self._subagent_manager

    @property
    def search_engine(self) -> WebSearchEngine:
        """懒加载联网搜索引擎。"""
        if self._search_engine is None:
            self._search_engine = get_search_engine()
            log.info("联网搜索引擎已初始化")
        return self._search_engine

    # ─── 命令系统构建 ──────────────────────────────────────────────────────

    def _build_commands(self) -> Dict[str, Tuple[Callable, str, str]]:
        """
        构建命令注册表。

        Returns:
            {命令名: (处理函数, 参数说明, 帮助描述)}
        """
        return {
            "scan": (self._cmd_scan, "<filepath>", "扫描 APK 文件"),
            "analyze": (self._cmd_analyze, "", "AI 分析最近的扫描结果"),
            "fix": (self._cmd_fix, "[risk_id ...]", "修复指定风险（空格分隔多个 ID）"),
            "fix_all": (self._cmd_fix_all, "", "修复所有可修复风险"),
            "status": (self._cmd_status, "", "查看当前状态"),
            "set_provider": (self._cmd_set_provider, "<name>", "切换 AI 供应商"),
            "set_model": (self._cmd_set_model, "<name>", "设置当前模型"),
            "providers": (self._cmd_list_providers, "", "列出可用 AI 供应商"),
            "history": (self._cmd_history, "", "查看对话历史摘要"),
            "clear": (self._cmd_clear, "", "清除上下文和对话历史"),
            "cache_stats": (self._cmd_cache_stats, "", "查看记忆缓存统计"),
            "confirm": (self._cmd_confirm, "", "确认执行待处理操作"),
            "cancel": (self._cmd_cancel, "", "取消待处理操作"),
            "subagent": (self._cmd_subagent, "status|cancel <id>", "管理子代理系统"),
            "search": (self._cmd_search, "<query>|fix <risk_id>", "联网搜索解决方案"),
            "help": (self._cmd_help, "", "显示帮助信息"),
        }

    # ─── 主入口：处理用户消息 ──────────────────────────────────────────────

    def process_message(self, text: str) -> str:
        """
        处理用户消息，返回助手回复。

        支持：
        - 内置命令（以 / 或命令名开头）
        - 自然语言理解（通过关键词匹配）
        - 确认响应（是/否/确认/取消）

        Args:
            text: 用户输入文本

        Returns:
            助手回复文本
        """
        text = text.strip()
        if not text:
            return "请输入指令。输入 help 查看可用命令。"

        # 记录用户消息
        self._add_to_history("user", text)

        # 1. 检查待确认操作
        if self._pending_confirmation:
            response = self._handle_confirmation(text)
            if response:
                self._add_to_history("assistant", response)
                return response

        # 2. 解析命令
        command, args = self._parse_command(text)

        if command and command in self._commands:
            handler, _, _ = self._commands[command]
            try:
                response = handler(args)
                self._add_to_history("assistant", response)
                return response
            except Exception as e:
                log.exception(f"命令执行失败 [{command}]: {e}")
                response = f"❌ 命令执行失败: {e}"
                self._add_to_history("assistant", response)
                return response

        # 3. 自然语言理解（简单关键词匹配）
        response = self._natural_language_process(text)
        self._add_to_history("assistant", response)
        return response

    def _parse_command(self, text: str) -> Tuple[Optional[str], str]:
        """
        解析命令。

        支持格式：
        - /scan /path/to/app.apk
        - scan /path/to/app.apk
        - fix R001 R002 R003

        Args:
            text: 输入文本

        Returns:
            (命令名, 参数文本)
        """
        text = text.strip()

        # 去掉前导 /
        if text.startswith("/"):
            text = text[1:]

        parts = text.split(maxsplit=1)
        cmd_name = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        return cmd_name, args

    def _natural_language_process(self, text: str) -> str:
        """
        简单自然语言处理。

        通过关键词匹配识别用户意图。

        Args:
            text: 用户输入

        Returns:
            助手回复
        """
        text_lower = text.lower()

        # 问候语
        if any(w in text_lower for w in ["你好", "hello", "hi", "hey"]):
            return (
                "👋 你好！我是 InstaGuard 智能安全助手。\n\n"
                "我可以帮你：\n"
                "• 扫描 APK 文件发现安全风险\n"
                "• 使用 AI 深度分析风险\n"
                "• 自动修复可修复的安全问题\n"
                "• 管理 AI 供应商和模型\n\n"
                "输入 help 查看完整命令列表，或直接告诉我你想做什么。"
            )

        # 扫描意图
        if any(w in text_lower for w in ["扫描", "scan", "检查", "分析apk", "检测"]):
            # 尝试提取文件路径
            path_match = re.search(r'["\']?([A-Za-z]:[^\s"\']+\.apk)["\']?', text)
            if not path_match:
                path_match = re.search(r'["\']?([^\s"\']+\.apk)["\']?', text)
            if path_match:
                filepath = path_match.group(1)
                return self._cmd_scan(filepath)
            return (
                "请提供要扫描的 APK 文件路径。\n"
                "用法: scan /path/to/app.apk"
            )

        # 分析意图
        if any(w in text_lower for w in ["分析", "analyze", "深度分析"]):
            if self._current_scan_result:
                # 检测是否需要启动子代理（大批量分析）
                risk_count = len(self._current_scan_result.risks)
                if risk_count > 10 and any(w in text_lower for w in ["深度", "全面", "完整", "详细"]):
                    # 自动启动子代理并行分析
                    self._auto_spawn_subagent_for_analyze()
                    return self._cmd_analyze("")
                return self._cmd_analyze("")
            return "请先扫描一个 APK 文件。用法: scan /path/to/app.apk"

        # 修复意图
        if any(w in text_lower for w in ["修复", "fix", "repair", "修补"]):
            if "全部" in text or "所有" in text or "all" in text_lower:
                # 检测是否需要启动子代理（批量修复）
                if self._current_scan_result:
                    repairable_count = sum(1 for r in self._current_scan_result.risks
                                          if getattr(r, 'repairable', True))
                    if repairable_count > 5:
                        self._auto_spawn_subagent_for_fix()
                return self._cmd_fix_all("")
            if self._current_scan_result:
                return self._cmd_fix_all("")
            return "请先扫描一个 APK 文件。用法: scan /path/to/app.apk"

        # 搜索意图 —— 联网搜索
        if any(w in text_lower for w in ["为什么失败", "怎么修复", "帮我查", "帮我搜",
                                          "搜索", "查找", "上网查", "联网查询",
                                          "为什么", "怎么做", "如何修复"]):
            return self._handle_nl_search(text)

        # 状态查询
        if any(w in text_lower for w in ["状态", "status", "进度", "怎么样"]):
            return self._cmd_status("")

        # 帮助
        if any(w in text_lower for w in ["帮助", "help", "怎么用", "功能"]):
            return self._cmd_help("")

        # 关于
        if any(w in text_lower for w in ["关于", "about", "版本", "version"]):
            return (
                "🛡️ InstaGuard v1.0.0\n"
                "Android APK 安全扫描与修复应用\n\n"
                "功能：\n"
                "• 多引擎 APK 安全扫描\n"
                "• AI 深度风险分析（多供应商支持）\n"
                "• 自动修复引擎\n"
                "• ⚡ 记忆加速缓存\n"
                "• 📚 经验库学习\n\n"
                "输入 help 查看命令列表。"
            )

        # 默认回复
        return (
            f"我可以帮你进行 APK 安全分析和修复。\n\n"
            f"当前状态: {'已加载扫描结果' if self._current_scan_result else '空闲'}\n"
            f"已连接供应商: {len(self.provider_manager.get_enabled_providers())} 个\n\n"
            f"你可以：\n"
            f"• 输入 scan <文件路径> 扫描 APK\n"
            f"• 输入 help 查看所有命令\n"
            f"• 直接描述你想做的事情"
        )

    # ─── 确认处理 ──────────────────────────────────────────────────────────

    def _handle_confirmation(self, text: str) -> Optional[str]:
        """
        处理待确认操作的响应。

        Args:
            text: 用户输入

        Returns:
            响应文本，None 表示不是确认响应
        """
        text_lower = text.lower()
        confirm_words = ["是", "yes", "确认", "confirm", "y", "ok", "好", "执行", "可以", "继续"]
        cancel_words = ["否", "no", "取消", "cancel", "n", "不", "停止", "stop"]

        if any(w == text_lower for w in confirm_words):
            pending = self._pending_confirmation
            self._pending_confirmation = None
            return self._execute_pending(pending)

        if any(w == text_lower for w in cancel_words):
            pending = self._pending_confirmation
            self._pending_confirmation = None
            action_desc = pending.get("description", "操作") if pending else "操作"
            return f"❌ 已取消: {action_desc}"

        return None

    def _request_confirmation(self, operation: str, details: str, action_data: Dict[str, Any]) -> str:
        """
        请求用户确认危险操作。

        Args:
            operation: 操作名称
            details: 操作详情
            action_data: 待执行的操作数据

        Returns:
            提示消息
        """
        self._pending_confirmation = {
            "operation": operation,
            "details": details,
            "data": action_data,
        }
        return (
            f"⚠️ **确认操作: {operation}**\n\n"
            f"{details}\n\n"
            f"回复 **确认/是** 执行操作，回复 **取消/否** 放弃。"
        )

    def _execute_pending(self, pending: Dict[str, Any]) -> str:
        """
        执行待确认的操作。

        Args:
            pending: 待执行操作数据

        Returns:
            执行结果
        """
        operation = pending.get("operation", "")
        data = pending.get("data", {})

        if operation == "fix_all":
            return self._execute_fix_internal(data.get("risk_ids", []))
        elif operation == "fix":
            return self._execute_fix_internal(data.get("risk_ids", []))

        return "未知的待执行操作。"

    # ─── 命令实现：scan ────────────────────────────────────────────────────

    def _cmd_scan(self, args: str) -> str:
        """
        扫描 APK 文件。

        Args:
            args: APK 文件路径

        Returns:
            扫描结果摘要
        """
        filepath = args.strip().strip('"').strip("'")

        if not filepath:
            return "❌ 请提供 APK 文件路径。用法: scan /path/to/app.apk"

        if not os.path.exists(filepath):
            return f"❌ 文件不存在: {filepath}"

        if not APKUtils.is_valid_apk(filepath):
            return f"❌ 不是有效的 APK 文件: {filepath}"

        return self.scan_apk(filepath)

    def scan_apk(self, filepath: str) -> str:
        """
        扫描 APK 文件（完整流程）。

        Args:
            filepath: APK 文件路径

        Returns:
            扫描结果摘要
        """
        log.info(f"🔍 开始扫描: {filepath}")

        # 清除旧结果
        self._current_scan_result = None
        self._current_repair_plan = None

        apk_size = APKUtils.get_file_size_mb(filepath)

        # 检查文件大小限制
        max_size = self._config.get_setting("max_apk_size_mb", 500)
        if apk_size > max_size:
            return f"❌ APK 文件过大 ({apk_size:.1f} MB)，超过限制 ({max_size} MB)"

        # 读取 APK 内容
        entries = APKUtils.list_entries(filepath, limit=2000)

        # 读取 AndroidManifest.xml（二进制格式）
        manifest_data = APKUtils.read_entry(filepath, "AndroidManifest.xml")

        # 扫描风险（使用实际 RiskItem 字段）
        risks: List[RiskItem] = []
        risk_index = 0

        # --- 检查 1: android:debuggable ---
        risk_index += 1
        if manifest_data and b"debuggable" in manifest_data.lower():
            risk = RiskItem(
                id=f"R{risk_index:03d}",
                category="debuggable",
                severity="high",
                title="应用处于可调试状态",
                description="AndroidManifest.xml 中 android:debuggable 设置为 true，攻击者可通过 ADB 获取应用数据。",
                fingerprint="",
                evidence='android:debuggable="true"',
                recommendation="将 android:debuggable 设为 false",
            )
            _ensure_risk_attrs(risk)
            risks.append(risk)

        # --- 检查 2: android:allowBackup ---
        risk_index += 1
        if manifest_data and b"allowBackup" in manifest_data.lower():
            risk = RiskItem(
                id=f"R{risk_index:03d}",
                category="backup",
                severity="medium",
                title="应用允许备份",
                description="android:allowBackup 未禁用，用户数据可能通过 ADB backup 被导出。",
                fingerprint="",
                evidence='android:allowBackup="true"',
                recommendation="将 android:allowBackup 设为 false",
            )
            _ensure_risk_attrs(risk)
            risks.append(risk)

        # --- 检查 3: 导出组件 ---
        risk_index += 1
        has_exported = False
        exported_components = []
        if manifest_data:
            for comp_type in [b"activity", b"service", b"receiver", b"provider"]:
                if comp_type in manifest_data.lower():
                    has_exported = True
                    exported_components.append(comp_type.decode())
        if has_exported:
            risk = RiskItem(
                id=f"R{risk_index:03d}",
                category="exported",
                severity="medium",
                title=f"存在导出组件: {', '.join(exported_components[:3])}",
                description=(
                    "APK 包含可能被外部调用的导出组件（Activity/Service/Receiver/Provider），"
                    "若未设置权限验证，可能被恶意应用利用。"
                ),
                fingerprint="",
                evidence=f"exported 组件: {', '.join(exported_components)}",
                recommendation="为非必要组件设置 android:exported=\"false\"，并为导出组件添加权限验证",
            )
            _ensure_risk_attrs(risk)
            risks.append(risk)

        # --- 检查 4: 签名文件 ---
        risk_index += 1
        signature_files = [e for e in entries if "META-INF/" in e and (e.endswith(".RSA") or e.endswith(".DSA") or e.endswith(".EC"))]
        if not signature_files:
            risk = RiskItem(
                id=f"R{risk_index:03d}",
                category="signature",
                severity="critical",
                title="APK 签名缺失",
                description="APK 未包含有效的签名文件（META-INF/*.RSA/DSA/EC），无法验证完整性。",
                fingerprint="",
                evidence="META-INF 中无签名文件",
                recommendation="使用 apksigner 或 jarsigner 重新签名",
            )
            _ensure_risk_attrs(risk)
            risks.append(risk)

        # --- 检查 5: 权限过多 ---
        risk_index += 1
        dangerous_permissions = [
            "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "WRITE_CONTACTS",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_SMS",
            "SEND_SMS", "READ_PHONE_STATE", "CALL_PHONE", "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
        ]
        found_permissions = []
        if manifest_data:
            for perm in dangerous_permissions:
                if perm.encode() in manifest_data:
                    found_permissions.append(perm)
        if len(found_permissions) > 3:
            risk = RiskItem(
                id=f"R{risk_index:03d}",
                category="permission",
                severity="medium",
                title=f"声明了 {len(found_permissions)} 个危险权限",
                description=f"应用声明了多个危险权限: {', '.join(found_permissions[:5])}。应确认是否实际使用，遵循最小权限原则。",
                fingerprint="",
                evidence=f"危险权限: {', '.join(found_permissions)}",
                recommendation="删除未使用的危险权限声明",
            )
            _ensure_risk_attrs(risk)
            risks.append(risk)
        elif found_permissions:
            risk = RiskItem(
                id=f"R{risk_index:03d}",
                category="permission",
                severity="low",
                title=f"声明了危险权限: {', '.join(found_permissions)}",
                description="应用声明了危险权限，应确认必要性。",
                fingerprint="",
                evidence=f"危险权限: {', '.join(found_permissions)}",
                recommendation="确认权限必要性，移除不必要的权限",
            )
            _ensure_risk_attrs(risk)
            risks.append(risk)

        # --- 检查 6: usesCleartextTraffic ---
        risk_index += 1
        if manifest_data and b"usesCleartextTraffic" in manifest_data.lower():
            risk = RiskItem(
                id=f"R{risk_index:03d}",
                category="cleartext_traffic",
                severity="high",
                title="允许明文网络流量",
                description="android:usesCleartextTraffic 设置为 true，应用可能使用 HTTP 明文通信。",
                fingerprint="",
                evidence='android:usesCleartextTraffic="true"',
                recommendation="设置 android:usesCleartextTraffic=\"false\" 强制 HTTPS",
            )
            _ensure_risk_attrs(risk)
            risks.append(risk)

        # --- 检查 7: 检查 classes.dex ---
        risk_index += 1
        has_classes_dex = any("classes.dex" in e for e in entries)
        if not has_classes_dex:
            risk = RiskItem(
                id=f"R{risk_index:03d}",
                category="structure",
                severity="info",
                title="APK 缺少 classes.dex",
                description="APK 中未找到 classes.dex 文件，可能不是标准的 Android 应用。",
                fingerprint="",
                evidence="classes.dex 文件缺失",
                recommendation="确认 APK 来源是否可靠",
            )
            setattr(risk, 'repairable', False)
            risks.append(risk)

        # --- 检查 8: 文件条目统计 ---
        risk_index += 1
        dex_count = sum(1 for e in entries if e.endswith(".dex"))
        so_count = sum(1 for e in entries if e.endswith(".so"))

        # 创建扫描结果（使用实际 ScanResult API）
        result = ScanResult()
        result.apk_path = filepath
        result.file_size_mb = apk_size
        result.package_name = "未知"
        for risk in risks:
            result.add_risk(risk)
        setattr(result, 'analyzed', False)  # 添加动态属性

        self._current_scan_result = result

        # 生成摘要
        crit = _get_risk_count(result, "critical")
        high = _get_risk_count(result, "high")
        med = _get_risk_count(result, "medium")
        low = _get_risk_count(result, "low")
        info_count = _get_risk_count(result, "info")
        total = result.stats.get("total", len(risks))

        summary = (
            f"✅ **扫描完成**\n\n"
            f"📁 文件: {os.path.basename(filepath)}\n"
            f"📦 大小: {apk_size:.2f} MB\n"
            f"📊 风险统计:\n"
            f"   🔴 严重: {crit}\n"
            f"   🟠 高风险: {high}\n"
            f"   🟡 中风险: {med}\n"
            f"   🟢 低风险: {low}\n"
            f"   ℹ️  信息: {info_count}\n"
            f"   📝 总计: {total}\n\n"
        )

        # 列出主要风险
        if risks:
            summary += "**主要风险:**\n"
            for risk in risks[:10]:
                severity_icon = {
                    "critical": "🔴", "high": "🟠", "medium": "🟡",
                    "low": "🟢", "info": "ℹ️",
                }.get(risk.severity, "⚪")
                repairable_label = " [可修复]" if getattr(risk, 'repairable', True) else ""
                summary += f"  {severity_icon} [{risk.id}] {risk.title}{repairable_label}\n"
            if len(risks) > 10:
                summary += f"  ... 还有 {len(risks) - 10} 个风险\n"

        summary += "\n💡 输入 **analyze** 进行 AI 深度分析，或输入 **fix_all** 修复所有可修复风险。"

        return summary

    # ─── 命令实现：analyze ─────────────────────────────────────────────────

    def _cmd_analyze(self, args: str) -> str:
        """AI 分析当前扫描结果。"""
        if not self._current_scan_result:
            return "❌ 没有可分析的扫描结果。请先执行 scan <filepath>。"

        if not self._current_scan_result.risks:
            return "📭 扫描结果中无风险项，无需分析。"

        return self.analyze_current()

    def analyze_current(self) -> str:
        """
        AI 分析当前扫描结果。

        Returns:
            分析结果
        """
        if not self._current_scan_result:
            return "❌ 无扫描结果。"

        result = self._current_scan_result
        total = len(result.risks)
        log.info(f"🔬 开始 AI 分析: {total} 个风险")

        # 检查 AI 供应商可用性
        enabled = self.provider_manager.get_enabled_providers()
        if not enabled:
            return (
                "⚠️ 没有可用的 AI 供应商。\n\n"
                "请先配置 AI 供应商和 API Key：\n"
                "• set_provider <供应商名>\n"
                "• 在设置中添加 API Key\n\n"
                "将使用离线分析（基于模板匹配）。"
            )

        # 保存分析前的状态
        provider_name = self.ai_analyzer.provider_name
        model = self.ai_analyzer.model

        # 执行分析
        self.ai_analyzer.analyze_scan_result(
            result,
            provider_name=provider_name,
        )

        # 统计结果
        analyzed_count = sum(1 for r in result.risks if r.ai_analysis)
        has_template_count = sum(
            1 for r in result.risks
            if getattr(r, 'repair_template_id', None)
        )

        # 标记已分析
        setattr(result, 'analyzed', True)

        summary = (
            f"✅ **AI 分析完成**\n\n"
            f"📊 分析统计: {analyzed_count}/{total} 成功\n"
            f"🔧 匹配修复模板: {has_template_count} 个\n"
            f"🤖 使用供应商: {provider_name or '自动'}\n"
            f"📦 使用模型: {model or '自动'}\n\n"
        )

        # 按严重程度展示分析结果
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_risks = sorted(
            result.risks,
            key=lambda r: (severity_order.get(r.severity.lower(), 99), r.id)
        )

        for risk in sorted_risks[:5]:
            if risk.ai_analysis:
                # 截取分析摘要
                analysis_text = risk.ai_analysis
                try:
                    parsed = json.loads(analysis_text)
                    assessment = parsed.get("risk_assessment", analysis_text)[:120]
                except json.JSONDecodeError:
                    assessment = analysis_text[:120]

                template_info = f" → {getattr(risk, 'repair_template_id', '')}" if getattr(risk, 'repair_template_id', None) else ""
                summary += (
                    f"**[{risk.id}] {risk.title}**{template_info}\n"
                    f"> {assessment}...\n\n"
                )

        if len(sorted_risks) > 5:
            summary += f"... 还有 {len(sorted_risks) - 5} 个风险的分析结果\n\n"

        summary += "💡 输入 **fix_all** 生成修复计划并执行修复。"

        return summary

    # ─── 命令实现：fix / fix_all ───────────────────────────────────────────

    def _cmd_fix(self, args: str) -> str:
        """
        修复指定风险。

        Args:
            args: 风险 ID 列表（空格分隔）

        Returns:
            操作结果
        """
        if not self._current_scan_result:
            return "❌ 没有可用的扫描结果。请先执行 scan <filepath>。"

        risk_ids = args.strip().split() if args.strip() else []
        if not risk_ids:
            return "❌ 请指定要修复的风险 ID。用法: fix R001 R002\n输入 status 查看所有风险。"

        # 验证 ID
        valid_ids = {r.id for r in self._current_scan_result.risks}
        invalid_ids = [rid for rid in risk_ids if rid not in valid_ids]
        if invalid_ids:
            return f"❌ 无效的风险 ID: {', '.join(invalid_ids)}\n可用 ID: {', '.join(sorted(valid_ids))}"

        return self.execute_fix(risk_ids)

    def _cmd_fix_all(self, args: str) -> str:
        """修复所有可修复风险。"""
        if not self._current_scan_result:
            return "❌ 没有可用的扫描结果。请先执行 scan <filepath>。"

        repairable = [
            r.id for r in self._current_scan_result.risks
            if getattr(r, 'repairable', True)
        ]
        if not repairable:
            return "📭 没有可自动修复的风险。部分风险需要人工处理。"

        # 需要确认
        if self._require_confirmation:
            risk_details = "\n".join(
                f"  • [{r.id}] {r.title}"
                for r in self._current_scan_result.risks
                if r.id in repairable
            )
            return self._request_confirmation(
                "fix_all",
                f"将修复 {len(repairable)} 个风险：\n{risk_details}\n\n"
                f"⚠️ 修复操作将修改 APK 文件并重新签名。将自动创建备份。",
                {"risk_ids": repairable},
            )

        return self.execute_fix(repairable)

    def execute_fix(self, risk_ids: List[str]) -> str:
        """
        执行修复操作。

        Args:
            risk_ids: 要修复的风险 ID 列表

        Returns:
            执行结果
        """
        if self._require_confirmation and not self._pending_confirmation:
            risk_details = "\n".join(
                f"  • [{r.id}] {r.title}"
                for r in self._current_scan_result.risks
                if r.id in risk_ids
            ) if self._current_scan_result else ""
            return self._request_confirmation(
                "fix",
                f"将修复 {len(risk_ids)} 个风险：\n{risk_details}",
                {"risk_ids": risk_ids},
            )

        return self._execute_fix_internal(risk_ids)

    def _execute_fix_internal(self, risk_ids: List[str]) -> str:
        """
        内部修复执行逻辑。

        Args:
            risk_ids: 风险 ID 列表

        Returns:
            执行结果
        """
        if not self._current_scan_result:
            return "❌ 无扫描结果。"

        log.info(f"🔧 开始修复: {len(risk_ids)} 个风险")

        # 1. 确保已完成 AI 分析
        unanalyzed = [
            r for r in self._current_scan_result.risks
            if r.id in risk_ids and not r.ai_analysis
        ]
        if unanalyzed:
            log.info(f"有 {len(unanalyzed)} 个风险未分析，先进行快速分析...")
            for risk in unanalyzed:
                self.ai_analyzer.analyze_risk(risk)

        # 2. 创建修复计划
        self._current_repair_plan = self.repair_executor.create_repair_plan(
            self._current_scan_result,
            selected_risks=risk_ids,
        )

        if not self._current_repair_plan.actions:
            return (
                "⚠️ 无法生成修复计划。\n\n"
                "可能原因：\n"
                "• 选中的风险没有匹配的修复模板\n"
                "• 风险需要人工处理\n\n"
                "输入 analyze 进行 AI 分析以获取更精准的修复建议。"
            )

        # 3. 预览变更
        preview = self.repair_executor.preview_changes(self._current_repair_plan)

        preview_text = (
            f"📋 **修复计划预览**\n\n"
            f"计划ID: {preview['plan_id']}\n"
            f"操作数: {preview['total_actions']}\n"
            f"影响文件: {', '.join(preview['files_affected'])}\n"
            f"需要重签名: {'是' if preview['requires_resign'] else '否'}\n"
            f"创建备份: {'是' if preview['backup_will_be_created'] else '否'}\n\n"
        )

        if preview["estimated_risks"]:
            preview_text += "⚠️ 潜在风险:\n"
            for risk_note in preview["estimated_risks"]:
                preview_text += f"  • {risk_note}\n"
            preview_text += "\n"

        preview_text += "**操作列表:**\n"
        for action in preview["actions"]:
            preview_text += (
                f"  [{action['action_id']}] {action['description']}\n"
                f"     目标: {action['target_file']} | 方式: {action['modify_type']}\n"
            )

        preview_text += "\n---\n"

        # 4. 执行修复
        def repair_callback(stage: str, message: str, progress: int) -> None:
            pass  # 进度由内部日志记录

        output_path = self.repair_executor.execute(
            self._current_repair_plan,
            callback=repair_callback,
        )

        if output_path:
            # 验证
            verification = self.repair_executor.verify(output_path)

            preview_text += (
                f"✅ **修复成功！**\n\n"
                f"📁 修复后 APK: {output_path}\n"
                f"📦 文件大小: {verification['size_mb']:.2f} MB\n"
                f"🔏 签名状态: {'✅ 已签名' if verification['signed'] else '⚠️ 未签名'}\n"
                f"✅ 验证结果: {'通过' if verification['pass'] else '发现问题'}\n\n"
            )

            if verification["issues"]:
                preview_text += "⚠️ 发现的问题:\n"
                for issue in verification["issues"]:
                    preview_text += f"  • {issue}\n"
                preview_text += "\n"

            if self._current_repair_plan.backup_path:
                preview_text += f"💾 原始备份: {self._current_repair_plan.backup_path}\n"

            preview_text += "\n💡 建议在真机/模拟器上测试修复后的 APK。"
        else:
            preview_text += (
                "❌ **修复失败**\n\n"
                "请检查日志了解详细错误信息。\n"
                f"备份文件: {self._current_repair_plan.backup_path or '无'}\n"
            )

        return preview_text

    # ─── 命令实现：status ──────────────────────────────────────────────────

    def _cmd_status(self, args: str) -> str:
        """查看当前状态。"""
        parts = ["📊 **当前状态**\n"]

        # 扫描结果
        if self._current_scan_result:
            sr = self._current_scan_result
            crit = _get_risk_count(sr, "critical")
            high = _get_risk_count(sr, "high")
            med = _get_risk_count(sr, "medium")
            low = _get_risk_count(sr, "low")
            total = sr.stats.get("total", len(sr.risks))
            analyzed = getattr(sr, 'analyzed', False)

            parts.append(
                f"📁 已加载 APK: {os.path.basename(sr.apk_path)}\n"
                f"📦 大小: {sr.file_size_mb:.2f} MB\n"
                f"📊 风险: {total} 个 "
                f"(🔴{crit} 🟠{high} 🟡{med} 🟢{low})\n"
                f"🤖 AI分析: {'✅ 已完成' if analyzed else '❌ 未分析'}\n\n"
            )

            # 列出风险
            parts.append("**风险列表:**\n")
            for risk in sr.risks:
                analyzed_icon = "✅" if risk.ai_analysis else "❌"
                status_icon = {
                    "critical": "🔴", "high": "🟠", "medium": "🟡",
                    "low": "🟢", "info": "ℹ️",
                }.get(risk.severity, "⚪")
                repairable_icon = "🔧" if getattr(risk, 'repairable', True) else "🔒"
                parts.append(
                    f"  {status_icon} [{risk.id}] {risk.title} "
                    f"| AI:{analyzed_icon} | {repairable_icon}\n"
                )
        else:
            parts.append("📭 无扫描结果。输入 scan <filepath> 开始扫描。\n")

        parts.append("\n")

        # 修复计划
        if self._current_repair_plan:
            rp = self._current_repair_plan
            parts.append(
                f"📋 修复计划: {rp.plan_id}\n"
                f"   操作数: {rp.total_actions}\n"
                f"   状态: {rp.status}\n"
            )
        else:
            parts.append("📋 修复计划: 无\n")

        parts.append("\n")

        # AI 供应商
        enabled_providers = self.provider_manager.get_enabled_providers()
        parts.append(f"🤖 AI 供应商: {len(enabled_providers)} 个已启用\n")
        for name, provider in enabled_providers.items():
            model_info = provider.active_model or (provider.models[0] if provider.models else "未设置")
            parts.append(f"   • {name}: {model_info}\n")

        # 对话历史
        parts.append(f"\n💬 对话历史: {len(self._conversation_history)} 条\n")

        # 记忆缓存
        cache_stats = self.memory_db.get_stats()
        parts.append(f"⚡ 记忆缓存: {cache_stats.get('total_memories', cache_stats.get('total_entries', 0))} 条\n")

        # 待确认
        if self._pending_confirmation:
            parts.append(
                f"\n⚠️ 有待确认操作: {self._pending_confirmation.get('operation', 'N/A')}\n"
                f"   回复 确认/取消\n"
            )

        return "".join(parts)

    # ─── 命令实现：set_provider / set_model ────────────────────────────────

    def _cmd_set_provider(self, args: str) -> str:
        """切换 AI 供应商。"""
        provider_name = args.strip()
        if not provider_name:
            available = list(self.provider_manager.get_all_providers().keys())
            return (
                f"请指定供应商名称。可用供应商: {', '.join(available)}\n"
                f"用法: set_provider openai"
            )

        provider = self.provider_manager.get_provider(provider_name)
        if not provider:
            available = list(self.provider_manager.get_all_providers().keys())
            return f"❌ 未知供应商: {provider_name}\n可用供应商: {', '.join(available)}"

        if not provider.enabled:
            return (
                f"⚠️ 供应商 {provider_name} 未启用。\n"
                f"请在设置中启用并配置 API Key。"
            )

        self.ai_analyzer.set_default_provider(provider_name)
        return (
            f"✅ 已切换 AI 供应商: {provider_name}\n"
            f"   端点: {provider.default_endpoint}\n"
            f"   可用模型: {', '.join(provider.models[:5])}"
        )

    def _cmd_set_model(self, args: str) -> str:
        """设置当前模型。"""
        model_name = args.strip()
        if not model_name:
            return "❌ 请指定模型名称。用法: set_model gpt-4o"

        # 获取当前供应商
        provider_name = self.ai_analyzer.provider_name
        if not provider_name:
            # 使用第一个启用的供应商
            enabled = self.provider_manager.get_enabled_providers()
            if enabled:
                provider_name = list(enabled.keys())[0]
            else:
                return "❌ 没有可用的 AI 供应商。请先配置供应商。"

        success = self.provider_manager.set_active_model(provider_name, model_name)
        if success:
            self.ai_analyzer.model = model_name
            return f"✅ 已设置模型: {model_name} (供应商: {provider_name})"
        else:
            return f"❌ 设置模型失败。请确认供应商 {provider_name} 存在。"

    def _cmd_list_providers(self, args: str) -> str:
        """列出所有可用供应商。"""
        all_providers = self.provider_manager.get_all_providers()
        if not all_providers:
            return "📭 没有配置任何 AI 供应商。"

        parts = ["🤖 **AI 供应商列表**\n\n"]
        for name, provider in all_providers.items():
            status = "✅ 已启用" if provider.enabled else "❌ 已禁用"
            has_key = "🔑 有Key" if provider.api_keys else "🔒 无Key"
            models = provider.models[:5] if provider.models else ["无"]
            parts.append(
                f"**{name}** ({provider.display_name}) {status} {has_key}\n"
                f"   端点: {provider.default_endpoint or '未设置'}\n"
                f"   模型: {', '.join(models)}\n"
                f"   活跃模型: {provider.active_model or '自动'}\n\n"
            )

        return "".join(parts)

    # ─── 命令实现：history / clear ─────────────────────────────────────────

    def _cmd_history(self, args: str) -> str:
        """查看对话历史摘要。"""
        if not self._conversation_history:
            return "📭 对话历史为空。"

        parts = [f"💬 **对话历史** (最近 {min(len(self._conversation_history), 10)} 条)\n\n"]
        for i, msg in enumerate(self._conversation_history[-10:]):
            role_icon = {"user": "👤", "assistant": "🤖", "system": "⚙️"}.get(msg.role, "❓")
            content_preview = msg.content[:80].replace("\n", " ")
            parts.append(f"{role_icon} [{i+1}] {content_preview}...\n")

        return "".join(parts)

    def _cmd_clear(self, args: str) -> str:
        """清除上下文。"""
        self.clear_context()
        return "✅ 上下文和对话历史已清除。"

    # ─── 命令实现：cache_stats ─────────────────────────────────────────────

    def _cmd_cache_stats(self, args: str) -> str:
        """查看记忆缓存统计。"""
        stats = self.memory_db.get_stats()
        exp_stats = self.experience_db.get_stats()

        return (
            f"⚡ **记忆缓存统计**\n"
            f"   总条目: {stats.get('total_memories', stats.get('total_entries', 0))}\n"
            f"   总命中: {stats.get('total_hits', 0)}\n"
            f"   类别: {len(stats.get('categories', {}))} 类\n\n"
            f"📚 **经验库统计**\n"
            f"   总条目: {exp_stats.get('total_entries', 0)}\n"
            f"   成功: {exp_stats.get('successful', 0)} | 失败: {exp_stats.get('failed', 0)}\n"
            f"   成功率: {exp_stats.get('success_rate', 0)}%\n"
            f"   24小时内: {exp_stats.get('last_24h', 0)} 条\n"
        )

    def _cmd_subagent(self, args: str) -> str:
        """管理子代理系统。

        Args:
            args: status | cancel <task_id>

        Returns:
            子代理状态或取消结果
        """
        args = args.strip().lower()

        if not args or args == "status":
            # 查看子代理状态
            s = self.subagent_manager.get_status()
            lines = ["🤖 **子代理系统状态**\n", ""]

            active = s.get("active_count", 0)
            queued = s.get("queue_size", 0)

            lines.append(f"📊 运行中: {active}/{s.get('max_workers', 3)} | 排队: {queued} | 已完成: {s.get('completed_count', 0)}")
            lines.append("")

            active_tasks = s.get("active_tasks", {})
            if active_tasks:
                lines.append("**活跃任务:**")
                for tid, t in active_tasks.items():
                    type_icon = {
                        "scan": "🔍", "analyze": "🔬", "fix": "🔧", "research": "🔎",
                    }.get(t.get("task_type", ""), "📋")
                    status_icon = "▶️" if t.get("status") == "running" else "⏳"
                    lines.append(f"  {type_icon} {status_icon} [{tid}] {t.get('task_type', '?')} (优先级: {t.get('priority', 0)})")
                lines.append("")

            queue = s.get("queue", [])
            if queue:
                lines.append("**等待队列:**")
                for t in queue:
                    lines.append(f"  ⏳ [{t.get('task_id', '?')}] {t.get('task_type', '?')}")
                lines.append("")

            if not active_tasks and not queue:
                lines.append("📭 当前没有活跃的子代理任务。")

            # 子代理结果摘要
            results = self.subagent_manager.collect_results()
            if results:
                lines.append("")
                lines.append(self.subagent_manager.summarize_results())

            return "\n".join(lines)

        elif args.startswith("cancel"):
            # 取消子代理
            task_id = args[len("cancel"):].strip()
            if not task_id:
                return "❌ 请指定要取消的任务 ID。用法: subagent cancel <task_id>"

            if task_id == "all":
                count = self.subagent_manager.cancel_all()
                return f"✅ 已取消 {count} 个子代理任务。"

            if self.subagent_manager.cancel_task(task_id):
                return f"✅ 已取消子代理任务: {task_id}"
            return f"❌ 未找到子代理任务: {task_id}"

        else:
            return "❌ 未知子命令。用法: subagent [status|cancel <task_id>]"

    # ─── 命令实现：search ──────────────────────────────────────────────────

    def _cmd_search(self, args: str) -> str:
        """联网搜索解决方案。

        Args:
            args: 搜索查询文本，或 "fix <risk_id>" 搜索特定风险的修复方案

        Returns:
            搜索结果
        """
        args = args.strip()

        if not args:
            return (
                "🔍 **联网搜索**\n\n"
                "用法:\n"
                "  search <查询内容> — 搜索 Android 安全相关问题\n"
                "  search fix <risk_id> — 搜索特定风险的修复方案\n\n"
                "示例:\n"
                "  search Android 12 debuggable false\n"
                "  search fix R001\n"
                "  search APK signing best practice"
            )

        # 检测 "fix <risk_id>" 模式
        if args.startswith("fix "):
            risk_id = args[4:].strip()
            return self._search_risk_fix(risk_id)

        # 普通搜索
        engine = self.search_engine
        log.info(f"联网搜索: {args[:80]}...")

        # 检查网络可用性
        if not engine.is_available():
            return (
                "⚠️ 搜索服务暂不可用（网络连接失败）。\n\n"
                "建议:\n"
                "• 检查网络连接\n"
                "• 稍后重试\n"
                "• 使用其他命令手动操作"
            )

        results = engine.search(args, max_results=8, focus="security")

        if not results:
            return "🔍 未找到相关结果。请尝试调整搜索关键词。"

        return engine.extract_solution(results) or "🔍 搜索完成，但无法提取有效方案。"

    def _search_risk_fix(self, risk_id: str) -> str:
        """搜索特定风险的修复方案。

        Args:
            risk_id: 风险 ID（如 R001）

        Returns:
            搜索到的修复方案
        """
        if not self._current_scan_result:
            return "❌ 没有扫描结果。请先执行 scan <filepath>。"

        risk = None
        for r in self._current_scan_result.risks:
            if r.id == risk_id:
                risk = r
                break

        if not risk:
            valid_ids = [r.id for r in self._current_scan_result.risks]
            return f"❌ 未找到风险 {risk_id}。可用 ID: {', '.join(valid_ids)}"

        log.info(f"搜索修复方案: {risk_id} - {risk.title}")

        engine = self.search_engine
        if not engine.is_available():
            return (
                "⚠️ 搜索服务暂不可用。\n\n"
                f"风险 [{risk_id}] {risk.title}\n"
                f"类别: {risk.category}\n"
                f"建议: {risk.recommendation}"
            )

        results = engine.search_security_issue(risk.title, risk.category)

        if not results:
            return (
                f"🔍 未找到 [{risk_id}] {risk.title} 的在线修复方案。\n\n"
                f"📋 本地建议: {risk.recommendation}"
            )

        solution = engine.extract_solution(results)
        return (
            f"🔍 **[{risk_id}] {risk.title} 的修复方案**\n\n"
            f"{solution or '无法提取方案，请查看原始搜索结果。'}"
        )

    # ─── 自然语言搜索处理 ─────────────────────────────────────────────────

    def _handle_nl_search(self, text: str) -> str:
        """处理自然语言搜索请求。

        从用户输入中提取搜索内容，执行联网搜索。

        Args:
            text: 用户输入

        Returns:
            搜索结果
        """
        text_lower = text.lower()

        # 如果有当前风险上下文，搜索当前问题
        if self._current_scan_result:
            # 查找风险引用
            risk_match = re.search(r'[Rr](\d{3})', text)
            if risk_match:
                risk_id = f"R{risk_match.group(1)}"
                return self._search_risk_fix(risk_id)

            # 尝试将问题与当前风险关联
            if any(w in text_lower for w in ["修复", "fix", "repair"]):
                # 提取提到的风险关键词
                for risk in self._current_scan_result.risks:
                    risk_keywords = risk.category.split("_")
                    for kw in risk_keywords:
                        if kw in text_lower:
                            return self._search_risk_fix(risk.id)

        # 提取搜索查询：去掉前缀词
        prefixes = ["为什么失败", "怎么修复", "帮我查", "帮我搜", "帮我查一下",
                     "搜索", "查找", "上网查", "联网查询", "为什么", "怎么做", "如何修复"]
        query = text
        for prefix in prefixes:
            if query.lower().startswith(prefix):
                query = query[len(prefix):].strip()
                break

        # 如果查询太短，添加 Android 安全上下文
        if len(query) < 5:
            query = f"Android APK security {query}"

        return self._cmd_search(query)

    # ─── 子代理自动启动 ───────────────────────────────────────────────────

    def _auto_spawn_subagent_for_analyze(self) -> None:
        """自动评估分析任务复杂度并启动子代理。"""
        if not self._current_scan_result:
            return

        risks_data = [
            {
                "id": r.id,
                "category": r.category,
                "title": r.title,
            }
            for r in self._current_scan_result.risks
        ]

        data = {
            "risks": risks_data,
            "risk_count": len(risks_data),
        }

        task_ids = self.subagent_manager.auto_split_and_spawn("analyze", data)
        if task_ids:
            log.info(f"自动启动 {len(task_ids)} 个分析子代理")

    def _auto_spawn_subagent_for_fix(self) -> None:
        """自动评估修复任务复杂度并启动子代理。"""
        if not self._current_scan_result:
            return

        repairable_risks = [
            r for r in self._current_scan_result.risks
            if getattr(r, "repairable", True)
        ]

        risks_data = [
            {
                "id": r.id,
                "category": r.category,
                "title": r.title,
                "repair_template_id": getattr(r, "repair_template_id", None),
            }
            for r in repairable_risks
        ]

        data = {
            "risks": risks_data,
            "fix_count": len(risks_data),
            "risk_ids": [r.id for r in repairable_risks],
        }

        task_ids = self.subagent_manager.auto_split_and_spawn("fix", data)
        if task_ids:
            log.info(f"自动启动 {len(task_ids)} 个修复子代理")

    def _init_subagent(self) -> SubAgentManager:
        """显式初始化子代理管理器。

        Returns:
            子代理管理器实例
        """
        return self.subagent_manager

    def _init_web_search(self) -> WebSearchEngine:
        """显式初始化联网搜索引擎。

        Returns:
            搜索引擎实例
        """
        return self.search_engine

    # ─── 命令实现：confirm / cancel ────────────────────────────────────────

    def _cmd_confirm(self, args: str) -> str:
        """确认执行待处理操作。"""
        return self._handle_confirmation("确认") or "⚠️ 当前没有待确认的操作。"

    def _cmd_cancel(self, args: str) -> str:
        """取消待处理操作。"""
        return self._handle_confirmation("取消") or "⚠️ 当前没有待确认的操作。"

    # ─── 命令实现：help ────────────────────────────────────────────────────

    def _cmd_help(self, args: str) -> str:
        """显示帮助信息。"""
        lines = [
            "🛡️ **InstaGuard 帮助**\n",
            "内置命令：\n",
        ]

        for cmd_name, (_, params, desc) in self._commands.items():
            param_display = f" {params}" if params else ""
            lines.append(f"  **{cmd_name}**{param_display} — {desc}\n")

        lines.extend([
            "\n",
            "快捷操作：\n",
            "  • 直接拖拽 APK 文件发送路径即可扫描\n",
            "  • 回复「是/确认」执行待确认操作\n",
            "  • 回复「否/取消」放弃操作\n",
            "\n",
            "自然语言示例：\n",
            "  • 「帮我扫描这个 APK」+ 文件路径\n",
            "  • 「分析一下安全风险」\n",
            "  • 「修复所有问题」\n",
            "  • 「切换到 OpenAI」\n",
            "  • 「当前状态怎么样」\n",
        ])

        return "".join(lines)

    # ─── 对话历史管理 ─────────────────────────────────────────────────────

    def _add_to_history(self, role: str, content: str) -> None:
        """
        添加消息到对话历史。

        Args:
            role: 角色（user/assistant/system）
            content: 消息内容
        """
        msg = ConversationMessage(role=role, content=content)
        self._conversation_history.append(msg)

        # 限制历史长度
        if len(self._conversation_history) > self.MAX_HISTORY * 2:
            self._conversation_history = self._conversation_history[-self.MAX_HISTORY * 2:]

    def get_conversation_history(self) -> List[Dict[str, Any]]:
        """
        获取对话历史。

        Returns:
            对话历史字典列表
        """
        return [msg.to_dict() for msg in self._conversation_history]

    def clear_context(self) -> None:
        """清除上下文和对话历史。"""
        self._conversation_history.clear()
        self._current_scan_result = None
        self._current_repair_plan = None
        self._pending_confirmation = None
        log.info("上下文已清除")

    # ─── 公共方法 ──────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """
        获取当前状态的完整字典。

        Returns:
            状态字典
        """
        scan_info = None
        if self._current_scan_result:
            sr = self._current_scan_result
            scan_info = {
                "apk_path": sr.apk_path,
                "file_size_mb": sr.file_size_mb,
                "package_name": sr.package_name,
                "total_risks": sr.stats.get("total", len(sr.risks)),
                "stats": sr.stats,
                "analyzed": getattr(sr, 'analyzed', False),
                "risk_ids": [r.id for r in sr.risks],
            }

        repair_info = None
        if self._current_repair_plan:
            repair_info = {
                "plan_id": self._current_repair_plan.plan_id,
                "total_actions": self._current_repair_plan.total_actions,
                "status": self._current_repair_plan.status,
            }

        return {
            "has_scan_result": self._current_scan_result is not None,
            "scan_result": scan_info,
            "has_repair_plan": self._current_repair_plan is not None,
            "repair_plan": repair_info,
            "has_pending_confirmation": self._pending_confirmation is not None,
            "history_length": len(self._conversation_history),
            "providers_enabled": len(self.provider_manager.get_enabled_providers()),
        }

    def set_confirmation_required(self, required: bool) -> None:
        """
        设置是否需要在危险操作前确认。

        Args:
            required: 是否需要确认
        """
        self._require_confirmation = required
        log.info(f"操作确认: {'开启' if required else '关闭'}")

    def reset(self) -> None:
        """完全重置助手状态。"""
        self.clear_context()
        self._ai_analyzer = None
        self._repair_executor = None
        log.info("助手已完全重置")


# ─── 便捷函数 ─────────────────────────────────────────────────────────────────

_agent_instance: Optional[InstaGuardAgent] = None


def get_agent() -> InstaGuardAgent:
    """获取 InstaGuardAgent 单例。"""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = InstaGuardAgent()
    return _agent_instance
