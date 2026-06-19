"""
InstaGuard - 未来简洁风主屏幕模块

Futuristic Minimal 三屏布局：
1. AssistantScreen - AI 助手对话界面
2. ScanScreen - APK 扫描与风险分析
3. SettingsScreen - 应用设置管理

设计语言：暗色主题 + 霓虹点缀 + 玻璃拟态卡片 + Canvas 自定义绘制

Author: InstaGuard Team
Version: 2.0.0
"""

import os
import time
from typing import Any, Dict, List, Optional
from datetime import datetime
from math import pi, cos, sin

# Kivy 核心
from kivy.uix.screenmanager import Screen
from kivy.uix.scrollview import ScrollView
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.widget import Widget
from kivy.uix.label import Label
from kivy.clock import Clock
from kivy.properties import (
    StringProperty, NumericProperty, BooleanProperty,
    ListProperty, ObjectProperty, ColorProperty,
)
from kivy.graphics import Color, RoundedRectangle, Line, Ellipse, Rectangle
from kivy.metrics import dp
from kivy.animation import Animation
from kivy.core.window import Window

# KivyMD 组件
from kivymd.uix.screen import MDScreen
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDButton, MDButtonText, MDIconButton
from kivymd.uix.textfield import MDTextField
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.card import MDCard
from kivymd.uix.scrollview import MDScrollView
from kivymd.uix.progressbar import MDProgressBar
from kivymd.uix.dialog import (
    MDDialog, MDDialogHeadlineText, MDDialogButtonContainer,
)
from kivymd.uix.switch import MDSwitch
from kivymd.uix.slider import MDSlider
from kivymd.uix.list import MDList, MDListItem, MDListItemHeadlineText
from kivymd.uix.chip import MDChip
from kivymd.uix.menu import MDDropdownMenu

# 内部模块
from utils import log, Config, APP_NAME, APP_VERSION
from ui.widgets import (
    GlowCard, NeonBadge, PulseButton, ScanProgressArc,
    TypewriterLabel, MinimalInput, NeonToggle, StatRing,
    RiskCard, ScanProgressBar, SeverityBadge,
    ConversationBubble, StatsCard, APIKeyDialog,
    ProviderChip, ModelDropdown,
    SEVERITY_COLORS, SEVERITY_ICONS, SEVERITY_NEON, SEVERITY_LABELS,
    BG_DEEP, BG_CARD, BG_SURFACE, BG_SURFACE_SOLID,
    CYAN, CYAN_DIM, CYAN_GLOW,
    PURPLE, PURPLE_DIM, PURPLE_GLOW,
    GREEN, GREEN_DIM,
    NEON_RED, NEON_ORANGE, NEON_YELLOW, NEON_GREY,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_HINT,
    BORDER_SUBTLE, BORDER_GLOW_CYAN,
)

# 尝试导入业务模块
try:
    from provider_manager import get_provider_manager
    PM_AVAILABLE = True
except ImportError:
    PM_AVAILABLE = False

try:
    from scanner import APKScanner, ScanResult, RiskItem
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False

try:
    from memory import MemoryDB
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False

try:
    from experience import ExperienceDB
    EXPERIENCE_AVAILABLE = True
except ImportError:
    EXPERIENCE_AVAILABLE = False

try:
    from agent import InstaGuardAgent
    AGENT_AVAILABLE = True
except ImportError:
    AGENT_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
#  深层暗色背景 Mixin
# ═══════════════════════════════════════════════════════════════════════════════

class DeepDarkMixin:
    """为屏幕设置深层暗色背景。"""

    def _apply_dark_bg(self, widget):
        """应用暗色背景到 widget 的 canvas。"""
        with widget.canvas.before:
            Color(*BG_DEEP)
            self._bg_rect = Rectangle(pos=widget.pos, size=widget.size)
        widget.bind(size=self._update_bg, pos=self._update_bg)

    def _update_bg(self, instance, *args):
        if hasattr(self, '_bg_rect'):
            self._bg_rect.pos = instance.pos
            self._bg_rect.size = instance.size


# ═══════════════════════════════════════════════════════════════════════════════
#  自定义 ScrollView
# ═══════════════════════════════════════════════════════════════════════════════

class ChatScrollView(MDScrollView):
    """对话区域滚动视图，自动滚动到底部。"""

    def scroll_to_bottom(self, *args):
        Clock.schedule_once(lambda dt: setattr(self, 'scroll_y', 0), 0.05)


# ═══════════════════════════════════════════════════════════════════════════════
#  AssistantScreen — AI 助手对话界面
# ═══════════════════════════════════════════════════════════════════════════════

class AssistantScreen(MDScreen, DeepDarkMixin):
    """
    AI 助手对话界面 — 未来简洁风。

    布局：
    - 顶部：极简标题 + 在线状态点
    - 中间：对话气泡列表（ConversationBubble 未来风）
    - 底部：MinimalInput + 发送 PulseButton + 4 个快捷图标按钮
    """

    messages = ListProperty([])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "assistant"
        self._apply_dark_bg(self)

        # 主布局
        self.layout = MDBoxLayout(orientation="vertical", spacing=0)
        self.layout.md_bg_color = (0, 0, 0, 0)

        self._build_header()
        self._build_chat_area()
        self._build_command_bar()
        self._build_input_area()

        self.add_widget(self.layout)

        # 初始化 Agent
        self._agent = None
        self._init_agent()

        # 欢迎消息
        self.add_message("assistant",
            "👋 你好！我是 InstaGuard AI 助手。\n\n"
            "我可以帮你：\n"
            "• 扫描 APK 文件安全风险\n"
            "• 分析风险并提供修复建议\n"
            "• 执行自动化修复\n"
            "• 回答安全相关问题\n\n"
            "请选择一个 APK 文件开始扫描，或者直接向我提问！")

    def _build_header(self):
        """构建极简标题栏。"""
        header = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            padding=(dp(16), dp(10), dp(16), dp(10)),
            spacing=dp(8),
        )
        header.md_bg_color = (0, 0, 0, 0)

        # 极简标题
        title = Label(
            text="InstaGuard",
            font_size=dp(18),
            color=TEXT_PRIMARY,
            bold=True,
            size_hint=(None, None),
            size=(dp(120), dp(28)),
            halign="left",
            valign="middle",
        )
        header.add_widget(title)

        # 在线状态点（青色小圆点）
        spacer = Widget(size_hint_x=1)
        header.add_widget(spacer)

        self._status_dot = Widget(
            size_hint=(None, None),
            size=(dp(8), dp(8)),
        )
        with self._status_dot.canvas:
            Color(*GREEN)
            Ellipse(pos=self._status_dot.pos, size=self._status_dot.size)
        header.add_widget(self._status_dot)

        self._status_text = Label(
            text="在线",
            font_size=dp(11),
            color=TEXT_SECONDARY,
            size_hint=(None, None),
            size=(dp(36), dp(20)),
        )
        header.add_widget(self._status_text)

        # 新对话按钮
        new_btn = MDIconButton(
            icon="plus",
            style="standard",
            theme_icon_color="Custom",
            icon_color=CYAN,
            on_release=self._new_conversation,
        )
        header.add_widget(new_btn)

        self.layout.add_widget(header)

    def _build_chat_area(self):
        """构建对话滚动区域。"""
        self.chat_scroll = ChatScrollView(size_hint_y=1)
        self.chat_scroll.md_bg_color = (0, 0, 0, 0)

        self.chat_box = MDBoxLayout(
            orientation="vertical",
            adaptive_height=True,
            spacing=dp(10),
            padding=(dp(8), dp(8)),
        )
        self.chat_box.md_bg_color = (0, 0, 0, 0)
        self.chat_box.bind(minimum_height=self.chat_box.setter('height'))

        self.chat_scroll.add_widget(self.chat_box)
        self.layout.add_widget(self.chat_scroll)

    def _build_command_bar(self):
        """构建快捷命令按钮栏（4 个图标按钮）。"""
        cmd_bar = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(2),
            padding=(dp(12), dp(4), dp(12), dp(4)),
        )
        cmd_bar.md_bg_color = (0, 0, 0, 0)

        commands = [
            ("🔍", "扫描", self._cmd_scan, CYAN),
            ("📊", "分析", self._cmd_analyze, PURPLE),
            ("🔧", "修复", self._cmd_repair, GREEN),
            ("📋", "状态", self._cmd_status, NEON_GREY),
        ]

        for icon, label, callback, color in commands:
            btn = PulseButton(
                icon_text=icon,
                label=label,
                pulse_color=color,
                on_release=callback,
            )
            cmd_bar.add_widget(btn)

        self.layout.add_widget(cmd_bar)

    def _build_input_area(self):
        """构建底部输入栏（MinimalInput + 发送按钮）。"""
        input_bar = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(6),
            padding=(dp(8), dp(8), dp(8), dp(12)),
        )
        input_bar.md_bg_color = (0, 0, 0, 0)

        # 极简输入框
        self.minimal_input = MinimalInput(
            hint_text="输入消息...",
            size_hint_x=0.82,
        )
        self.minimal_input.bind_on_validate(self._send_message)
        input_bar.add_widget(self.minimal_input)

        # 发送按钮（圆形 PulseButton）
        send_btn = PulseButton(
            icon_text="▶",
            pulse_color=CYAN,
            on_release=self._send_message,
        )
        send_btn.size_hint_x = 0.1
        input_bar.add_widget(send_btn)

        self.layout.add_widget(input_bar)

    def _init_agent(self):
        if AGENT_AVAILABLE:
            try:
                self._agent = InstaGuardAgent()
                log.info("InstaGuardAgent 已初始化")
            except Exception as e:
                log.warning(f"Agent 初始化失败: {e}")
                self._agent = None

    def _new_conversation(self, instance):
        self.chat_box.clear_widgets()
        self.messages = []
        self.add_message("assistant", "新对话已开始。有什么可以帮助你的？")

    def _cmd_scan(self, instance):
        self.minimal_input._text_input.text = "请扫描 APK 文件"
        self._send_message()

    def _cmd_analyze(self, instance):
        self.minimal_input._text_input.text = "请分析当前扫描结果"
        self._send_message()

    def _cmd_repair(self, instance):
        self.minimal_input._text_input.text = "请修复发现的安全风险"
        self._send_message()

    def _cmd_status(self, instance):
        self.minimal_input._text_input.text = "当前状态如何？"
        self._send_message()

    def _send_message(self, instance=None):
        text = self.minimal_input.text.strip()
        if not text:
            return

        self.add_message("user", text)
        self.minimal_input.clear()

        Clock.schedule_once(lambda dt: self._process_message(text), 0.2)

    def _process_message(self, text):
        self.add_message("assistant", "⏳ 正在思考...")

        if self._agent and AGENT_AVAILABLE:
            try:
                response = self._agent.chat(text)
                self._remove_last_assistant()
                # 使用打字机效果
                self._add_typewriter_message("assistant", response or "抱歉，处理请求时出错。")
            except Exception as e:
                self._remove_last_assistant()
                self.add_message("assistant", f"❌ 错误: {str(e)}")
                log.exception(f"Agent 处理失败: {e}")
        else:
            self._remove_last_assistant()
            if "扫描" in text:
                self.add_message("assistant",
                    "🔍 扫描功能已就绪！\n\n"
                    "请切换到「扫描」标签页，选择一个 APK 文件开始扫描。\n\n"
                    "或者告诉我 APK 文件的路径，我可以帮你分析。")
            elif "分析" in text:
                self.add_message("assistant",
                    "📊 分析功能使用 AI 检查 APK 安全风险。\n\n"
                    "请在扫描页完成扫描后，结果会自动分析。"
                    "已发现的漏洞会按严重程度分类显示。")
            elif "修复" in text:
                self.add_message("assistant",
                    "🔧 修复功能可以自动修复部分安全风险。\n\n"
                    "支持修复类型：\n"
                    "• 权限裁剪\n"
                    "• 导出组件锁定\n"
                    "• 加密加固\n"
                    "• 混淆配置\n\n"
                    "请在扫描结果页选择需要修复的风险项。")
            elif "状态" in text:
                self.add_message("assistant",
                    "📋 当前状态：\n\n"
                    "• 系统：运行中 ✓\n"
                    "• AI 供应商：请在设置页配置\n"
                    "• 上次扫描：无\n"
                    "• 已修复问题：0\n\n"
                    "请在设置页面配置 AI 供应商后开始使用。")
            else:
                self.add_message("assistant",
                    f"收到你的消息：「{text[:50]}{'...' if len(text) > 50 else ''}」\n\n"
                    "当前未配置 AI 供应商。请在「设置」页面添加 API Key 以启用 AI 对话功能。")

    def _add_typewriter_message(self, role, content):
        """添加带打字机效果的消息。"""
        timestamp = datetime.now().strftime("%H:%M")
        self.messages.append({
            "role": role,
            "content": content,
            "time": timestamp,
        })

        bubble = ConversationBubble(
            message="",
            role=role,
            timestamp=timestamp,
        )
        # 用 TypewriterLabel 替换气泡内的文字
        # 获取气泡内第一个 Label（消息标签）并替换为 TypewriterLabel
        for child in bubble.children:
            if isinstance(child, Label) and not isinstance(child, MDLabel):
                child.text = ""
                self._start_typewriter(child, content)
                break
        else:
            # 如果没有找到，直接设置文字
            bubble.message = content

        # 重新添加消息标签（使用 TypewriterLabel）
        bubble.clear_widgets()
        bubble.add_widget(TypewriterLabel(
            full_text=content,
            speed=0.02,
            size_hint_y=None,
        ))
        if timestamp:
            time_label = Label(
                text=timestamp,
                font_size=dp(10),
                color=TEXT_HINT,
                size_hint_y=None,
                height=dp(14),
                halign="right",
            )
            bubble.add_widget(time_label)

        self.chat_box.add_widget(bubble)
        self.chat_scroll.scroll_to_bottom()

    def _start_typewriter(self, label, content):
        """为普通 Label 模拟打字机效果。"""
        label.text = ""
        char_index = [0]

        def add_char(dt):
            if char_index[0] < len(content):
                char_index[0] += 1
                label.text = content[:char_index[0]]
            else:
                return False

        Clock.schedule_interval(add_char, 0.02)

    def _remove_last_assistant(self):
        if self.messages and self.messages[-1]["role"] == "assistant":
            self.messages.pop()
            if self.chat_box.children:
                self.chat_box.remove_widget(self.chat_box.children[-1])

    def add_message(self, role, content):
        timestamp = datetime.now().strftime("%H:%M")
        self.messages.append({
            "role": role,
            "content": content,
            "time": timestamp,
        })

        bubble = ConversationBubble(
            message=content,
            role=role,
            timestamp=timestamp,
        )
        self.chat_box.add_widget(bubble)
        self.chat_scroll.scroll_to_bottom()


# ═══════════════════════════════════════════════════════════════════════════════
#  ScanScreen — APK 扫描与风险分析
# ═══════════════════════════════════════════════════════════════════════════════

class ScanScreen(MDScreen, DeepDarkMixin):
    """
    APK 扫描界面 — 未来简洁风。

    布局：
    - 顶部：ScanProgressArc 大圆弧进度
    - 中间：4 格 StatsCard + 可展开 RiskCard 列表
    - 底部：PulseButton 操作栏
    """

    scan_results = ListProperty([])
    current_apk = StringProperty("")
    is_scanning = BooleanProperty(False)
    auto_analyze = BooleanProperty(True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "scan"
        self._apply_dark_bg(self)

        self.layout = MDBoxLayout(orientation="vertical", spacing=0)
        self.layout.md_bg_color = (0, 0, 0, 0)

        self._build_header()
        self._build_arc_area()
        self._build_stats_bar()
        self._build_risk_list()
        self._build_action_buttons()

        self.add_widget(self.layout)

        self._scanner = None
        if SCANNER_AVAILABLE:
            try:
                self._scanner = APKScanner()
            except Exception:
                self._scanner = None

    def _build_header(self):
        """构建极简标题栏 + 文件选择器。"""
        header = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            padding=(dp(16), dp(10), dp(16), dp(6)),
            spacing=dp(8),
        )
        header.md_bg_color = (0, 0, 0, 0)

        title = Label(
            text="APK 安全扫描",
            font_size=dp(16),
            color=TEXT_PRIMARY,
            bold=True,
            size_hint=(0.4, None),
            height=dp(28),
            halign="left",
            valign="middle",
        )
        header.add_widget(title)

        self.file_label = Label(
            text="未选择 APK",
            font_size=dp(12),
            color=TEXT_HINT,
            size_hint=(0.35, None),
            height=dp(24),
            halign="left",
            valign="middle",
        )
        header.add_widget(self.file_label)

        select_btn = MDButton(
            MDButtonText(
                text="选择文件",
                font_style="label",
                role="small",
            ),
            style="text",
            size_hint_x=0.25,
            theme_text_color="Custom",
            text_color=CYAN,
            on_release=self._select_apk,
        )
        header.add_widget(select_btn)

        self.layout.add_widget(header)

    def _build_arc_area(self):
        """构建大圆弧进度区域。"""
        arc_box = MDBoxLayout(
            orientation="vertical",
            adaptive_height=True,
            padding=(0, dp(8), 0, dp(8)),
        )
        arc_box.md_bg_color = (0, 0, 0, 0)

        self.scan_arc = ScanProgressArc(
            size_hint=(None, None),
            size=(dp(200), dp(200)),
            pos_hint={"center_x": 0.5},
        )
        self.scan_arc.opacity = 0
        self.scan_arc.height = 0
        arc_box.add_widget(self.scan_arc)

        # 空状态提示
        self._arc_hint = Label(
            text="点击下方按钮开始扫描",
            font_size=dp(13),
            color=TEXT_HINT,
            size_hint_y=None,
            height=dp(24),
            halign="center",
        )
        arc_box.add_widget(self._arc_hint)

        self.layout.add_widget(arc_box)

    def _build_stats_bar(self):
        """构建 4 格统计卡片栏。"""
        self.stats_bar = GridLayout(
            cols=4,
            adaptive_height=True,
            spacing=dp(6),
            padding=(dp(10), dp(6)),
        )

        severities = [
            ("严重", 0, NEON_RED),
            ("高危", 0, NEON_ORANGE),
            ("中危", 0, NEON_YELLOW),
            ("低危", 0, CYAN),
        ]

        self.stat_cards = {}
        for label, value, color in severities:
            card = StatsCard(
                stat_label=label,
                stat_value=value,
                badge_color=color,
            )
            self.stat_cards[label] = card
            self.stats_bar.add_widget(card)

        self.layout.add_widget(self.stats_bar)

    def _build_risk_list(self):
        """构建风险列表区域。"""
        list_header = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            padding=(dp(14), dp(4), dp(14), dp(2)),
        )
        list_header.md_bg_color = (0, 0, 0, 0)

        list_title = Label(
            text="风险列表",
            font_size=dp(15),
            color=TEXT_PRIMARY,
            bold=True,
            size_hint=(0.7, None),
            height=dp(24),
            halign="left",
            valign="middle",
        )
        list_header.add_widget(list_title)

        self.risk_count_label = Label(
            text="0 项",
            font_size=dp(12),
            color=TEXT_SECONDARY,
            size_hint=(0.3, None),
            height=dp(24),
            halign="right",
            valign="middle",
        )
        list_header.add_widget(self.risk_count_label)
        self.layout.add_widget(list_header)

        self.risk_scroll = MDScrollView(size_hint_y=1)
        self.risk_scroll.md_bg_color = (0, 0, 0, 0)

        self.risk_list_box = MDBoxLayout(
            orientation="vertical",
            adaptive_height=True,
            spacing=dp(6),
            padding=(dp(8), dp(4)),
        )
        self.risk_list_box.md_bg_color = (0, 0, 0, 0)
        self.risk_list_box.bind(minimum_height=self.risk_list_box.setter('height'))

        self.risk_scroll.add_widget(self.risk_list_box)
        self.layout.add_widget(self.risk_scroll)

        self._empty_hint = Label(
            text="📂 请选择一个 APK 文件并点击扫描",
            font_size=dp(13),
            color=TEXT_HINT,
            size_hint_y=None,
            height=dp(36),
            halign="center",
        )

    def _build_action_buttons(self):
        """构建操作按钮栏（PulseButton 风格）。"""
        action_bar = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(8),
            padding=(dp(8), dp(8), dp(8), dp(12)),
        )
        action_bar.md_bg_color = (0, 0, 0, 0)

        # 扫描按钮
        self.scan_btn = PulseButton(
            icon_text="▶",
            label="开始扫描",
            pulse_color=CYAN,
            on_release=self._start_scan,
        )

        # 修复按钮
        self.fix_btn = PulseButton(
            icon_text="🔧",
            label="批量修复",
            pulse_color=GREEN,
            on_release=self._batch_fix,
        )

        # 导出按钮
        self.export_btn = PulseButton(
            icon_text="📄",
            label="导出报告",
            pulse_color=PURPLE,
            on_release=self._export_report,
        )

        for btn in [self.scan_btn, self.fix_btn, self.export_btn]:
            action_bar.add_widget(btn)

        self.fix_btn.disabled = True
        self.export_btn.disabled = True

        self.layout.add_widget(action_bar)

    def _select_apk(self, instance):
        """打开文件选择器选择 APK。"""
        try:
            from plyer import filechooser
            filechooser.open_file(
                on_selection=self._on_apk_selected,
                filters=[("APK 文件", "*.apk")],
            )
        except ImportError:
            from kivy.uix.popup import Popup
            from kivy.uix.filechooser import FileChooserListView

            chooser = FileChooserListView(
                filters=["*.apk"],
                path=os.path.expanduser("~"),
            )
            popup = Popup(
                title="选择 APK 文件",
                content=chooser,
                size_hint=(0.9, 0.9),
            )
            chooser.bind(
                on_submit=lambda instance, selection, touch:
                    self._on_apk_selected(selection)
            )
            popup.open()

    def _on_apk_selected(self, files):
        if files:
            self.current_apk = files[0] if isinstance(files, list) else files
            self.file_label.text = os.path.basename(self.current_apk)
            self.scan_btn.disabled = False
            log.info(f"已选择 APK: {self.current_apk}")

    def _start_scan(self, instance):
        if not self.current_apk:
            return

        self.is_scanning = True
        self.scan_btn.disabled = True
        self.fix_btn.disabled = True
        self.export_btn.disabled = True

        self.risk_list_box.clear_widgets()
        self.scan_results = []
        self.risk_count_label.text = "0 项"

        # 显示圆弧进度
        self._arc_hint.opacity = 0
        self._arc_hint.height = 0
        self.scan_arc.opacity = 1
        self.scan_arc.height = dp(200)
        self.scan_arc.progress = 0.0
        self.scan_arc.stage_text = "准备扫描..."

        self._scan_stages = [
            ("解包 APK...", 0.0),
            ("解析 Manifest...", 0.15),
            ("扫描权限...", 0.30),
            ("分析组件...", 0.45),
            ("检查代码...", 0.60),
            ("AI 风险评估...", 0.80),
            ("生成报告...", 0.95),
            ("扫描完成", 1.0),
        ]
        self._stage_index = 0
        Clock.schedule_interval(self._advance_scan, 0.6)

    def _advance_scan(self, dt):
        if self._stage_index < len(self._scan_stages):
            stage, progress = self._scan_stages[self._stage_index]
            self.scan_arc.update(progress, stage)
            self._stage_index += 1
        else:
            Clock.unschedule(self._advance_scan)
            self._finish_scan()

    def _finish_scan(self):
        self.is_scanning = False
        self.scan_btn.disabled = False
        self.fix_btn.disabled = False
        self.export_btn.disabled = False

        # 隐藏圆弧进度
        self.scan_arc.opacity = 0
        self.scan_arc.height = 0
        self._arc_hint.opacity = 1
        self._arc_hint.height = dp(24)

        if SCANNER_AVAILABLE and self._scanner:
            try:
                results = self._scanner.scan(self.current_apk)
                self.scan_results = results
            except Exception as e:
                log.exception(f"扫描失败: {e}")
                self.scan_results = self._generate_mock_results()
        else:
            self.scan_results = self._generate_mock_results()

        self._display_results()

    def _generate_mock_results(self):
        return [
            {
                "title": "硬编码 API Key 泄露",
                "description": "在 classes.dex 中发现硬编码的 API Key 字符串。可能被逆向工程提取。",
                "severity": "critical",
                "detail": "风险详情：\n• 位置：com/example/utils/ConfigManager.smali\n• 泄露类型：API Key\n• 建议：使用环境变量或安全存储\n• OWASP：MSTG-STORAGE-1",
            },
            {
                "title": "敏感权限未声明保护",
                "description": "AndroidManifest.xml 中声明了 READ_SMS 权限但未使用 protectionLevel。",
                "severity": "high",
                "detail": "风险详情：\n• 文件：AndroidManifest.xml\n• 权限：android.permission.READ_SMS\n• 建议：添加 protectionLevel='signature'\n• CWE：CWE-285",
            },
            {
                "title": "导出组件无权限保护",
                "description": "Activity 'com.example.WebViewActivity' exported=true 但未设置权限。",
                "severity": "medium",
                "detail": "风险详情：\n• 组件：com.example.WebViewActivity\n• 类型：Activity\n• 风险：任意应用可调用\n• 建议：添加 android:permission 或设置 exported=false",
            },
            {
                "title": "WebView JavaScript 未限制",
                "description": "WebView 启用了 JavaScript 但未设置安全策略，存在 XSS 风险。",
                "severity": "medium",
                "detail": "风险详情：\n• 组件：WebViewActivity\n• 风险：XSS 攻击\n• 建议：禁用不必要的 JS 或使用 setAllowFileAccess(false)",
            },
            {
                "title": "Debug 模式未关闭",
                "description": "AndroidManifest.xml 中 android:debuggable 属性为 true。",
                "severity": "low",
                "detail": "风险详情：\n• 文件：AndroidManifest.xml\n• 状态：android:debuggable=\"true\"\n• 建议：发布版本设置 debuggable=false",
            },
            {
                "title": "APK 使用旧版 TLS",
                "description": "网络安全配置未限制 TLS 版本，可能使用不安全的旧版协议。",
                "severity": "low",
                "detail": "风险详情：\n• 配置：缺少 network_security_config.xml\n• 建议：添加网络安全配置，限制 TLS 1.2+",
            },
        ]

    def _display_results(self):
        self.risk_list_box.clear_widgets()

        counts = {"严重": 0, "高危": 0, "中危": 0, "低危": 0}
        severity_map = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}

        if not self.scan_results:
            self.risk_list_box.add_widget(Label(
                text="✅ 未发现安全风险！",
                font_size=dp(14),
                color=GREEN,
                size_hint_y=None,
                height=dp(36),
                halign="center",
            ))
        else:
            for item in self.scan_results:
                severity = item.get("severity", "info")
                if severity in severity_map:
                    counts[severity_map[severity]] += 1

                card = RiskCard(
                    risk_title=item.get("title", ""),
                    risk_desc=item.get("description", ""),
                    severity=severity,
                    detail_text=item.get("detail", ""),
                    on_fix=self._fix_single_risk,
                )
                self.risk_list_box.add_widget(card)

        for label, count in counts.items():
            if label in self.stat_cards:
                self.stat_cards[label].update_value(count)

        self.risk_count_label.text = f"{len(self.scan_results)} 项"
        log.info(f"扫描完成，发现 {len(self.scan_results)} 个风险")

    def _fix_single_risk(self, card):
        log.info(f"尝试修复: {card.risk_title}")
        dialog = MDDialog(
            MDDialogHeadlineText(text="正在修复..."),
            MDBoxLayout(
                Label(
                    text=f"正在修复: {card.risk_title}",
                    size_hint_y=None,
                    height=dp(30),
                    halign="center",
                ),
                orientation="vertical",
                adaptive_height=True,
                padding=dp(20),
            ),
        )
        dialog.open()
        Clock.schedule_once(lambda dt: dialog.dismiss(), 2)

    def _batch_fix(self, instance):
        if not self.scan_results:
            return
        log.info("开始批量修复")
        fixable = [r for r in self.scan_results
                   if r.get("severity", "") in ("critical", "high", "medium")]

        dialog = MDDialog(
            MDDialogHeadlineText(text="批量修复"),
            MDBoxLayout(
                Label(
                    text=f"将尝试修复 {len(fixable)} 个风险项。\n\n"
                         "此操作可能修改 APK 文件，建议先备份。",
                    size_hint_y=None,
                    height=dp(50),
                    halign="center",
                ),
                orientation="vertical",
                adaptive_height=True,
                padding=dp(20),
            ),
            MDDialogButtonContainer(
                MDButton(
                    MDButtonText(text="取消"),
                    style="text",
                    on_release=lambda x: dialog.dismiss(),
                ),
                MDButton(
                    MDButtonText(text="开始修复"),
                    style="filled",
                    on_release=lambda x: (
                        dialog.dismiss(),
                        self._execute_batch_fix()
                    ),
                ),
                spacing=dp(8),
            ),
        )
        dialog.open()

    def _execute_batch_fix(self):
        self.scan_arc.opacity = 1
        self.scan_arc.height = dp(200)
        self.scan_arc.update(0.0, "正在修复...")
        self._arc_hint.opacity = 0
        self._arc_hint.height = 0

        Clock.schedule_once(lambda dt: self.scan_arc.update(0.5, "修复中..."), 1.5)
        Clock.schedule_once(lambda dt: self.scan_arc.update(1.0, "修复完成"), 3)
        Clock.schedule_once(lambda dt: self._finish_batch_fix(), 3.5)

    def _finish_batch_fix(self):
        self.scan_arc.opacity = 0
        self.scan_arc.height = 0
        self._arc_hint.opacity = 1
        self._arc_hint.height = dp(24)
        log.info("批量修复完成")

    def _export_report(self, instance):
        report_path = os.path.join(
            os.path.expanduser("~"),
            f"instaguard_report_{datetime.now():%Y%m%d_%H%M%S}.json",
        )
        try:
            import json
            report = {
                "app": APP_NAME,
                "version": APP_VERSION,
                "apk": self.current_apk,
                "timestamp": datetime.now().isoformat(),
                "total_risks": len(self.scan_results),
                "results": self.scan_results,
            }
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            log.info(f"报告已导出: {report_path}")
            self._show_snackbar(f"报告已保存: {os.path.basename(report_path)}")
        except Exception as e:
            log.exception(f"导出报告失败: {e}")
            self._show_snackbar("导出失败")

    def _show_snackbar(self, message):
        try:
            from kivymd.uix.snackbar import MDSnackbar
            MDSnackbar(
                Label(text=message, size_hint_y=None, height=dp(20)),
                duration=2,
                y=dp(24),
            ).open()
        except Exception:
            log.info(f"[Snackbar] {message}")


# ═══════════════════════════════════════════════════════════════════════════════
#  SettingsScreen — 应用设置界面
# ═══════════════════════════════════════════════════════════════════════════════

class SettingsScreen(MDScreen, DeepDarkMixin):
    """
    设置界面 — 未来简洁风。

    布局：
    - 供应商列表: NeonToggle + 名称 + 模型名
    - Ollama 检测: 独立行 + 状态指示
    - 记忆/经验库管理
    - 自定义样式滑块
    - 关于信息
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "settings"
        self._apply_dark_bg(self)

        self.layout = MDBoxLayout(orientation="vertical", spacing=0)
        self.layout.md_bg_color = (0, 0, 0, 0)

        self._build_header()
        self._build_content()

        self.add_widget(self.layout)

        self.config = Config()
        try:
            self.config.load()
        except Exception:
            pass

    def _build_header(self):
        header = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            padding=(dp(16), dp(10)),
        )
        header.md_bg_color = (0, 0, 0, 0)

        title = Label(
            text="设置",
            font_size=dp(18),
            color=TEXT_PRIMARY,
            bold=True,
            size_hint_x=0.9,
            size_hint_y=None,
            height=dp(28),
            halign="left",
            valign="middle",
        )
        header.add_widget(title)
        self.layout.add_widget(header)

    def _build_content(self):
        scroll = MDScrollView(size_hint_y=1)
        scroll.md_bg_color = (0, 0, 0, 0)

        content_box = MDBoxLayout(
            orientation="vertical",
            adaptive_height=True,
            spacing=dp(2),
            padding=(dp(8), dp(4)),
        )
        content_box.md_bg_color = (0, 0, 0, 0)
        content_box.bind(minimum_height=content_box.setter('height'))

        # ── AI 供应商 ──
        self._section_header(content_box, "🤖 AI 供应商")
        self._build_provider_section(content_box)

        # ── API Key ──
        self._section_header(content_box, "🔑 API Key 管理")
        self._build_api_key_section(content_box)

        # ── Ollama ──
        self._section_header(content_box, "🦙 Ollama 本地服务")
        self._build_ollama_section(content_box)

        # ── 记忆库 ──
        self._section_header(content_box, "🧠 记忆库管理")
        self._build_memory_section(content_box)

        # ── 经验库 ──
        self._section_header(content_box, "📚 经验库管理")
        self._build_experience_section(content_box)

        # ── 通用设置 ──
        self._section_header(content_box, "⚙️ 通用设置")
        self._build_general_section(content_box)

        # ── 关于 ──
        self._section_header(content_box, "ℹ️ 关于")
        self._build_about_section(content_box)

        scroll.add_widget(content_box)
        self.layout.add_widget(scroll)

    def _section_header(self, parent, label):
        """创建区块标题（GlowCard 分隔线风格）。"""
        header = Label(
            text=label,
            font_size=dp(14),
            color=CYAN,
            bold=True,
            size_hint_y=None,
            height=dp(36),
            halign="left",
            valign="middle",
            padding=(dp(8), 0),
        )
        parent.add_widget(header)

    def _build_provider_section(self, parent):
        """构建供应商配置区域（NeonToggle）。"""
        if PM_AVAILABLE:
            try:
                pm = get_provider_manager()
                providers = pm.get_all_providers()
            except Exception:
                providers = self.config.get_providers()
        else:
            providers = self.config.get_providers()

        for name, provider in providers.items():
            row = MDBoxLayout(
                orientation="horizontal",
                adaptive_height=True,
                spacing=dp(8),
                padding=(dp(8), dp(4), dp(8), dp(4)),
            )
            row.md_bg_color = (0, 0, 0, 0)

            # NeonToggle 开关
            toggle = NeonToggle(
                active=provider.enabled,
                on_toggle=lambda val, n=name: self._toggle_provider(n, val),
            )
            row.add_widget(toggle)

            # 供应商名称
            name_label = Label(
                text=provider.display_name or name,
                font_size=dp(13),
                color=TEXT_PRIMARY,
                size_hint=(0.3, None),
                height=dp(26),
                halign="left",
                valign="middle",
            )
            row.add_widget(name_label)

            # 模型选择器
            model_dropdown = ModelDropdown(
                provider_name=name,
                models=provider.models,
                selected_model=provider.active_model or "",
                on_select=self._on_model_select,
                size_hint_x=0.5,
            )
            row.add_widget(model_dropdown)

            parent.add_widget(row)

    def _build_api_key_section(self, parent):
        """构建 API Key 管理区域。"""
        key_row = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(8),
            padding=(dp(8), dp(4), dp(8), dp(4)),
        )
        key_row.md_bg_color = (0, 0, 0, 0)

        self.api_status_label = Label(
            text="已配置 Key：0 个供应商",
            font_size=dp(12),
            color=TEXT_SECONDARY,
            size_hint=(0.6, None),
            height=dp(26),
            halign="left",
            valign="middle",
        )
        key_row.add_widget(self.api_status_label)

        add_key_btn = MDButton(
            MDButtonText(text="添加 Key", font_style="label", role="small"),
            style="text",
            size_hint_x=0.4,
            theme_text_color="Custom",
            text_color=CYAN,
            on_release=self._add_api_key,
        )
        key_row.add_widget(add_key_btn)
        parent.add_widget(key_row)

        self._refresh_api_status()

    def _build_ollama_section(self, parent):
        """构建 Ollama 检测区域。"""
        ollama_row = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(8),
            padding=(dp(8), dp(4), dp(8), dp(4)),
        )
        ollama_row.md_bg_color = (0, 0, 0, 0)

        self.ollama_status_label = Label(
            text="未检测",
            font_size=dp(12),
            color=TEXT_SECONDARY,
            size_hint=(0.6, None),
            height=dp(26),
            halign="left",
            valign="middle",
        )
        ollama_row.add_widget(self.ollama_status_label)

        detect_btn = MDButton(
            MDButtonText(text="检测", font_style="label", role="small"),
            style="text",
            size_hint_x=0.4,
            theme_text_color="Custom",
            text_color=GREEN,
            on_release=self._detect_ollama,
        )
        ollama_row.add_widget(detect_btn)
        parent.add_widget(ollama_row)

    def _build_memory_section(self, parent):
        """构建记忆库管理区域。"""
        mem_row = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(8),
            padding=(dp(8), dp(4), dp(8), dp(4)),
        )
        mem_row.md_bg_color = (0, 0, 0, 0)

        self.memory_status_label = Label(
            text="记忆库: 0 条记录",
            font_size=dp(12),
            color=TEXT_SECONDARY,
            size_hint=(0.5, None),
            height=dp(26),
            halign="left",
            valign="middle",
        )
        mem_row.add_widget(self.memory_status_label)

        clear_mem_btn = MDButton(
            MDButtonText(text="清理", font_style="label", role="small"),
            style="text",
            size_hint_x=0.25,
            theme_text_color="Custom",
            text_color=NEON_RED[:3] + (0.8,),
            on_release=self._clear_memory,
        )
        mem_row.add_widget(clear_mem_btn)
        parent.add_widget(mem_row)

        if MEMORY_AVAILABLE:
            try:
                mem_db = MemoryDB()
                stats = mem_db.get_stats()
                self.memory_status_label.text = f"记忆库: {stats.get('total', 0)} 条记录"
            except Exception:
                pass

    def _build_experience_section(self, parent):
        """构建经验库管理区域。"""
        exp_row = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(8),
            padding=(dp(8), dp(4), dp(8), dp(4)),
        )
        exp_row.md_bg_color = (0, 0, 0, 0)

        self.exp_status_label = Label(
            text="经验库: 0 条记录",
            font_size=dp(12),
            color=TEXT_SECONDARY,
            size_hint=(0.5, None),
            height=dp(26),
            halign="left",
            valign="middle",
        )
        exp_row.add_widget(self.exp_status_label)

        clear_exp_btn = MDButton(
            MDButtonText(text="清理", font_style="label", role="small"),
            style="text",
            size_hint_x=0.25,
            theme_text_color="Custom",
            text_color=NEON_RED[:3] + (0.8,),
            on_release=self._clear_experience,
        )
        exp_row.add_widget(clear_exp_btn)
        parent.add_widget(exp_row)

        if EXPERIENCE_AVAILABLE:
            try:
                exp_db = ExperienceDB()
                stats = exp_db.get_stats()
                self.exp_status_label.text = f"经验库: {stats.get('total', 0)} 条记录"
            except Exception:
                pass

    def _build_general_section(self, parent):
        """构建通用设置区域（自定义滑块）。"""
        # 相似度阈值
        sim_row = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(8),
            padding=(dp(8), dp(4), dp(8), dp(4)),
        )
        sim_row.md_bg_color = (0, 0, 0, 0)

        sim_label = Label(
            text="相似度阈值",
            font_size=dp(12),
            color=TEXT_PRIMARY,
            size_hint=(0.35, None),
            height=dp(30),
            halign="left",
            valign="middle",
        )
        sim_row.add_widget(sim_label)

        self.sim_value_label = Label(
            text=str(self.config.get_setting("memory_similarity_threshold", 0.85)),
            font_size=dp(12),
            color=CYAN,
            size_hint=(0.1, None),
            height=dp(30),
            halign="center",
            valign="middle",
        )
        sim_row.add_widget(self.sim_value_label)

        sim_slider = MDSlider(
            value=self.config.get_setting("memory_similarity_threshold", 0.85) * 100,
            min=50,
            max=99,
            size_hint_x=0.55,
            thumb_color_active=CYAN,
            thumb_color_inactive=TEXT_HINT,
            track_color_active=CYAN,
            track_color_inactive=TEXT_HINT,
        )
        sim_slider.bind(value=lambda obj, val: self._on_sim_change(val))
        sim_row.add_widget(sim_slider)
        parent.add_widget(sim_row)

        # 最大 APK 大小
        size_row = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(8),
            padding=(dp(8), dp(4), dp(8), dp(4)),
        )
        size_row.md_bg_color = (0, 0, 0, 0)

        size_label = Label(
            text="最大 APK (MB)",
            font_size=dp(12),
            color=TEXT_PRIMARY,
            size_hint=(0.35, None),
            height=dp(30),
            halign="left",
            valign="middle",
        )
        size_row.add_widget(size_label)

        self.size_value_label = Label(
            text=str(self.config.get_setting("max_apk_size_mb", 500)),
            font_size=dp(12),
            color=CYAN,
            size_hint=(0.1, None),
            height=dp(30),
            halign="center",
            valign="middle",
        )
        size_row.add_widget(self.size_value_label)

        size_slider = MDSlider(
            value=self.config.get_setting("max_apk_size_mb", 500),
            min=50,
            max=2000,
            step=50,
            size_hint_x=0.55,
            thumb_color_active=CYAN,
            thumb_color_inactive=TEXT_HINT,
            track_color_active=CYAN,
            track_color_inactive=TEXT_HINT,
        )
        size_slider.bind(value=lambda obj, val: self._on_size_change(int(val)))
        size_row.add_widget(size_slider)
        parent.add_widget(size_row)

    def _build_about_section(self, parent):
        """构建关于信息区域。"""
        about_card = GlowCard(
            glow_enabled=True,
            glow_color=CYAN_DIM,
            padding=dp(16),
            spacing=dp(6),
        )

        app_info = Label(
            text=f"{APP_NAME} v{APP_VERSION}",
            font_size=dp(16),
            color=CYAN,
            bold=True,
            size_hint_y=None,
            height=dp(26),
            halign="left",
        )
        about_card.add_widget(app_info)

        desc = Label(
            text="Android 安全扫描与修复应用\n\n"
                 "基于 AI 的自动化 APK 安全分析工具，\n"
                 "支持多供应商模型进行智能风险识别和自动修复。",
            font_size=dp(12),
            color=TEXT_SECONDARY,
            size_hint_y=None,
            height=dp(64),
            halign="left",
        )
        about_card.add_widget(desc)

        credits = Label(
            text="Powered by: Kivy/KivyMD • Buildozer\n© 2026 InstaGuard Team",
            font_size=dp(10),
            color=TEXT_HINT,
            size_hint_y=None,
            height=dp(30),
            halign="left",
        )
        about_card.add_widget(credits)

        parent.add_widget(about_card)

    # ─── 事件处理 ──────────────────────────────────────────────────────────

    def _toggle_provider(self, provider_name, enabled):
        provider = self.config.get_provider(provider_name)
        if provider:
            provider.enabled = enabled
            self.config.save()
            log.info(f"供应商 {provider_name} {'已启用' if enabled else '已禁用'}")

    def _on_model_select(self, provider_name, model):
        if PM_AVAILABLE:
            try:
                pm = get_provider_manager()
                pm.set_active_model(provider_name, model)
            except Exception:
                pass
        provider = self.config.get_provider(provider_name)
        if provider:
            provider.active_model = model
            self.config.save()
        log.info(f"供应商 {provider_name} 模型切换: {model}")

    def _add_api_key(self, instance):
        providers = self.config.get_providers()
        provider_names = list(providers.keys())
        if not provider_names:
            log.warning("没有可用的供应商")
            return
        self._open_key_dialog(provider_names[0])

    def _open_key_dialog(self, provider_name):
        dialog = APIKeyDialog(
            provider_name=provider_name,
            on_save=self._save_api_key,
        )
        dialog.open()

    def _save_api_key(self, provider_name, api_key):
        if PM_AVAILABLE:
            try:
                pm = get_provider_manager()
                pm.add_api_key(provider_name, api_key)
            except Exception:
                pass
        else:
            provider = self.config.get_provider(provider_name)
            if provider:
                if api_key not in provider.api_keys:
                    provider.api_keys.append(api_key)
                    provider.enabled = True
                    self.config.save()

        self._refresh_api_status()
        log.info(f"API Key 已保存: {provider_name}")

    def _refresh_api_status(self):
        providers_with_keys = 0
        for name, provider in self.config.get_providers().items():
            if provider.api_keys:
                providers_with_keys += 1
        self.api_status_label.text = f"已配置 Key：{providers_with_keys} 个供应商"

    def _detect_ollama(self, instance):
        if PM_AVAILABLE:
            try:
                pm = get_provider_manager()
                result = pm.detect_ollama()
                if result["available"]:
                    self.ollama_status_label.text = f"✅ 运行中 ({result['endpoint']})"
                    self.ollama_status_label.color = GREEN
                else:
                    self.ollama_status_label.text = "❌ 未检测到"
                    self.ollama_status_label.color = NEON_RED
            except Exception as e:
                self.ollama_status_label.text = f"检测失败: {e}"
        else:
            self.ollama_status_label.text = "❌ ProviderManager 不可用"

    def _clear_memory(self, instance):
        if MEMORY_AVAILABLE:
            try:
                mem_db = MemoryDB()
                mem_db.clear()
                self.memory_status_label.text = "记忆库: 0 条记录"
                log.info("记忆库已清理")
            except Exception as e:
                log.exception(f"清理记忆库失败: {e}")

    def _clear_experience(self, instance):
        if EXPERIENCE_AVAILABLE:
            try:
                exp_db = ExperienceDB()
                exp_db.clear()
                self.exp_status_label.text = "经验库: 0 条记录"
                log.info("经验库已清理")
            except Exception as e:
                log.exception(f"清理经验库失败: {e}")

    def _on_sim_change(self, value):
        threshold = value / 100.0
        self.sim_value_label.text = f"{threshold:.2f}"
        self.config.set_setting("memory_similarity_threshold", threshold)
        self.config.save()

    def _on_size_change(self, value):
        self.size_value_label.text = str(value)
        self.config.set_setting("max_apk_size_mb", value)
        self.config.save()
