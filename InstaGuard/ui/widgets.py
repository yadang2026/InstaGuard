"""
InstaGuard - 未来简洁风 UI 组件

Futuristic Minimal 设计语言：
- 暗色主题 #0D0D0D / #1A1A1A
- 霓虹点缀色：青 #00E5FF、紫 #B388FF、绿 #00E676
- 玻璃拟态卡片 + 发光效果
- Canvas 自定义绘制

提供组件：
- GlowCard: 玻璃拟态卡片
- NeonBadge: 霓虹严重程度徽章
- PulseButton: 脉冲动画按钮
- ScanProgressArc: 圆弧扫描进度
- TypewriterLabel: 打字机效果文本
- MinimalInput: 极简输入框
- NeonToggle: 霓虹开关
- StatRing: 环形统计图
- 向后兼容组件：SeverityBadge, RiskCard, ScanProgressBar,
  ConversationBubble, StatsCard, APIKeyDialog, ProviderChip, ModelDropdown

Author: InstaGuard Team
Version: 2.0.0
"""

from typing import Any, Dict, List, Optional, Tuple
from math import pi, cos, sin

from kivy.clock import Clock
from kivy.uix.widget import Widget
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.behaviors import ButtonBehavior
from kivy.properties import (
    StringProperty, NumericProperty, BooleanProperty,
    ColorProperty, ListProperty, ObjectProperty, OptionProperty,
)
from kivy.graphics import (
    Color, RoundedRectangle, Line, Ellipse, Rectangle,
    PushMatrix, PopMatrix, Rotate, Mesh, SmoothLine,
)
from kivy.graphics.instructions import InstructionGroup
from kivy.animation import Animation
from kivy.metrics import dp
from kivy.core.window import Window

# KivyMD 组件
from kivymd.uix.card import MDCard
from kivymd.uix.chip import MDChip
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDButton, MDButtonText
from kivymd.uix.progressbar import MDProgressBar
from kivymd.uix.dialog import MDDialog, MDDialogHeadlineText, MDDialogButtonContainer
from kivymd.uix.textfield import MDTextField
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.relativelayout import MDRelativeLayout
from kivymd.uix.menu import MDDropdownMenu


# ═══════════════════════════════════════════════════════════════════════════════
# 未来简洁风色彩系统
# ═══════════════════════════════════════════════════════════════════════════════

# ── 背景色 ──
BG_DEEP = (0.051, 0.051, 0.051, 1)         # #0D0D0D 最深背景
BG_CARD = (0.102, 0.102, 0.102, 1)          # #1A1A1A 卡片背景
BG_SURFACE = (0.078, 0.078, 0.118, 0.6)    # rgba(20,20,30,0.6) 玻璃态表面
BG_SURFACE_SOLID = (0.078, 0.078, 0.118, 1) # 不透明版

# ── 霓虹点缀色 ──
CYAN = (0.0, 0.898, 1.0, 1.0)              # #00E5FF
CYAN_DIM = (0.0, 0.898, 1.0, 0.3)          # 暗淡青色
CYAN_GLOW = (0.0, 0.898, 1.0, 0.6)         # 发光青色
PURPLE = (0.702, 0.533, 1.0, 1.0)           # #B388FF
PURPLE_DIM = (0.702, 0.533, 1.0, 0.3)
PURPLE_GLOW = (0.702, 0.533, 1.0, 0.6)
GREEN = (0.0, 0.902, 0.463, 1.0)            # #00E676
GREEN_DIM = (0.0, 0.902, 0.463, 0.3)
GREEN_GLOW = (0.0, 0.902, 0.463, 0.6)

# ── 严重程度霓虹色 ──
NEON_RED = (1.0, 0.09, 0.18, 1.0)           # #FF1744
NEON_RED_GLOW = (1.0, 0.09, 0.18, 0.5)
NEON_ORANGE = (1.0, 0.57, 0.0, 1.0)         # #FF9100
NEON_ORANGE_GLOW = (1.0, 0.57, 0.0, 0.5)
NEON_YELLOW = (1.0, 0.92, 0.0, 1.0)         # #FFEA00
NEON_YELLOW_GLOW = (1.0, 0.92, 0.0, 0.4)
NEON_GREY = (0.459, 0.459, 0.459, 1.0)      # #757575

# ── 文字色 ──
TEXT_PRIMARY = (0.95, 0.95, 0.95, 1.0)
TEXT_SECONDARY = (0.6, 0.6, 0.65, 1.0)
TEXT_HINT = (0.35, 0.35, 0.4, 1.0)
TEXT_ON_NEON = (0.05, 0.05, 0.05, 1.0)

# ── 边框色 ──
BORDER_SUBTLE = (0.15, 0.15, 0.2, 0.5)
BORDER_GLOW_CYAN = (0.0, 0.898, 1.0, 0.3)

# ═══════════════════════════════════════════════════════════════════════════════
# 严重程度颜色映射（向后兼容）
# ═══════════════════════════════════════════════════════════════════════════════

SEVERITY_COLORS: Dict[str, Tuple[str, str, str]] = {
    "critical": ("#FF1744", "严重", "#FFCDD2"),
    "high":     ("#FF9100", "高危", "#FFE0B2"),
    "medium":   ("#FFEA00", "中危", "#FFF9C4"),
    "low":      ("#00E5FF", "低危", "#B3F0FF"),
    "info":     ("#757575", "信息", "#E0E0E0"),
}

SEVERITY_NEON: Dict[str, Tuple] = {
    "critical": NEON_RED,
    "high":     NEON_ORANGE,
    "medium":   NEON_YELLOW,
    "low":      CYAN,
    "info":     NEON_GREY,
}

SEVERITY_NEON_GLOW: Dict[str, Tuple] = {
    "critical": NEON_RED_GLOW,
    "high":     NEON_ORANGE_GLOW,
    "medium":   NEON_YELLOW_GLOW,
    "low":      CYAN_DIM,
    "info":     (0.459, 0.459, 0.459, 0.3),
}

SEVERITY_ICONS: Dict[str, str] = {
    "critical": "alert-octagon",
    "high":     "alert-circle",
    "medium":   "alert",
    "low":      "information-outline",
    "info":     "information",
}

SEVERITY_LABELS: Dict[str, str] = {
    "critical": "严重",
    "high":     "高危",
    "medium":   "中危",
    "low":      "低危",
    "info":     "信息",
}


# ═══════════════════════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════════════════════

def _rgba_to_kivy(hex_color: str) -> Tuple[float, float, float, float]:
    """将 hex 颜色转为 Kivy RGBA 元组。"""
    h = hex_color.lstrip("#")
    if len(h) == 6:
        r, g, b = int(h[0:2], 16)/255, int(h[2:4], 16)/255, int(h[4:6], 16)/255
        return (r, g, b, 1.0)
    elif len(h) == 8:
        r, g, b, a = int(h[0:2], 16)/255, int(h[2:4], 16)/255, int(h[4:6], 16)/255, int(h[6:8], 16)/255
        return (r, g, b, a)
    return (0.5, 0.5, 0.5, 1.0)


# ═══════════════════════════════════════════════════════════════════════════════
#  1. GlowCard — 玻璃拟态卡片
# ═══════════════════════════════════════════════════════════════════════════════

class GlowCard(MDBoxLayout):
    """
    玻璃拟态卡片组件。

    半透明深色背景 + 柔和圆角 + 可选霓虹边框发光。

    Attributes:
        glow_color: 发光颜色（霓虹色元组）
        glow_enabled: 是否启用发光效果
        corner_radius: 圆角大小 (dp)
    """

    glow_color = ColorProperty(CYAN_DIM)
    glow_enabled = BooleanProperty(False)
    corner_radius = NumericProperty(20)

    def __init__(self, glow_color=None, glow_enabled=False, **kwargs):
        super().__init__(**kwargs)
        if glow_color:
            self.glow_color = glow_color
        self.glow_enabled = glow_enabled
        self.orientation = "vertical"
        self.adaptive_height = True
        self.padding = dp(16)
        self.spacing = dp(8)

        # 背景色使用 canvas
        self.md_bg_color = (0, 0, 0, 0)  # 透明，用 canvas 绘制

    def on_size(self, *args):
        """重绘 canvas。"""
        self._draw_background()

    def on_pos(self, *args):
        self._draw_background()

    def _draw_background(self):
        """在 canvas.before 上绘制玻璃拟态背景。"""
        self.canvas.before.clear()
        with self.canvas.before:
            # 半透明深色背景
            Color(*BG_SURFACE)
            RoundedRectangle(
                pos=self.pos,
                size=self.size,
                radius=[dp(self.corner_radius)]
            )
            # 霓虹发光边框
            if self.glow_enabled:
                Color(*self.glow_color)
                Line(
                    rounded_rectangle=(
                        self.x + dp(0.5), self.y + dp(0.5),
                        self.width - dp(1), self.height - dp(1),
                        dp(self.corner_radius)
                    ),
                    width=dp(1.2)
                )

    def enable_glow(self, color=None):
        """启用霓虹发光效果。"""
        if color:
            self.glow_color = color
        self.glow_enabled = True
        self._draw_background()

    def disable_glow(self):
        """禁用发光效果。"""
        self.glow_enabled = False
        self._draw_background()


# ═══════════════════════════════════════════════════════════════════════════════
#  2. NeonBadge — 霓虹严重程度徽章
# ═══════════════════════════════════════════════════════════════════════════════

class NeonBadge(MDBoxLayout):
    """
    霓虹严重程度徽章。

    胶囊形状，不同严重程度对应不同霓虹色，带发光效果。

    Attributes:
        severity: 严重程度 (critical/high/medium/low/info)
        badge_text: 显示的文本
    """

    severity = StringProperty("info")
    badge_text = StringProperty("")

    def __init__(self, severity="info", badge_text="", **kwargs):
        super().__init__(**kwargs)
        self.severity = severity
        self.badge_text = badge_text or SEVERITY_LABELS.get(severity, "信息")

        self.orientation = "horizontal"
        self.adaptive_size = True
        self.size_hint = (None, None)
        self.height = dp(24)
        self.spacing = 0
        self.padding = (dp(10), dp(2), dp(10), dp(2))

        # 透明背景，canvas 绘制
        self.md_bg_color = (0, 0, 0, 0)

        # 文字标签
        self._label = Label(
            text=self.badge_text,
            font_size=dp(11),
            bold=True,
            color=(0.05, 0.05, 0.05, 1),
            size_hint=(None, None),
            size=self._label_size(),
        )
        self._label.bind(texture_size=self._update_label_size)
        self.add_widget(self._label)

    def _label_size(self):
        return (dp(40), dp(18))

    def _update_label_size(self, instance, value):
        instance.size = value
        self.width = value[0] + dp(20)
        self._draw_badge()

    def on_size(self, *args):
        self._draw_badge()

    def on_pos(self, *args):
        self._draw_badge()

    def _draw_badge(self):
        """用 canvas 绘制胶囊形霓虹徽章。"""
        self.canvas.before.clear()
        color = SEVERITY_NEON.get(self.severity, NEON_GREY)
        glow = SEVERITY_NEON_GLOW.get(self.severity, (0.459, 0.459, 0.459, 0.3))

        with self.canvas.before:
            # 外层发光
            Color(*glow)
            RoundedRectangle(
                pos=(self.x - dp(2), self.y - dp(2)),
                size=(self.width + dp(4), self.height + dp(4)),
                radius=[dp(14)]
            )
            # 主体
            Color(*color)
            RoundedRectangle(
                pos=self.pos,
                size=self.size,
                radius=[dp(12)]
            )


# ═══════════════════════════════════════════════════════════════════════════════
#  3. PulseButton — 脉冲动画按钮
# ═══════════════════════════════════════════════════════════════════════════════

class PulseButton(ButtonBehavior, MDBoxLayout):
    """
    脉冲动画按钮。

    按压时扩散波纹，默认半透明，hover 明亮。

    Attributes:
        icon_text: 图标/文字
        pulse_color: 脉冲颜色
        label: 短文字标签
    """

    icon_text = StringProperty("")
    label = StringProperty("")
    pulse_color = ColorProperty(CYAN)

    def __init__(self, icon_text="", label="", pulse_color=None, on_release=None, **kwargs):
        super().__init__(**kwargs)
        self.icon_text = icon_text
        self.label = label
        if pulse_color:
            self.pulse_color = pulse_color
        if on_release:
            self.bind(on_release=on_release)

        self.orientation = "vertical"
        self.adaptive_size = True
        self.size_hint = (None, None)
        self.spacing = dp(2)
        self.padding = (dp(12), dp(8), dp(12), dp(8))
        self.md_bg_color = (0, 0, 0, 0)

        # 图标
        if icon_text:
            icon_lbl = Label(
                text=icon_text,
                font_size=dp(20),
                color=TEXT_PRIMARY,
                size_hint=(None, None),
                size=(dp(32), dp(32)),
                halign="center",
                valign="middle",
            )
            icon_lbl.bind(texture_size=icon_lbl.setter('size'))
            self.add_widget(icon_lbl)
            self._icon = icon_lbl

        # 标签
        if label:
            lbl = Label(
                text=label,
                font_size=dp(9),
                color=TEXT_SECONDARY,
                size_hint=(None, None),
                size=(dp(60), dp(14)),
                halign="center",
            )
            lbl.bind(texture_size=lbl.setter('size'))
            self.add_widget(lbl)

        self._pulse_anim = None
        self._ripple_widget = None

    def on_press(self):
        """按压时触发脉冲。"""
        self._start_pulse()

    def _start_pulse(self):
        """开始脉冲波纹动画。"""
        if self._ripple_widget:
            self.remove_widget(self._ripple_widget)

        self._ripple_widget = Widget(
            size_hint=(None, None),
            size=(dp(4), dp(4)),
            pos=(self.center_x - dp(2), self.center_y - dp(2)),
        )
        with self._ripple_widget.canvas:
            Color(*self.pulse_color[:3], 0.5)
            self._ripple_circle = Ellipse(
                pos=self._ripple_widget.pos,
                size=self._ripple_widget.size,
            )
        self.add_widget(self._ripple_widget)

        anim = Animation(
            size=(dp(120), dp(120)),
            pos=(self.center_x - dp(60), self.center_y - dp(60)),
            duration=0.4,
            t="out_quad",
        )
        anim &= Animation(opacity=0, duration=0.4)
        anim.bind(on_complete=lambda *a: self._cleanup_ripple())
        anim.start(self._ripple_widget)

    def _cleanup_ripple(self):
        if self._ripple_widget:
            self.remove_widget(self._ripple_widget)
            self._ripple_widget = None


# ═══════════════════════════════════════════════════════════════════════════════
#  4. ScanProgressArc — 圆弧扫描进度
# ═══════════════════════════════════════════════════════════════════════════════

class ScanProgressArc(Widget):
    """
    圆弧扫描进度组件。

    Canvas 绘制 270° 圆弧，渐变霓虹色（青→紫），中心显示百分比。

    Attributes:
        progress: 进度 0.0 - 1.0
        stage_text: 当前阶段文本
    """

    progress = NumericProperty(0.0)
    stage_text = StringProperty("准备扫描...")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.size_hint = (None, None)
        self._arc_size = dp(200)
        self.size = (self._arc_size, self._arc_size)

        # 中心文字
        self._percent_label = Label(
            text="0%",
            font_name="RobotoMono-Regular.ttf",
            font_size=dp(36),
            color=CYAN,
            bold=True,
            size_hint=(None, None),
            size=(dp(100), dp(44)),
            halign="center",
            valign="middle",
        )
        self._percent_label.bind(texture_size=self._percent_label.setter('size'))
        self.add_widget(self._percent_label)

        self._stage_label = Label(
            text=self.stage_text,
            font_size=dp(11),
            color=TEXT_SECONDARY,
            size_hint=(None, None),
            size=(dp(160), dp(20)),
            halign="center",
        )
        self.add_widget(self._stage_label)

        self.bind(progress=self._on_progress)
        self.bind(stage_text=self._on_stage)
        self.bind(size=self._update_labels)
        self.bind(pos=self._update_labels)

    def _update_labels(self, *args):
        cx, cy = self.center_x, self.center_y
        self._percent_label.pos = (cx - dp(50), cy - dp(10))
        self._stage_label.pos = (cx - dp(80), cy - dp(36))
        self._draw_arc()

    def _on_progress(self, *args):
        self._percent_label.text = f"{int(self.progress * 100)}%"
        self._update_labels()

    def _on_stage(self, *args):
        self._stage_label.text = self.stage_text
        self._update_labels()

    def _draw_arc(self):
        """绘制 270° 圆弧。"""
        self.canvas.before.clear()
        w, h = self.size
        cx, cy = self.center_x, self.center_y
        r = min(w, h) / 2 - dp(16)
        track_width = dp(10)

        # 起始角度 135°（左下），结束角度 405°（右下），即 270° 弧
        start_angle = 135
        sweep_angle = 270 * self.progress

        with self.canvas.before:
            # 背景轨道
            Color(0.12, 0.12, 0.15, 0.6)
            Line(
                circle=(cx, cy, r, start_angle, start_angle + 270),
                width=track_width,
                cap="none",
            )

            # 渐变弧——用多段 Line 模拟渐变
            if self.progress > 0:
                segments = 64
                seg_angle = sweep_angle / segments
                for i in range(int(segments * self.progress)):
                    a1 = start_angle + i * (270 / segments)
                    a2 = a1 + (270 / segments)
                    # 青色到紫色渐变
                    t = i / max(segments - 1, 1)
                    cr = CYAN[0] + (PURPLE[0] - CYAN[0]) * t
                    cg = CYAN[1] + (PURPLE[1] - CYAN[1]) * t
                    cb = CYAN[2] + (PURPLE[2] - CYAN[2]) * t
                    Color(cr, cg, cb, 1.0)
                    Line(
                        circle=(cx, cy, r, a1, a2),
                        width=track_width,
                        cap="none",
                    )

            # 末端亮点
            if self.progress > 0:
                end_angle = start_angle + sweep_angle
                end_rad = (end_angle - 90) * pi / 180.0
                ex = cx + r * cos(end_rad)
                ey = cy + r * sin(end_rad)
                Color(*PURPLE)
                Ellipse(
                    pos=(ex - dp(6), ey - dp(6)),
                    size=(dp(12), dp(12)),
                )

    def update(self, progress: float, stage: str = ""):
        """更新进度和阶段。"""
        self.progress = max(0.0, min(1.0, progress))
        if stage:
            self.stage_text = stage


# ═══════════════════════════════════════════════════════════════════════════════
#  5. TypewriterLabel — 打字机效果文本
# ═══════════════════════════════════════════════════════════════════════════════

class TypewriterLabel(Label):
    """
    打字机效果文本组件。

    逐字显示，带闪烁光标效果。

    Attributes:
        full_text: 完整文本
        char_index: 当前显示到的字符位置
        speed: 打字速度（秒/字符）
        show_cursor: 是否显示光标
        cursor_visible: 光标当前可见状态
    """

    full_text = StringProperty("")
    char_index = NumericProperty(0)
    speed = NumericProperty(0.03)
    show_cursor = BooleanProperty(True)
    cursor_visible = BooleanProperty(True)

    def __init__(self, full_text="", speed=0.03, **kwargs):
        super().__init__(**kwargs)
        self.full_text = full_text
        self.speed = speed
        self.text = ""
        self.font_size = dp(14)
        self.color = TEXT_PRIMARY
        self.halign = "left"
        self.valign = "top"
        self.bind(size=self._update_text_size)
        self.text_size = (dp(280), None)

        self._typing_event = None
        self._cursor_event = None

    def _update_text_size(self, instance, value):
        self.text_size = (value[0] - dp(16), None)

    def start_typing(self, text=None):
        """开始打字机动画。"""
        if text:
            self.full_text = text
        self.char_index = 0
        self.text = ""
        self.cursor_visible = True

        if self._typing_event:
            Clock.unschedule(self._typing_event)
        self._typing_event = Clock.schedule_interval(self._type_char, self.speed)

        if self._cursor_event:
            Clock.unschedule(self._cursor_event)
        self._cursor_event = Clock.schedule_interval(self._blink_cursor, 0.5)

    def _type_char(self, dt):
        """逐字显示。"""
        if self.char_index < len(self.full_text):
            self.char_index += 1
            displayed = self.full_text[:self.char_index]
            if self.show_cursor and self.cursor_visible:
                displayed += "|"
            self.text = displayed
        else:
            Clock.unschedule(self._typing_event)
            self._typing_event = None
            if self.show_cursor:
                self.text = self.full_text + " "
                if self._cursor_event:
                    Clock.unschedule(self._cursor_event)
                    self._cursor_event = Clock.schedule_interval(self._blink_cursor, 0.8)

    def _blink_cursor(self, dt):
        """光标闪烁。"""
        self.cursor_visible = not self.cursor_visible
        if self.char_index >= len(self.full_text):
            self.text = self.full_text + ("|" if self.cursor_visible else " ")
        else:
            displayed = self.full_text[:self.char_index]
            self.text = displayed + ("|" if self.cursor_visible else "")

    def finish(self):
        """立即显示全部文本。"""
        if self._typing_event:
            Clock.unschedule(self._typing_event)
            self._typing_event = None
        self.char_index = len(self.full_text)
        self.text = self.full_text

    def stop_cursor(self):
        """停止光标闪烁。"""
        if self._cursor_event:
            Clock.unschedule(self._cursor_event)
            self._cursor_event = None
        self.cursor_visible = False
        self.text = self.full_text


# ═══════════════════════════════════════════════════════════════════════════════
#  6. MinimalInput — 极简输入框
# ═══════════════════════════════════════════════════════════════════════════════

class MinimalInput(MDBoxLayout):
    """
    极简输入框组件。

    无边框，仅底部一条细线，focus 时变为霓虹色。

    Attributes:
        hint_text: 占位文本
        text: 输入文本
        active_line_color: 激活时底线颜色
    """

    hint_text = StringProperty("")
    text = StringProperty("")
    active_line_color = ColorProperty(CYAN)
    focused = BooleanProperty(False)

    def __init__(self, hint_text="输入内容...", **kwargs):
        super().__init__(**kwargs)
        self.hint_text = hint_text
        self.orientation = "vertical"
        self.adaptive_height = True
        self.spacing = dp(4)
        self.padding = (dp(8), dp(4), dp(8), dp(0))
        self.md_bg_color = (0, 0, 0, 0)

        # 文本输入
        self._text_input = MDTextField(
            hint_text=hint_text,
            mode="line",
            line_color_normal=TEXT_HINT,
            line_color_focus=CYAN,
            text_color_normal=TEXT_PRIMARY,
            text_color_focus=TEXT_PRIMARY,
            hint_text_color_normal=TEXT_HINT,
            hint_text_color_focus=CYAN_DIM[:3] + (0.6,),
            fill_color_normal=(0, 0, 0, 0),
            fill_color_focus=(0, 0, 0, 0),
            bg_color_normal=(0, 0, 0, 0),
            bg_color_active=(0, 0, 0, 0),
            size_hint_x=1,
            font_size=dp(14),
        )
        self._text_input.bind(
            text=self._on_text_change,
            focus=self._on_focus_change,
        )
        self._text_input.bind(on_text_validate=self._on_validate)
        self.add_widget(self._text_input)

        # 底部霓虹线
        self._line = Widget(
            size_hint=(1, None),
            height=dp(1),
        )
        with self._line.canvas:
            Color(*TEXT_HINT)
            self._line_rect = Rectangle(
                pos=self._line.pos,
                size=self._line.size,
            )
        self._line.bind(pos=self._update_line_rect, size=self._update_line_rect)
        self.add_widget(self._line)

        self._glow_anim = None
        self._line_color = TEXT_HINT

    def _update_line_rect(self, *args):
        self._line_rect.pos = self._line.pos
        self._line_rect.size = self._line.size

    def _on_text_change(self, instance, value):
        self.text = value

    def _on_focus_change(self, instance, value):
        self.focused = value
        if value:
            self._animate_line(CYAN)
        else:
            self._animate_line(TEXT_HINT)

    def _animate_line(self, target_color):
        """动画过渡底线颜色。"""
        if self._glow_anim:
            self._glow_anim.cancel(self._line)
        steps = 15
        duration = 0.25
        sr, sg, sb, sa = self._line_color
        tr, tg, tb, ta = target_color
        dr = (tr - sr) / steps
        dg = (tg - sg) / steps
        db = (tb - sb) / steps

        def update_color(dt):
            nonlocal sr, sg, sb
            sr += dr
            sg += dg
            sb += db
            self._line_color = (max(0, min(1, sr)), max(0, min(1, sg)), max(0, min(1, sb)), 1.0)
            self._line.canvas.clear()
            with self._line.canvas:
                Color(*self._line_color)
                self._line_rect = Rectangle(pos=self._line.pos, size=self._line.size)

        self._glow_anim = Clock.schedule_interval(update_color, duration / steps)

    def _on_validate(self, instance):
        """回车键回调——由外部绑定。"""
        pass

    def bind_on_validate(self, callback):
        """绑定回车键回调。"""
        self._text_input.bind(on_text_validate=callback)

    def clear(self):
        """清空输入。"""
        self._text_input.text = ""
        self.text = ""


# ═══════════════════════════════════════════════════════════════════════════════
#  7. NeonToggle — 霓虹开关
# ═══════════════════════════════════════════════════════════════════════════════

class NeonToggle(ButtonBehavior, Widget):
    """
    霓虹开关组件。

    自定义 Canvas 开关，关闭暗灰，开启青色发光，平滑过渡。

    Attributes:
        active: 是否开启
        active_color: 开启颜色
        inactive_color: 关闭颜色
    """

    active = BooleanProperty(False)
    active_color = ColorProperty(CYAN)
    inactive_color = ColorProperty((0.2, 0.2, 0.25, 1.0))

    def __init__(self, active=False, on_toggle=None, **kwargs):
        super().__init__(**kwargs)
        self.active = active
        self.size_hint = (None, None)
        self.size = (dp(48), dp(26))
        self._knob_x = dp(3) if not active else dp(25)

        if on_toggle:
            self.bind(on_release=lambda x: (
                setattr(self, 'active', not self.active),
                on_toggle(self.active)
            ))
        else:
            self.bind(on_release=lambda x: setattr(self, 'active', not self.active))

        self.bind(active=self._animate_toggle)
        self.bind(size=self._draw_toggle, pos=self._draw_toggle)

    def _draw_toggle(self, *args):
        """绘制开关。"""
        self.canvas.clear()
        w, h = self.size
        track_h = dp(14)
        track_y = self.y + (h - track_h) / 2
        radius = track_h / 2
        knob_r = dp(10)

        with self.canvas:
            # 轨道
            if self.active:
                Color(*self.active_color[:3], 0.3)
            else:
                Color(*self.inactive_color[:3], 0.4)
            RoundedRectangle(
                pos=(self.x, track_y),
                size=(w, track_h),
                radius=[radius],
            )

            # 滑块
            if self.active:
                Color(*self.active_color)
            else:
                Color(0.35, 0.35, 0.4, 1.0)
            Ellipse(
                pos=(self.x + self._knob_x, self.y + (h - knob_r * 2) / 2),
                size=(knob_r * 2, knob_r * 2),
            )

            # 发光效果
            if self.active:
                Color(*self.active_color[:3], 0.15)
                Ellipse(
                    pos=(self.x + self._knob_x - dp(3), self.y + (h - knob_r * 2) / 2 - dp(3)),
                    size=((knob_r + dp(3)) * 2, (knob_r + dp(3)) * 2),
                )

    def _animate_toggle(self, instance, value):
        """平滑动画过渡。"""
        target_x = dp(25) if value else dp(3)

        def animate_knob(dt):
            diff = target_x - self._knob_x
            if abs(diff) < dp(0.5):
                self._knob_x = target_x
                self._draw_toggle()
                return False
            self._knob_x += diff * 0.3
            self._draw_toggle()

        Clock.schedule_interval(animate_knob, 0.016)


# ═══════════════════════════════════════════════════════════════════════════════
#  8. StatRing — 环形统计图
# ═══════════════════════════════════════════════════════════════════════════════

class StatRing(Widget):
    """
    环形统计图组件。

    Canvas 环形图显示风险分布比例，中心显示总数。

    Attributes:
        segments: 各段数据 [{"label": "严重", "value": 3, "color": (1,0,0,1)}, ...]
        total_label: 中心标签文字
    """

    segments = ListProperty([])
    total_label = StringProperty("0")

    def __init__(self, segments=None, **kwargs):
        super().__init__(**kwargs)
        self.segments = segments or []
        self.size_hint = (None, None)
        self._ring_size = dp(100)
        self.size = (self._ring_size, self._ring_size)

        # 中心文字
        self._total_label = Label(
            text="0",
            font_name="RobotoMono-Regular.ttf",
            font_size=dp(20),
            color=TEXT_PRIMARY,
            bold=True,
            size_hint=(None, None),
            size=(dp(60), dp(28)),
            halign="center",
            valign="middle",
        )
        self.add_widget(self._total_label)

        self._sub_label = Label(
            text="总计",
            font_size=dp(10),
            color=TEXT_SECONDARY,
            size_hint=(None, None),
            size=(dp(60), dp(14)),
            halign="center",
        )
        self.add_widget(self._sub_label)

        self.bind(segments=self._on_segments)
        self.bind(size=self._update_center, pos=self._update_center)

    def _update_center(self, *args):
        cx, cy = self.center_x, self.center_y
        self._total_label.pos = (cx - dp(30), cy + dp(2))
        self._sub_label.pos = (cx - dp(30), cy - dp(14))
        self._draw_ring()

    def _on_segments(self, *args):
        total = sum(s.get("value", 0) for s in self.segments)
        self._total_label.text = str(total)
        self._update_center()

    def _draw_ring(self):
        """绘制环形图。"""
        self.canvas.before.clear()
        w, h = self.size
        cx, cy = self.center_x, self.center_y
        outer_r = min(w, h) / 2 - dp(4)
        inner_r = outer_r - dp(12)
        ring_width = outer_r - inner_r

        total = sum(s.get("value", 0) for s in self.segments)
        if total == 0:
            # 空环
            with self.canvas.before:
                Color(0.15, 0.15, 0.18, 0.4)
                Line(circle=(cx, cy, (outer_r + inner_r) / 2, 0, 360), width=ring_width)
            return

        angle = -90  # 从顶部开始
        for seg in self.segments:
            value = seg.get("value", 0)
            color = seg.get("color", NEON_GREY)
            sweep = (value / total) * 360 if total > 0 else 0

            with self.canvas.before:
                Color(*color[:3], 0.9)
                Line(
                    circle=(cx, cy, (outer_r + inner_r) / 2, angle, angle + sweep),
                    width=ring_width,
                    cap="none",
                )
            angle += sweep

    def set_data(self, segments: list):
        """设置环形图数据。"""
        self.segments = segments


# ═══════════════════════════════════════════════════════════════════════════════
#  向后兼容组件
# ═══════════════════════════════════════════════════════════════════════════════

# ─── SeverityBadge (向后兼容) ─────────────────────────────────────────────────

class SeverityBadge(MDBoxLayout):
    """严重程度徽章（向后兼容版，映射到 NeonBadge 样式）。"""

    severity = StringProperty("info")

    def __init__(self, severity="info", **kwargs):
        super().__init__(**kwargs)
        self.severity = severity
        self.adaptive_size = True
        self.size_hint_x = None
        self.padding = (dp(8), dp(2), dp(8), dp(2))
        self.spacing = dp(4)
        self.md_bg_color = (0, 0, 0, 0)

        color = SEVERITY_NEON.get(severity, NEON_GREY)
        label_text = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])[1]

        icon_label = Label(
            text=label_text,
            font_size=dp(12),
            bold=True,
            color=(0.05, 0.05, 0.05, 1),
            size_hint=(None, None),
            size=(dp(32), dp(20)),
            halign="center",
            valign="middle",
        )
        icon_label.bind(texture_size=icon_label.setter('size'))
        self.add_widget(icon_label)
        self._badge_color = color

    def on_size(self, *args):
        self._draw_badge()

    def on_pos(self, *args):
        self._draw_badge()

    def _draw_badge(self):
        self.canvas.before.clear()
        with self.canvas.before:
            Color(*self._badge_color)
            RoundedRectangle(
                pos=self.pos,
                size=self.size,
                radius=[dp(8)]
            )


# ─── RiskCard (向后兼容，升级到 GlowCard 风格) ───────────────────────────────

class RiskCard(MDCard):
    """风险项卡片（向后兼容，未来简洁风升级版）。"""

    risk_title = StringProperty("")
    risk_desc = StringProperty("")
    severity = StringProperty("info")
    detail_text = StringProperty("")
    is_expanded = BooleanProperty(False)

    def __init__(self, risk_title="", risk_desc="", severity="info",
                 detail_text="", on_expand=None, on_fix=None, **kwargs):
        super().__init__(**kwargs)
        self.risk_title = risk_title
        self.risk_desc = risk_desc
        self.severity = severity
        self.detail_text = detail_text
        self.on_expand = on_expand
        self.on_fix = on_fix

        self.size_hint_y = None
        self.height = dp(80)
        self.padding = dp(12)
        self.spacing = dp(8)
        self.style = "elevated"
        self.elevation = 0
        self.radius = [dp(16)]
        self.orientation = "vertical"
        self.md_bg_color = BG_SURFACE_SOLID

        # 左边框霓虹色条
        neon_edge_color = SEVERITY_NEON.get(severity, NEON_GREY)
        with self.canvas.before:
            Color(*neon_edge_color)
            self._neon_strip = Rectangle(
                pos=(self.x, self.y),
                size=(dp(3), self.height),
            )

        self._build_layout()

    def _build_layout(self):
        top_row = MDBoxLayout(
            orientation="horizontal",
            adaptive_height=True,
            spacing=dp(8),
        )
        badge = NeonBadge(severity=self.severity)
        top_row.add_widget(badge)

        title_label = Label(
            text=self.risk_title,
            font_size=dp(15),
            color=TEXT_PRIMARY,
            size_hint=(0.65, None),
            height=dp(24),
            halign="left",
            valign="middle",
        )
        title_label.bind(texture_size=title_label.setter('size'))
        top_row.add_widget(title_label)

        spacer = Widget(size_hint_x=1)
        top_row.add_widget(spacer)

        expand_btn = MDButton(
            MDButtonText(
                text="▼" if not self.is_expanded else "▲",
                font_style="label",
                role="small",
            ),
            style="text",
            size_hint_x=None,
            width=dp(36),
            theme_text_color="Custom",
            text_color=CYAN,
            on_release=self._toggle_expand,
        )
        top_row.add_widget(expand_btn)
        self._expand_btn = expand_btn
        self.add_widget(top_row)

        desc_label = Label(
            text=self.risk_desc[:120] + ("..." if len(self.risk_desc) > 120 else ""),
            font_size=dp(12),
            color=TEXT_SECONDARY,
            size_hint_y=None,
            height=dp(20),
            halign="left",
            valign="top",
        )
        self.add_widget(desc_label)
        self._desc_label = desc_label

        self._detail_box = MDBoxLayout(
            orientation="vertical",
            adaptive_height=True,
            spacing=dp(4),
            opacity=0,
            height=0,
        )
        detail_label = Label(
            text=self.detail_text,
            font_size=dp(11),
            color=TEXT_HINT,
            size_hint_y=None,
        )
        detail_label.bind(texture_size=detail_label.setter('height'))
        self._detail_box.add_widget(detail_label)

        if self.on_fix and self.severity in ("critical", "high", "medium"):
            fix_btn = MDButton(
                MDButtonText(text="尝试修复", font_style="label"),
                style="tonal",
                size_hint_x=None,
                width=dp(100),
                on_release=lambda x: self.on_fix(self),
            )
            self._detail_box.add_widget(fix_btn)

        self.add_widget(self._detail_box)

    def on_pos(self, *args):
        if hasattr(self, '_neon_strip'):
            self._neon_strip.pos = (self.x, self.y)

    def on_size(self, *args):
        if hasattr(self, '_neon_strip'):
            self._neon_strip.size = (dp(3), self.height)

    def _toggle_expand(self, instance):
        self.is_expanded = not self.is_expanded
        btn_text = instance.children[0] if instance.children else None
        if self.is_expanded:
            self._detail_box.opacity = 1
            self._detail_box.height = self._detail_box.minimum_height
            self.height = dp(80) + self._detail_box.minimum_height
        else:
            self._detail_box.opacity = 0
            self._detail_box.height = 0
            self.height = dp(80)
        if self.on_expand:
            self.on_expand(self)

    def update_severity(self, new_severity):
        """更新严重程度。"""
        self.severity = new_severity
        self.canvas.before.clear()
        neon_edge_color = SEVERITY_NEON.get(new_severity, NEON_GREY)
        with self.canvas.before:
            Color(*neon_edge_color)
            self._neon_strip = Rectangle(
                pos=(self.x, self.y),
                size=(dp(3), self.height),
            )


# ─── ScanProgressBar (向后兼容) ───────────────────────────────────────────────

class ScanProgressBar(MDBoxLayout):
    """扫描进度条（向后兼容版）。"""

    stage_name = StringProperty("准备中...")
    progress = NumericProperty(0.0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "vertical"
        self.adaptive_height = True
        self.spacing = dp(8)
        self.padding = (dp(12), dp(12))

        self._stage_label = Label(
            text=self.stage_name,
            font_size=dp(14),
            color=TEXT_PRIMARY,
            size_hint_y=None,
            height=dp(22),
        )
        self.add_widget(self._stage_label)

        self._progress_bar = MDProgressBar(
            value=0,
            max=100,
            size_hint_x=1,
            height=dp(6),
            radius=[dp(3)],
            color=CYAN,
        )
        self.add_widget(self._progress_bar)

        self._percent_label = Label(
            text="0%",
            font_size=dp(12),
            color=TEXT_SECONDARY,
            size_hint_y=None,
            height=dp(18),
            halign="right",
        )
        self.add_widget(self._percent_label)

    def update(self, stage: str, percent: float):
        self.stage_name = stage
        self.progress = percent
        self._stage_label.text = stage
        self._progress_bar.value = int(percent)
        self._percent_label.text = f"{percent:.0f}%"

    def reset(self):
        self.update("准备中...", 0.0)


# ─── ConversationBubble (向后兼容，升级未来风) ────────────────────────────────

class ConversationBubble(MDCard):
    """对话气泡（未来简洁风升级版）。"""

    message = StringProperty("")
    role = StringProperty("user")
    timestamp = StringProperty("")

    def __init__(self, message="", role="user", timestamp="", **kwargs):
        super().__init__(**kwargs)
        self.message = message
        self.role = role
        self.timestamp = timestamp

        self.size_hint_y = None
        self.height = dp(60)
        self.padding = dp(12)
        self.spacing = dp(6)
        self.style = "elevated"
        self.elevation = 0
        self.orientation = "vertical"
        self.size_hint_x = 0.85

        if role == "user":
            self.pos_hint = {"right": 1}
            self.md_bg_color = (0.25, 0.15, 0.35, 0.7)  # 紫色半透明
            self.radius = [dp(18), dp(18), dp(6), dp(18)]
            text_color = TEXT_PRIMARY
            # 右侧紫色细线
            with self.canvas.after:
                Color(*PURPLE_DIM)
                self._edge_line = Rectangle(
                    pos=(self.right - dp(2), self.y),
                    size=(dp(2), self.height),
                )
        else:
            self.pos_hint = {"right": 0}
            self.md_bg_color = BG_SURFACE
            self.radius = [dp(18), dp(18), dp(18), dp(6)]
            text_color = TEXT_PRIMARY
            # 左侧青色细线
            with self.canvas.after:
                Color(*CYAN_DIM)
                self._edge_line = Rectangle(
                    pos=(self.x, self.y),
                    size=(dp(2), self.height),
                )

        msg_label = Label(
            text=message,
            font_size=dp(13),
            color=text_color,
            halign="left",
            valign="top",
            size_hint_y=None,
        )
        msg_label.bind(
            size=msg_label.setter('texture_size'),
            texture_size=self._adjust_height,
        )
        self.add_widget(msg_label)

        if timestamp:
            time_label = Label(
                text=timestamp,
                font_size=dp(10),
                color=TEXT_HINT,
                size_hint_y=None,
                height=dp(14),
                halign="right",
            )
            self.add_widget(time_label)

    def on_pos(self, *args):
        if hasattr(self, '_edge_line') and self.role == "assistant":
            self._edge_line.pos = (self.x, self.y)
        elif hasattr(self, '_edge_line') and self.role == "user":
            self._edge_line.pos = (self.right - dp(2), self.y)

    def on_size(self, *args):
        if hasattr(self, '_edge_line'):
            self._edge_line.size = (dp(2), self.height)

    def _adjust_height(self, instance, value):
        self.height = value[1] + dp(36)


# ─── StatsCard (向后兼容，GlowCard 风格) ──────────────────────────────────────

class StatsCard(MDCard):
    """统计数据卡片（未来简洁风升级版）。"""

    stat_label = StringProperty("")
    stat_value = NumericProperty(0)
    badge_color = ColorProperty((0.5, 0.5, 0.5, 1))

    def __init__(self, stat_label="", stat_value=0, badge_color=None, **kwargs):
        super().__init__(**kwargs)
        self.stat_label = stat_label
        self.stat_value = stat_value
        if badge_color:
            self.badge_color = badge_color

        self.size_hint_x = 1
        self.size_hint_y = None
        self.height = dp(70)
        self.padding = dp(10)
        self.spacing = dp(4)
        self.style = "elevated"
        self.elevation = 0
        self.radius = [dp(16)]
        self.orientation = "vertical"
        self.md_bg_color = BG_SURFACE_SOLID

        value_label = Label(
            text=str(stat_value),
            font_size=dp(24),
            bold=True,
            color=self.badge_color[:3] + (1,),
            size_hint_y=None,
            height=dp(32),
            halign="center",
            valign="middle",
        )
        self.add_widget(value_label)
        self._value_label = value_label

        label_text = Label(
            text=stat_label,
            font_size=dp(12),
            color=TEXT_SECONDARY,
            size_hint_y=None,
            height=dp(18),
            halign="center",
        )
        self.add_widget(label_text)

    def update_value(self, new_value):
        self.stat_value = new_value
        self._value_label.text = str(new_value)


# ─── ProviderChip (向后兼容) ──────────────────────────────────────────────────

class ProviderChip(MDChip):
    """供应商芯片（向后兼容）。"""

    provider_name = StringProperty("")
    is_enabled = BooleanProperty(True)

    def __init__(self, provider_name="", is_enabled=True, on_toggle=None, **kwargs):
        super().__init__(**kwargs)
        self.provider_name = provider_name
        self.is_enabled = is_enabled
        self.on_toggle = on_toggle
        self.text = provider_name
        self.icon = "check-circle" if is_enabled else "close-circle"
        self.color = (0.0, 0.8, 0.4, 1) if is_enabled else (0.5, 0.5, 0.5, 1)
        self.type = "filter"
        self.adaptive_size = True

    def toggle(self):
        self.is_enabled = not self.is_enabled
        self.icon = "check-circle" if self.is_enabled else "close-circle"
        self.color = (0.0, 0.8, 0.4, 1) if self.is_enabled else (0.5, 0.5, 0.5, 1)
        if self.on_toggle:
            self.on_toggle(self.provider_name, self.is_enabled)


# ─── ModelDropdown (向后兼容) ─────────────────────────────────────────────────

class ModelDropdown(MDBoxLayout):
    """模型下拉选择器（向后兼容）。"""

    selected_model = StringProperty("")
    models = ListProperty([])
    provider_name = StringProperty("")

    def __init__(self, provider_name="", models=None, selected_model="",
                 on_select=None, **kwargs):
        super().__init__(**kwargs)
        self.provider_name = provider_name
        self.models = models or []
        self.selected_model = selected_model or (self.models[0] if self.models else "")
        self.on_select = on_select

        self.orientation = "horizontal"
        self.adaptive_height = True
        self.spacing = dp(6)

        self._label = Label(
            text=self.selected_model or "未选择",
            font_size=dp(12),
            color=TEXT_PRIMARY,
            size_hint=(0.7, None),
            height=dp(24),
            halign="left",
            valign="middle",
        )
        self.add_widget(self._label)

        dropdown_btn = MDButton(
            MDButtonText(text="▼", font_style="label"),
            style="text",
            size_hint_x=None,
            width=dp(36),
            on_release=self._open_menu,
        )
        self.add_widget(dropdown_btn)
        self.menu = None

    def _open_menu(self, instance):
        if not self.models:
            return
        menu_items = [{"text": m, "on_release": lambda m=m: self._select_model(m)}
                      for m in self.models]
        self.menu = MDDropdownMenu(
            caller=instance,
            items=menu_items,
            max_height=dp(200),
        )
        self.menu.open()

    def _select_model(self, model):
        self.selected_model = model
        self._label.text = model
        if self.menu:
            self.menu.dismiss()
        if self.on_select:
            self.on_select(self.provider_name, model)

    def set_models(self, models, selected=""):
        self.models = models
        if selected and selected in models:
            self.selected_model = selected
            self._label.text = selected
        elif models:
            self.selected_model = models[0]
            self._label.text = models[0]


# ─── APIKeyDialog (向后兼容) ──────────────────────────────────────────────────

class APIKeyDialog:
    """API Key 输入对话框（向后兼容）。"""

    def __init__(self, provider_name="", on_save=None, **kwargs):
        self.provider_name = provider_name
        self.on_save = on_save

        self._text_field = MDTextField(
            hint_text=f"请输入 {provider_name.upper()} API Key",
            mode="filled",
            password=True,
            size_hint_x=1,
        )

        self.dialog = MDDialog(
            MDDialogHeadlineText(
                text=f"添加 {provider_name.upper() if provider_name else ''} API Key",
            ),
            MDBoxLayout(
                self._text_field,
                orientation="vertical",
                adaptive_height=True,
                spacing=dp(12),
                padding=dp(16),
            ),
            MDDialogButtonContainer(
                MDButton(
                    MDButtonText(text="取消"),
                    style="text",
                    on_release=lambda x: self.dialog.dismiss(),
                ),
                MDButton(
                    MDButtonText(text="保存"),
                    style="filled",
                    on_release=self._on_save,
                ),
                spacing=dp(8),
            ),
            size_hint_x=0.9,
            size_hint_y=None,
        )

    def open(self):
        self._text_field.text = ""
        self.dialog.open()

    def _on_save(self, instance):
        api_key = self._text_field.text.strip()
        if api_key and self.on_save:
            self.on_save(self.provider_name, api_key)
        self.dialog.dismiss()
