"""
InstaGuard - Android 安全扫描与修复应用
Main entry point

基于 Kivy/KivyMD 的跨平台 Android APK 安全扫描工具。
支持 AI 驱动的智能风险识别和自动修复。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import sys

# ─── 路径设置 ──────────────────────────────────────────────────────────────────
# 确保项目根目录在 Python 路径中
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# ─── 初始化环境 ────────────────────────────────────────────────────────────────
from utils import initialize, log, APP_NAME, APP_VERSION

initialize()

# ─── Android 权限请求 ──────────────────────────────────────────────────────────
try:
    from android.permissions import request_permissions, Permission
    request_permissions([
        Permission.READ_EXTERNAL_STORAGE,
        Permission.WRITE_EXTERNAL_STORAGE,
        Permission.RECORD_AUDIO,   # 语音输入
        Permission.INTERNET,
    ])
    log.info("Android 权限已请求")
except ImportError:
    # 桌面环境，无需权限
    pass

# ─── Kivy 设置 ─────────────────────────────────────────────────────────────────
from kivy.config import Config as KivyConfig

# 禁止多点触控红色点（调试用）
KivyConfig.set("input", "mouse", "mouse,disable_multitouch")
# 窗口图标
KivyConfig.set("kivy", "window_icon", os.path.join(_project_root, "icon.png"))
# 退出确认
KivyConfig.set("kivy", "exit_on_escape", "0")

# ─── Kivy 应用 ─────────────────────────────────────────────────────────────────
from kivy.app import App
from kivy.core.window import Window
from kivy.utils import platform
from kivy.metrics import dp

# Material Design
from kivymd.app import MDApp
from kivymd.uix.bottomnavigation import MDBottomNavigation, MDBottomNavigationItem
from kivymd.uix.screen import MDScreen

# UI 屏幕
from ui.screens import AssistantScreen, ScanScreen, SettingsScreen


class InstaGuardApp(MDApp):
    """
    InstaGuard 主应用类。

    使用 Material Design 底部导航的三屏布局：
    - 助手 (Assistant): AI 对话交互
    - 扫描 (Scan): APK 安全扫描与分析
    - 设置 (Settings): 供应商、API Key、通用配置
    """

    title: str = APP_NAME
    """应用标题"""

    def __init__(self, **kwargs) -> None:
        """初始化 InstaGuard 应用。"""
        super().__init__(**kwargs)
        log.info(f"InstaGuardApp v{APP_VERSION} 启动中...")

    def build(self) -> MDBottomNavigation:
        """
        构建应用 UI。

        创建底部导航栏，包含三个主要标签页。

        Returns:
            MDBottomNavigation 底部导航组件
        """
        # 主题配置
        self.theme_cls.primary_palette = "DeepPurple"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.material_style = "M3"

        # 窗口大小（桌面环境使用手机比例）
        if platform != "android":
            Window.size = (420, 780)
            Window.minimum_width = 360
            Window.minimum_height = 600

        # 创建屏幕实例
        self.assistant_screen = AssistantScreen()
        self.scan_screen = ScanScreen()
        self.settings_screen = SettingsScreen()

        # ─── 底部导航 ──────────────────────────────────────────────────────

        self.bottom_nav = MDBottomNavigation(
            panel_color=self.theme_cls.backgroundColor,
            text_color_active=self.theme_cls.primaryColor,
        )

        # 助手标签页
        tab_assistant = MDBottomNavigationItem(
            self.assistant_screen,
            name="assistant",
            text="助手",
            icon="message-text",
            badge_icon="numeric-1-circle" if False else "",
        )
        self.bottom_nav.add_widget(tab_assistant)

        # 扫描标签页
        tab_scan = MDBottomNavigationItem(
            self.scan_screen,
            name="scan",
            text="扫描",
            icon="shield-search",
        )
        self.bottom_nav.add_widget(tab_scan)

        # 设置标签页
        tab_settings = MDBottomNavigationItem(
            self.settings_screen,
            name="settings",
            text="设置",
            icon="cog",
        )
        self.bottom_nav.add_widget(tab_settings)

        log.info("UI 构建完成")
        return self.bottom_nav

    def on_start(self) -> None:
        """应用启动后回调。"""
        super().on_start()
        log.info("InstaGuard 已启动")
        if platform == "android":
            Window.bind(on_keyboard=self._on_android_back)

    def on_stop(self) -> None:
        """应用退出前回调。"""
        log.info("InstaGuard 正在退出...")
        # 保存配置
        try:
            from utils import Config
            Config().save()
            log.info("配置已保存")
        except Exception as e:
            log.warning(f"配置保存失败: {e}")

    def on_pause(self) -> bool:
        """应用暂停回调（Android）。"""
        log.debug("InstaGuard 进入后台")
        return True

    def on_resume(self) -> None:
        """应用恢复回调（Android）。"""
        log.debug("InstaGuard 恢复运行")

    def _on_android_back(self, window, key, *args) -> bool:
        """处理 Android 返回键。

        Args:
            window: Kivy 窗口对象
            key: 按键代码

        Returns:
            是否已处理
        """
        if key == 27:  # ESC / Android 返回键
            # 如果当前不是在第一个标签页，则不让返回键退出
            if self.bottom_nav.current != "assistant":
                self.bottom_nav.switch_tab("assistant")
                return True
        return False


# ─── 入口点 ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        app = InstaGuardApp()
        app.run()
    except Exception as e:
        log.exception(f"应用启动失败: {e}")
        # 在桌面环境显示错误
        if platform != "android":
            import traceback
            traceback.print_exc()
