# InstaGuard 🔒

**Android 安全扫描与修复应用** — 基于 AI 驱动的自动化 APK 安全分析工具。

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![Kivy](https://img.shields.io/badge/Kivy-2.3%2B-green.svg)](https://kivy.org)
[![KivyMD](https://img.shields.io/badge/KivyMD-1.2%2B-purple.svg)](https://github.com/kivymd/KivyMD)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 功能概述

| 功能 | 描述 |
|------|------|
| 🔍 **APK 扫描** | 深度扫描 APK 文件，检查 Manifest、权限、组件导出、硬编码密钥等 |
| 🤖 **AI 风险分析** | 支持多 AI 供应商（OpenAI、Anthropic、DeepSeek、Ollama 等）进行智能安全分析 |
| 🔧 **自动修复** | 一键修复常见安全漏洞：权限裁剪、组件锁定、加密加固 |
| 💬 **AI 助手** | 内置对话助手，解答安全相关问题，指导修复流程 |
| 📊 **报告导出** | 生成 JSON 格式的详细安全审计报告 |
| 🧠 **记忆库** | 记录已修复的风险，相似问题自动匹配历史解决方案 |
| 📚 **经验库** | 从修复成功/失败中学习，持续优化修复策略 |

---

## 🏗️ 架构说明

```
┌─────────────────────────────────────────────────────────────┐
│                       InstaGuard                             │
├───────────────┬───────────────────┬─────────────────────────┤
│   UI Layer    │   Business Layer   │    Data Layer           │
│   (KivyMD)    │                    │                         │
├───────────────┼───────────────────┼─────────────────────────┤
│ main.py       │ agent.py           │ memory.py               │
│ ui/screens.py │ - InstaGuardAgent  │ - MemoryDB (SQLite)     │
│ ui/widgets.py │                    │                         │
│               │ scanner.py         │ experience.py           │
│               │ - APKScanner       │ - ExperienceDB (SQLite) │
│               │ - ScanResult       │                         │
│               │                    │ utils.py                │
│               │ ai_analyzer.py     │ - Config (JSON)         │
│               │ - AIAnalyzer       │ - Logger                │
│               │                    │ - HashUtils             │
│               │ executor.py        │ - APKUtils              │
│               │ - RepairExecutor   │                         │
│               │                    │ provider_manager.py     │
│               │ repair_templates.py│ - ProviderManager       │
│               │ - TemplateRegistry │ - Multi-AI clients      │
└───────────────┴───────────────────┴─────────────────────────┘
```

### 数据流

```
APK 文件 → Scanner (androguard) → RiskItem[] → AIAnalyzer (LLM)
    → 增强分析 → RepairExecutor → 修复后的 APK
    → 记忆库/经验库 ← 学习反馈 ← 修复结果
```

---

## 🚀 安装与运行

### 前置要求

- Python 3.11+
- pip / uv 包管理器

### 桌面环境

```bash
# 1. 克隆项目
git clone https://github.com/your-org/InstaGuard.git
cd InstaGuard

# 2. 创建虚拟环境（推荐）
python -m venv venv
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 3. 安装依赖
pip install -r requirements.txt

# 4. 运行
python main.py
```

### 桌面环境（使用 uv）

```bash
uv pip install -r requirements.txt
python main.py
```

### Android 环境

Android 平台通过 Buildozer 打包为 APK，详见下方 [📦 Buildozer 打包](#-buildozer-打包) 章节。

---

## 📦 Buildozer 打包

### 1. 安装 Buildozer

```bash
pip install buildozer
```

### 2. 初始化配置

```bash
buildozer init
```

### 3. 编辑 `buildozer.spec`

修改以下关键配置项：

```ini
# 应用标识
package.name = instaguard
package.domain = com.nousresearch

# Python 版本
requirements = python3,kivy==2.3.0,kivymd==1.2.0,androguard,openai,anthropic,httpx,requests,lxml,cryptography

# Android 权限
android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,RECORD_AUDIO

# 最低 API 级别
android.api = 30
android.minapi = 24

# 架构支持
android.arch = arm64-v8a, armeabi-v7a

# 退出行为（按返回键不退出）
android.allow_backup = True

# 应用图标
icon.filename = %(source.dir)s/icon.png

# 日志级别
log_level = 2
```

### 4. 构建与部署

```bash
# 构建 debug APK
buildozer android debug

# 构建 release APK（需要签名）
buildozer android release

# 构建并自动部署到连接的设备
buildozer android debug deploy run

# 查看日志
buildozer android logcat
```

---

## 📁 项目结构树

```
InstaGuard/
├── main.py                    # 应用入口，MDApp 主类
├── utils.py                   # 共享工具：Config、Logger、Hash、APK 操作
├── provider_manager.py        # 多 AI 供应商管理器
├── scanner.py                 # APK 扫描器（androguard 集成）
├── memory.py                  # 记忆库（SQLite）
├── experience.py              # 经验库（SQLite）
├── ai_analyzer.py             # AI 风险分析器
├── repair_templates.py        # 修复模板注册表
├── executor.py                # 修复执行器
├── agent.py                   # InstaGuard 智能代理
├── requirements.txt           # Python 依赖列表
├── README.md                  # 项目文档（本文件）
├── buildozer.spec             # Buildozer Android 打包配置
├── icon.png                   # 应用图标
│
├── ui/                        # UI 模块
│   ├── __init__.py
│   ├── screens.py             # 主屏幕（Assistant、Scan、Settings）
│   └── widgets.py             # 可复用组件（RiskCard、StatsCard、对话气泡等）
│
└── assets/                    # 资源文件（可选）
    ├── fonts/
    └── images/
```

---

## ⚙️ 配置说明

配置文件自动保存在 `~/.instaguard/config.json`（Android 上为应用私有目录）。

### 配置项

| 配置键 | 默认值 | 描述 |
|--------|--------|------|
| `memory_similarity_threshold` | `0.85` | 记忆库指纹匹配相似度阈值 (0.50-0.99) |
| `max_apk_size_mb` | `500` | 最大允许扫描的 APK 文件大小 (MB) |
| `repair_backup_enabled` | `true` | 修复前是否自动备份 APK |
| `voice_input_enabled` | `true` | 是否启用语音输入 |
| `language` | `zh` | 界面语言 |

### 供应商配置

```json
{
  "providers": {
    "openai": {
      "name": "openai",
      "display_name": "OpenAI",
      "default_endpoint": "https://api.openai.com/v1",
      "api_keys": ["sk-..."],
      "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
      "active_model": "gpt-4o",
      "enabled": true
    }
  }
}
```

---

## 🤖 AI 供应商配置指南

### OpenAI

1. 访问 [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2. 创建 API Key
3. 在 InstaGuard 设置页 → "添加 Key" → 选择 OpenAI → 粘贴 Key

### Anthropic (Claude)

1. 访问 [console.anthropic.com](https://console.anthropic.com/)
2. 生成 API Key
3. 在设置页添加到 Anthropic

### DeepSeek

1. 访问 [platform.deepseek.com](https://platform.deepseek.com/)
2. 获取 API Key
3. 在设置页添加到 DeepSeek

### Ollama（本地部署）

```bash
# 安装 Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 拉取模型
ollama pull llama3
ollama pull mistral

# 启动服务
ollama serve

# 在 InstaGuard 设置页点击"检测"
```

### 自定义供应商

支持任何兼容 OpenAI API 格式的服务：
1. 在设置中选择"自定义"
2. 配置端点 URL 和模型名称
3. 添加 API Key（如果需要）

---

## 🔧 开发指南

### 添加新的风险检测规则

在 `scanner.py` 中扩展 `APKScanner` 类：

```python
class APKScanner:
    def scan(self, apk_path: str) -> List[ScanResult]:
        results = []
        results.extend(self._check_permissions())
        results.extend(self._check_exported_components())
        results.extend(self._check_hardcoded_secrets())
        # 添加自定义规则...
        return results
```

### 添加新的修复模板

在 `repair_templates.py` 中注册：

```python
@TemplateRegistry.register("new_fix")
class NewFixTemplate(RepairTemplate):
    name = "new_fix"
    description = "自定义修复"
    
    def can_fix(self, risk: RiskItem) -> bool:
        return risk.severity in ("high", "critical")
    
    def execute(self, apk_path: str, risk: RiskItem) -> bool:
        # 实现修复逻辑...
        return True
```

---

## 🤝 贡献指南

欢迎贡献！请遵循以下流程：

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

### 代码规范

- Python 3.11+，使用类型注解
- 遵循 PEP 8
- 所有注释使用中文
- 新功能需包含文档字符串
- UI 组件遵循 KivyMD Material Design 3 规范

---

## 📄 许可证

MIT License © 2026 InstaGuard Team

---

## 🙏 致谢

- [Kivy](https://kivy.org/) - 跨平台 Python GUI 框架
- [KivyMD](https://github.com/kivymd/KivyMD) - Material Design 组件库
- [Androguard](https://github.com/androguard/androguard) - APK 静态分析
- [Buildozer](https://github.com/kivy/buildozer) - Python → Android 打包工具
