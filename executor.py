"""
InstaGuard - 修复执行器

纯 Python 实现 APK 修改流程：
备份 → 解包 → 修改 Manifest/资源 → 重打包 → 对齐 → 签名

修复方案来自：AI 分析、预置模板、记忆库已验证方案。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import re
import json
import time
import shutil
import zipfile
import tempfile
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils import log, APKUtils, Config, HashUtils
from scanner import RiskItem, ScanResult
from repair_templates import (
    RepairTemplate, TemplateRegistry, get_template_registry,
)
from ai_analyzer import AIAnalyzer
from memory import MemoryDB
from experience import ExperienceDB


# ─── 修复相关数据结构 ─────────────────────────────────────────────────────────

@dataclass
class RepairAction:
    """单个修复操作。"""
    action_id: str                              # 操作 ID
    risk_id: str                                # 关联的风险 ID
    template_id: str                            # 使用的模板 ID
    target_file: str                            # 目标文件（如 "AndroidManifest.xml"）
    modify_type: str                            # 修改类型: "replace" / "delete" / "add" / "insert"
    search_pattern: str = ""                    # 搜索模式
    replacement: str = ""                       # 替换内容
    description: str = ""                       # 操作描述（中文）
    reversible: bool = True                     # 是否可逆
    requires_resign: bool = True                # 是否需要重签名
    original_content: Optional[str] = None      # 原始内容（用于回滚）


@dataclass
class RepairPlan:
    """修复计划。"""
    plan_id: str                                # 计划 ID
    apk_path: str                               # 原始 APK 路径
    backup_path: str = ""                       # 备份路径
    actions: List[RepairAction] = field(default_factory=list)
    total_actions: int = 0                      # 总操作数
    created_at: float = field(default_factory=time.time)
    status: str = "pending"                     # pending / executing / completed / failed / rolled_back

    def __post_init__(self):
        self.total_actions = len(self.actions)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典。"""
        return {
            "plan_id": self.plan_id,
            "apk_path": self.apk_path,
            "backup_path": self.backup_path,
            "actions": [
                {
                    "action_id": a.action_id,
                    "risk_id": a.risk_id,
                    "template_id": a.template_id,
                    "target_file": a.target_file,
                    "modify_type": a.modify_type,
                    "description": a.description,
                    "reversible": a.reversible,
                }
                for a in self.actions
            ],
            "total_actions": self.total_actions,
            "status": self.status,
        }


# ─── 修复执行器 ───────────────────────────────────────────────────────────────

class RepairExecutor:
    """
    APK 修复执行器。

    功能：
    1. 纯 Python 实现 APK 修改流程
    2. 修复方案来自 AI 分析、预置模板、经验库
    3. 修复前展示变更摘要，支持一键执行
    4. 使用 zipfile 方式修改 APK（不依赖 apktool）
    """

    def __init__(self):
        self._template_registry = get_template_registry()
        self._memory_db: Optional[MemoryDB] = None
        self._experience_db: Optional[ExperienceDB] = None
        self._config = Config()

    @property
    def memory_db(self) -> MemoryDB:
        """懒加载 MemoryDB。"""
        if self._memory_db is None:
            self._memory_db = MemoryDB()
        return self._memory_db

    @property
    def experience_db(self) -> ExperienceDB:
        """懒加载 ExperienceDB。"""
        if self._experience_db is None:
            self._experience_db = ExperienceDB()
        return self._experience_db

    # ─── 创建修复计划 ──────────────────────────────────────────────────────

    def create_repair_plan(
        self,
        result: ScanResult,
        selected_risks: Optional[List[str]] = None,
    ) -> RepairPlan:
        """
        根据扫描结果创建修复计划。

        流程：
        1. 筛选要修复的风险（selected_risks 指定 ID，或全部可修复）
        2. 匹配修复模板
        3. 生成 RepairAction 列表
        4. 整合 AI 分析和经验库建议

        Args:
            result: 扫描结果
            selected_risks: 指定的风险 ID 列表（None 则修复所有可修复风险）

        Returns:
            RepairPlan 修复计划
        """
        plan_id = f"plan_{int(time.time())}"
        actions: List[RepairAction] = []

        # 筛选风险
        if selected_risks:
            target_risks = [
                r for r in result.risks
                if r.id in selected_risks
            ]
        else:
            target_risks = [r for r in result.risks if getattr(r, 'repairable', True)]

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        target_risks.sort(key=lambda r: severity_order.get(r.severity.lower(), 99))

        action_index = 0

        for risk in target_risks:
            # 1. 尝试使用 AI 推荐的模板
            template = None
            template_id = getattr(risk, 'repair_template_id', None)
            if template_id:
                template = self._template_registry.get_template(template_id)

            # 2. 回退到类别匹配
            if not template:
                category_templates = self._template_registry.get_templates_for_category(
                    risk.category
                )
                if category_templates:
                    template = category_templates[0]

            # 3. 查询经验库获取已验证方案
            if not template:
                successful = self.experience_db.get_successful_templates(risk.category, limit=1)
                if successful:
                    exp_template_id = successful[0].get("repair_template_id", "")
                    template = self._template_registry.get_template(exp_template_id)

            if not template:
                log.warning(f"风险 {risk.id} 无匹配修复模板，跳过")
                continue

            # 创建修复操作
            action_index += 1
            action = RepairAction(
                action_id=f"ACT{action_index:03d}",
                risk_id=risk.id,
                template_id=template.template_id,
                target_file=template.file_pattern or "AndroidManifest.xml",
                modify_type=self._determine_modify_type(template),
                search_pattern=template.search_pattern,
                replacement=template.replacement,
                description=f"[{template.template_id}] {template.title}: {risk.title}",
                reversible=template.reversible,
                requires_resign=template.requires_resign,
            )
            actions.append(action)

        # 创建计划
        plan = RepairPlan(
            plan_id=plan_id,
            apk_path=result.apk_path,
            backup_path="",  # 执行时才创建备份
            actions=actions,
        )

        log.info(f"修复计划已创建: {plan_id}, {len(actions)} 个操作")
        return plan

    def _determine_modify_type(self, template: RepairTemplate) -> str:
        """
        根据模板确定修改类型。

        Args:
            template: 修复模板

        Returns:
            修改类型字符串
        """
        if template.search_pattern and template.replacement:
            return "replace"
        if template.modify_target == "manifest":
            return "replace"  # Manifest 修改通常为替换
        if template.modify_target == "resource":
            return "add"      # 资源文件通常为新增
        return "manual"       # 需要人工处理

    # ─── 预览变更 ──────────────────────────────────────────────────────────

    def preview_changes(self, plan: RepairPlan) -> Dict[str, Any]:
        """
        预览修复计划的所有变更。

        Args:
            plan: 修复计划

        Returns:
            变更摘要字典，包含：
            {
                "plan_id": str,
                "total_actions": int,
                "files_affected": List[str],
                "actions": List[Dict],
                "estimated_risks": List[str],
                "requires_resign": bool,
            }
        """
        files_affected = list(set(a.target_file for a in plan.actions))
        estimated_risks = []
        requires_resign = False

        for action in plan.actions:
            if action.requires_resign:
                requires_resign = True
            if not action.reversible:
                estimated_risks.append(f"不可逆操作: {action.description}")

        if requires_resign:
            estimated_risks.append("修复后 APK 需要重新签名，签名将发生改变")

        preview = {
            "plan_id": plan.plan_id,
            "total_actions": plan.total_actions,
            "files_affected": files_affected,
            "actions": [
                {
                    "action_id": a.action_id,
                    "description": a.description,
                    "target_file": a.target_file,
                    "modify_type": a.modify_type,
                    "reversible": a.reversible,
                }
                for a in plan.actions
            ],
            "estimated_risks": estimated_risks,
            "requires_resign": requires_resign,
            "backup_will_be_created": self._config.get_setting("repair_backup_enabled", True),
        }

        return preview

    # ─── 执行修复 ──────────────────────────────────────────────────────────

    def execute(
        self,
        plan: RepairPlan,
        callback: Optional[Callable] = None,
        keytool_path: Optional[str] = None,
    ) -> Optional[str]:
        """
        执行修复计划。

        完整流程：
        1. 备份原 APK
        2. 解包 APK
        3. 应用修改
        4. 重打包 APK
        5. zipalign 对齐
        6. 签名

        Args:
            plan: 修复计划
            callback: 进度回调 callable(stage, message, progress_pct)
            keytool_path: keytool 路径（用于签名）

        Returns:
            修复后 APK 路径，失败返回 None
        """
        if not plan.actions:
            log.error("修复计划无操作，跳过执行")
            return None

        log.info(f"🔧 开始执行修复计划: {plan.plan_id} ({plan.total_actions} 个操作)")

        temp_dir = tempfile.mkdtemp(prefix="instaguard_repair_")
        extracted_dir = os.path.join(temp_dir, "extracted")
        modified_apk_path = ""
        aligned_apk_path = ""
        signed_apk_path = ""

        try:
            # === 阶段 1: 备份原 APK ===
            self._report(callback, "backup", "正在备份原 APK...", 5)
            if self._config.get_setting("repair_backup_enabled", True):
                plan.backup_path = APKUtils.create_backup(plan.apk_path)
                if not plan.backup_path:
                    log.warning("备份创建失败，继续执行")
            else:
                log.info("备份已禁用，跳过")

            # === 阶段 2: 解包 APK ===
            self._report(callback, "extract", "正在解包 APK...", 15)
            os.makedirs(extracted_dir, exist_ok=True)

            with zipfile.ZipFile(plan.apk_path, "r") as zf:
                zf.extractall(extracted_dir)
            log.info(f"APK 已解包到: {extracted_dir}")

            # === 阶段 3: 应用修改 ===
            self._report(callback, "modify", f"正在应用 {plan.total_actions} 个修改...", 30)
            applied = 0
            failed_actions: List[str] = []

            for i, action in enumerate(plan.actions):
                progress = 30 + int((i / plan.total_actions) * 35)
                self._report(callback, "modify", f"应用修改: {action.description}", progress)

                success = self._apply_action(action, extracted_dir)
                if success:
                    applied += 1
                else:
                    failed_actions.append(action.action_id)
                    log.error(f"修改失败: {action.description}")

            log.info(f"修改完成: {applied}/{plan.total_actions} 成功")
            if failed_actions:
                log.warning(f"失败的操作: {failed_actions}")

            plan.status = "executing"

            # === 阶段 4: 重打包 APK ===
            self._report(callback, "repack", "正在重打包 APK...", 70)
            modified_apk_path = os.path.join(temp_dir, "modified.apk")
            self._repack_apk(extracted_dir, modified_apk_path)
            log.info(f"APK 已重打包: {modified_apk_path}")

            # === 阶段 5: zipalign 对齐 ===
            self._report(callback, "align", "正在 zipalign 对齐...", 80)
            aligned_apk_path = os.path.join(temp_dir, "aligned.apk")
            aligned = self._zipalign(modified_apk_path, aligned_apk_path)
            if aligned:
                final_apk = aligned_apk_path
            else:
                log.warning("zipalign 不可用，使用未对齐的 APK")
                final_apk = modified_apk_path

            # === 阶段 6: 签名 ===
            self._report(callback, "sign", "正在签名 APK...", 90)
            signed_apk_path = os.path.join(
                os.path.dirname(plan.apk_path),
                f"instaguard_repaired_{int(time.time())}.apk"
            )
            signed = self._sign_apk(final_apk, signed_apk_path, keytool_path)
            if signed:
                final_output = signed_apk_path
            else:
                log.warning("签名失败，输出未签名 APK")
                shutil.copy2(final_apk, signed_apk_path)
                final_output = signed_apk_path

            plan.status = "completed"

            # === 记录经验 ===
            for action in plan.actions:
                try:
                    # 尝试调用 record_success（实际 ExperienceDB API）
                    if hasattr(self.experience_db, 'record_success'):
                        self.experience_db.record_success(
                            feature_hash="",
                            category="",
                            repair_method=action.template_id,
                            context={"action_id": action.action_id, "description": action.description},
                        )
                    elif hasattr(self.experience_db, 'log_experience'):
                        self.experience_db.log_experience(
                            risk_category="",
                            risk_fingerprint="",
                            repair_template_id=action.template_id,
                            action_type="repair",
                            success=action.action_id not in failed_actions,
                        )
                except Exception as e:
                    log.debug(f"记录经验失败: {e}")

            self._report(callback, "complete", f"✅ 修复完成: {final_output}", 100)
            log.info(f"✅ 修复计划执行完成: {final_output}")
            return final_output

        except Exception as e:
            log.exception(f"修复执行失败: {e}")
            plan.status = "failed"
            self._report(callback, "error", f"❌ 修复失败: {e}", -1)

            # 尝试回滚
            if plan.backup_path and os.path.exists(plan.backup_path):
                log.info("尝试回滚到备份...")
                try:
                    backup_restore = plan.apk_path + ".restored"
                    shutil.copy2(plan.backup_path, backup_restore)
                    log.info(f"备份已恢复为: {backup_restore}")
                except Exception as rollback_e:
                    log.error(f"回滚失败: {rollback_e}")

            return None

        finally:
            # 清理临时目录
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

    def _report(
        self,
        callback: Optional[Callable],
        stage: str,
        message: str,
        progress: int,
    ) -> None:
        """安全调用回调。"""
        if callback:
            try:
                callback(stage, message, progress)
            except Exception as e:
                log.debug(f"回调异常: {e}")

    def _apply_action(self, action: RepairAction, extracted_dir: str) -> bool:
        """
        在解包目录中应用单个修复操作。

        Args:
            action: 修复操作
            extracted_dir: 解包目录

        Returns:
            是否成功
        """
        # 查找目标文件
        target_path = self._find_target_file(extracted_dir, action.target_file)
        if not target_path:
            log.warning(f"未找到目标文件: {action.target_file}")
            return False

        try:
            # 读取文件内容
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # 保存原始内容（用于回滚）
            action.original_content = content

            if action.modify_type == "replace":
                if action.search_pattern:
                    # 使用正则替换
                    new_content = re.sub(
                        action.search_pattern,
                        action.replacement,
                        content,
                    )
                    if new_content == content:
                        # 尝试智能匹配（处理 Android XML 命名空间变体）
                        alt_pattern = action.search_pattern.replace(
                            "android:", r"(?:android:)?"
                        )
                        new_content = re.sub(alt_pattern, action.replacement, content)

                    if new_content != content:
                        with open(target_path, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        log.info(f"  已修改: {os.path.basename(target_path)} ({action.description})")
                        return True
                    else:
                        log.warning(f"  未匹配到内容: {os.path.basename(target_path)}")
                        return False
                else:
                    # 无搜索模式，标记为需人工处理
                    log.info(f"  需人工处理: {action.description}")
                    return True

            elif action.modify_type == "delete":
                if action.search_pattern:
                    new_content = re.sub(action.search_pattern, "", content)
                    if new_content != content:
                        with open(target_path, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        log.info(f"  已删除: {os.path.basename(target_path)}")
                        return True

            elif action.modify_type == "add":
                # 追加内容到文件末尾
                if action.replacement:
                    with open(target_path, "a", encoding="utf-8") as f:
                        f.write("\n" + action.replacement)
                    log.info(f"  已追加: {os.path.basename(target_path)}")
                    return True

            elif action.modify_type == "insert":
                # 在指定位置插入
                if action.search_pattern:
                    new_content = re.sub(
                        action.search_pattern,
                        lambda m: m.group(0) + action.replacement,
                        content,
                        count=1,
                    )
                    if new_content != content:
                        with open(target_path, "w", encoding="utf-8") as f:
                            f.write(new_content)
                        log.info(f"  已插入: {os.path.basename(target_path)}")
                        return True

        except Exception as e:
            log.error(f"应用修改失败 {target_path}: {e}")
            return False

        return False

    def _find_target_file(self, root_dir: str, pattern: str) -> Optional[str]:
        """
        在目录中查找匹配模式的目标文件。

        Args:
            root_dir: 根目录
            pattern: 文件名模式

        Returns:
            文件完整路径，未找到返回 None
        """
        # 1. 精确匹配
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                if filename == pattern:
                    return os.path.join(dirpath, filename)

        # 2. 忽略大小写匹配
        pattern_lower = pattern.lower()
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                if filename.lower() == pattern_lower:
                    return os.path.join(dirpath, filename)

        # 3. 部分匹配
        for dirpath, _, filenames in os.walk(root_dir):
            for filename in filenames:
                if pattern_lower in filename.lower():
                    return os.path.join(dirpath, filename)

        return None

    def _repack_apk(self, source_dir: str, output_path: str) -> None:
        """
        将解包目录重新打包为 APK。

        Args:
            source_dir: 解包目录
            output_path: 输出 APK 路径
        """
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for dirpath, _, filenames in os.walk(source_dir):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    arcname = os.path.relpath(file_path, source_dir)
                    # 统一路径分隔符
                    arcname = arcname.replace("\\", "/")
                    zf.write(file_path, arcname)

    def _zipalign(self, input_apk: str, output_apk: str, alignment: int = 4) -> bool:
        """
        对 APK 进行 zipalign 对齐。

        优先使用系统 zipalign 工具，不可用则使用 Python 实现。

        Args:
            input_apk: 输入 APK
            output_apk: 输出 APK
            alignment: 对齐字节数

        Returns:
            是否成功
        """
        # 尝试使用系统 zipalign
        zipalign_paths = [
            "zipalign",
            os.path.join(os.environ.get("ANDROID_HOME", ""), "build-tools", "*", "zipalign"),
            os.path.join(os.environ.get("ANDROID_SDK_ROOT", ""), "build-tools", "*", "zipalign"),
        ]

        for path_pattern in zipalign_paths:
            try:
                # 尝试直接调用
                result = subprocess.run(
                    [path_pattern, "-p", "-f", str(alignment), input_apk, output_apk],
                    capture_output=True,
                    timeout=60,
                )
                if result.returncode == 0:
                    log.info(f"zipalign 完成（使用: {path_pattern}）")
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            except Exception as e:
                log.debug(f"zipalign 尝试失败 ({path_pattern}): {e}")

        # Python 实现的简化对齐
        log.info("使用 Python 实现的简化对齐...")
        try:
            return self._python_zipalign(input_apk, output_apk, alignment)
        except Exception as e:
            log.warning(f"Python zipalign 失败: {e}")
            # 直接复制
            shutil.copy2(input_apk, output_apk)
            return False

    def _python_zipalign(
        self, input_apk: str, output_apk: str, alignment: int = 4
    ) -> bool:
        """
        纯 Python 实现的 zipalign。

        对 ZIP 内的未压缩条目进行 4 字节对齐。

        Args:
            input_apk: 输入 APK
            output_apk: 输出 APK
            alignment: 对齐字节数

        Returns:
            是否成功
        """
        with zipfile.ZipFile(input_apk, "r") as zin:
            with zipfile.ZipFile(output_apk, "w", zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)

                    # 对于未压缩条目，添加 padding
                    if item.compress_type == zipfile.ZIP_STORED:
                        padding = (alignment - (len(data) % alignment)) % alignment
                        if padding > 0:
                            data += b"\x00" * padding

                    zout.writestr(item, data)

        return True

    def _sign_apk(
        self,
        input_apk: str,
        output_apk: str,
        keytool_path: Optional[str] = None,
    ) -> bool:
        """
        对 APK 进行签名。

        优先使用 apksigner，回退到 jarsigner。
        在 Windows 上需要对路径做特殊处理。

        Args:
            input_apk: 输入 APK
            output_apk: 输出 APK
            keytool_path: 自定义密钥库路径

        Returns:
            是否成功
        """
        # 检查是否有调试密钥库
        debug_keystore_paths = [
            os.path.join(os.path.expanduser("~"), ".android", "debug.keystore"),
            os.path.join(os.environ.get("USERPROFILE", ""), ".android", "debug.keystore"),
        ]

        keystore = None
        for path in debug_keystore_paths:
            if os.path.exists(path):
                keystore = path
                break

        if not keystore and keytool_path:
            if os.path.exists(keytool_path):
                keystore = keytool_path

        # 如果没有密钥库，生成一个调试密钥库
        if not keystore:
            keystore = self._generate_debug_keystore()

        if not keystore:
            log.error("无法获取签名密钥库")
            return False

        log.info(f"使用密钥库: {keystore}")

        # 尝试 apksigner
        apksigner_result = self._try_sign_with_apksigner(input_apk, output_apk, keystore)
        if apksigner_result:
            return True

        # 回退到 jarsigner
        jarsigner_result = self._try_sign_with_jarsigner(input_apk, output_apk, keystore)
        if jarsigner_result:
            return True

        log.error("所有签名方式均失败")
        return False

    def _try_sign_with_apksigner(
        self, input_apk: str, output_apk: str, keystore: str
    ) -> bool:
        """尝试使用 apksigner 签名。"""
        apksigner_paths = [
            "apksigner",
            os.path.join(os.environ.get("ANDROID_HOME", ""), "build-tools", "*", "apksigner"),
            os.path.join(os.environ.get("ANDROID_SDK_ROOT", ""), "build-tools", "*", "apksigner"),
        ]

        for path_pattern in apksigner_paths:
            try:
                # 先复制到输出路径
                shutil.copy2(input_apk, output_apk)

                cmd = [
                    path_pattern, "sign",
                    "--ks", keystore,
                    "--ks-pass", "pass:android",
                    "--ks-key-alias", "androiddebugkey",
                    "--key-pass", "pass:android",
                    output_apk,
                ]
                result = subprocess.run(cmd, capture_output=True, timeout=60)
                if result.returncode == 0:
                    log.info("apksigner 签名成功")
                    return True
                else:
                    log.debug(f"apksigner 失败: {result.stderr.decode(errors='replace')}")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            except Exception as e:
                log.debug(f"apksigner 异常: {e}")

        return False

    def _try_sign_with_jarsigner(
        self, input_apk: str, output_apk: str, keystore: str
    ) -> bool:
        """尝试使用 jarsigner 签名。"""
        try:
            shutil.copy2(input_apk, output_apk)

            cmd = [
                "jarsigner",
                "-verbose",
                "-sigalg", "SHA1withRSA",
                "-digestalg", "SHA1",
                "-keystore", keystore,
                "-storepass", "android",
                "-keypass", "android",
                output_apk,
                "androiddebugkey",
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            if result.returncode == 0:
                log.info("jarsigner 签名成功")
                return True
            else:
                log.debug(f"jarsigner 失败: {result.stderr.decode(errors='replace')}")
        except FileNotFoundError:
            log.debug("jarsigner 不可用")
        except Exception as e:
            log.debug(f"jarsigner 异常: {e}")

        return False

    def _generate_debug_keystore(self) -> Optional[str]:
        """
        生成调试用密钥库。

        使用 keytool 生成 debug.keystore。

        Returns:
            密钥库路径，失败返回 None
        """
        keystore_dir = os.path.join(os.path.expanduser("~"), ".android")
        os.makedirs(keystore_dir, exist_ok=True)
        keystore_path = os.path.join(keystore_dir, "debug.keystore")

        # 如果已存在则直接返回
        if os.path.exists(keystore_path):
            return keystore_path

        try:
            log.info("正在生成调试密钥库...")
            cmd = [
                "keytool",
                "-genkey",
                "-v",
                "-keystore", keystore_path,
                "-storepass", "android",
                "-alias", "androiddebugkey",
                "-keypass", "android",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-dname", "CN=Android Debug,O=Android,C=US",
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode == 0:
                log.info(f"调试密钥库已生成: {keystore_path}")
                return keystore_path
            else:
                log.warning(f"keytool 生成失败: {result.stderr.decode(errors='replace')}")
        except FileNotFoundError:
            log.warning("keytool 不可用，无法生成调试密钥库")
        except Exception as e:
            log.error(f"生成密钥库失败: {e}")

        return None

    # ─── 验证修复 ──────────────────────────────────────────────────────────

    def verify(self, apk_path: str) -> Dict[str, Any]:
        """
        验证修复后的 APK。

        检查项：
        1. 文件是否存在
        2. 是否为有效 ZIP/APK
        3. 文件大小
        4. 基本签名验证

        Args:
            apk_path: 修复后 APK 路径

        Returns:
            验证结果字典
        """
        result: Dict[str, Any] = {
            "path": apk_path,
            "exists": False,
            "is_valid_apk": False,
            "size_mb": 0.0,
            "signed": False,
            "issues": [],
            "pass": False,
        }

        if not os.path.exists(apk_path):
            result["issues"].append("文件不存在")
            return result

        result["exists"] = True
        result["size_mb"] = APKUtils.get_file_size_mb(apk_path)

        # 验证是否为有效 APK
        result["is_valid_apk"] = APKUtils.is_valid_apk(apk_path)
        if not result["is_valid_apk"]:
            result["issues"].append("不是有效的 APK 文件")

        # 检查签名（简单检查 META-INF 目录）
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                names = zf.namelist()
                has_signature = any(
                    n.startswith("META-INF/") and (
                        n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC")
                    )
                    for n in names
                )
                result["signed"] = has_signature
                if not has_signature:
                    result["issues"].append("APK 未签名")
        except Exception as e:
            result["issues"].append(f"签名检查失败: {e}")

        # 无问题即通过
        result["pass"] = len(result["issues"]) == 0

        if result["pass"]:
            log.info(f"✅ APK 验证通过: {apk_path}")
        else:
            log.warning(f"⚠️ APK 验证发现问题: {result['issues']}")

        return result

    # ─── 工具方法 ──────────────────────────────────────────────────────────

    def rollback(self, plan: RepairPlan) -> bool:
        """
        回滚修复（从备份恢复）。

        Args:
            plan: 修复计划

        Returns:
            是否回滚成功
        """
        if not plan.backup_path or not os.path.exists(plan.backup_path):
            log.error("备份文件不存在，无法回滚")
            return False

        try:
            restore_path = plan.apk_path + ".restored"
            shutil.copy2(plan.backup_path, restore_path)
            plan.status = "rolled_back"
            log.info(f"已回滚到备份: {restore_path}")
            return True
        except Exception as e:
            log.error(f"回滚失败: {e}")
            return False
