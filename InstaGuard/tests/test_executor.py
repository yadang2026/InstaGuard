"""
test_executor.py - 测试修复执行器 RepairExecutor。

测试覆盖：
- 执行器初始化
- create_repair_plan 修复计划创建
- preview_changes 预览变更
- modify_manifest（使用 mock APK）
- zipalign_fallback
- _apply_action / _find_target_file
- verify 验证
- rollback 回滚
"""
import os
import tempfile
import zipfile
from unittest.mock import patch, MagicMock

from scanner import RiskItem, ScanResult
from repair_templates import RepairTemplate, TemplateRegistry, get_template_registry
from executor import RepairExecutor, RepairPlan, RepairAction


class TestExecutorInit:
    """执行器初始化测试。"""

    def test_init(self):
        """测试执行器初始化。"""
        executor = RepairExecutor()
        assert executor._template_registry is not None
        assert executor._config is not None

    def test_memory_db_lazy(self):
        """测试 MemoryDB 懒加载。"""
        executor = RepairExecutor()
        assert executor._memory_db is None
        db = executor.memory_db
        assert executor._memory_db is not None

    def test_experience_db_lazy(self):
        """测试 ExperienceDB 懒加载。"""
        executor = RepairExecutor()
        assert executor._experience_db is None
        db = executor.experience_db
        assert executor._experience_db is not None


class TestCreateRepairPlan:
    """修复计划创建测试。"""

    def _make_sample_result(self):
        """创建含风险项的 ScanResult。"""
        result = ScanResult(
            apk_path="/tmp/test.apk",
            package_name="com.example.test",
        )
        risk = RiskItem(
            id="R001",
            category="debuggable",
            severity="high",
            title="可调试",
            description="应用可调试",
            fingerprint="fp001",
            evidence='android:debuggable="true"',
            recommendation="设置 debuggable=false",
        )
        # 设置修复属性
        setattr(risk, 'repair_template_id', 'TPL001')
        setattr(risk, 'repairable', True)
        setattr(risk, 'ai_analysis', 'done')
        result.add_risk(risk)
        return result

    def test_create_repair_plan_all(self):
        """测试为所有风险创建修复计划。"""
        executor = RepairExecutor()
        result = self._make_sample_result()
        plan = executor.create_repair_plan(result)
        assert isinstance(plan, RepairPlan)
        assert plan.apk_path == "/tmp/test.apk"
        assert plan.status == "pending"
        assert len(plan.actions) >= 1

    def test_create_repair_plan_selected(self):
        """测试为指定风险创建修复计划。"""
        executor = RepairExecutor()
        result = self._make_sample_result()
        plan = executor.create_repair_plan(result, selected_risks=["R001"])
        assert len(plan.actions) >= 1
        assert plan.actions[0].risk_id == "R001"

    def test_create_repair_plan_no_repairable(self):
        """测试无风险时返回空计划。"""
        executor = RepairExecutor()
        result = ScanResult(apk_path="/tmp/test.apk")
        plan = executor.create_repair_plan(result)
        assert len(plan.actions) == 0

    def test_repair_plan_to_dict(self):
        """测试 RepairPlan.to_dict()。"""
        plan = RepairPlan(plan_id="test-plan", apk_path="/tmp/test.apk")
        d = plan.to_dict()
        assert d["plan_id"] == "test-plan"
        assert "actions" in d


class TestPreviewChanges:
    """预览变更测试。"""

    def test_preview_changes(self):
        """测试预览变更摘要。"""
        executor = RepairExecutor()
        action = RepairAction(
            action_id="ACT001",
            risk_id="R001",
            template_id="TPL001",
            target_file="AndroidManifest.xml",
            modify_type="replace",
            search_pattern='android:debuggable="true"',
            replacement='android:debuggable="false"',
            description="移除调试标志",
        )
        plan = RepairPlan(
            plan_id="test-plan",
            apk_path="/tmp/test.apk",
            actions=[action],
        )
        preview = executor.preview_changes(plan)
        assert preview["total_actions"] == 1
        assert "AndroidManifest.xml" in preview["files_affected"]
        assert preview["requires_resign"] is True


class TestModifyManifest:
    """Manifest 修改测试（使用临时文件模拟）。"""

    def test_apply_action_replace(self, temp_dir):
        """测试替换模式修改文件。"""
        executor = RepairExecutor()

        # 创建测试文件
        test_file = os.path.join(temp_dir, "AndroidManifest.xml")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write('<manifest><application android:debuggable="true">test</application></manifest>')

        action = RepairAction(
            action_id="ACT001",
            risk_id="R001",
            template_id="TPL001",
            target_file="AndroidManifest.xml",
            modify_type="replace",
            search_pattern=r'android:debuggable="true"',
            replacement=r'android:debuggable="false"',
            description="移除调试标志",
        )
        success = executor._apply_action(action, temp_dir)
        assert success is True

        # 验证修改结果
        with open(test_file, "r", encoding="utf-8") as f:
            content = f.read()
        assert 'android:debuggable="false"' in content

    def test_find_target_file_exact(self, temp_dir):
        """测试精确匹配查找文件。"""
        executor = RepairExecutor()
        test_file = os.path.join(temp_dir, "subdir", "AndroidManifest.xml")
        os.makedirs(os.path.dirname(test_file), exist_ok=True)
        with open(test_file, "w") as f:
            f.write("test")

        found = executor._find_target_file(temp_dir, "AndroidManifest.xml")
        assert found is not None
        assert "AndroidManifest.xml" in found

    def test_find_target_file_not_found(self, temp_dir):
        """测试未找到文件返回 None。"""
        executor = RepairExecutor()
        found = executor._find_target_file(temp_dir, "nonexistent_file.xml")
        assert found is None


class TestZipalignFallback:
    """zipalign 降级方案测试。"""

    def test_python_zipalign(self, temp_dir):
        """测试 Python 实现的 zipalign。"""
        executor = RepairExecutor()

        # 创建测试 APK（最小 ZIP）
        input_apk = os.path.join(temp_dir, "input.apk")
        output_apk = os.path.join(temp_dir, "output.apk")

        with zipfile.ZipFile(input_apk, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("test.txt", "hello world")

        result = executor._python_zipalign(input_apk, output_apk)
        assert result is True
        assert os.path.exists(output_apk)

    def test_zipalign_fallback(self, temp_dir):
        """测试 zipalign 系统工具不可用时回退。"""
        executor = RepairExecutor()
        input_apk = os.path.join(temp_dir, "in.apk")
        output_apk = os.path.join(temp_dir, "out.apk")

        with zipfile.ZipFile(input_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")

        with patch.object(executor, "_python_zipalign", return_value=True):
            result = executor._zipalign(input_apk, output_apk)
            assert result is True

    def test_repack_apk(self, temp_dir):
        """测试重新打包 APK。"""
        executor = RepairExecutor()
        source = os.path.join(temp_dir, "extracted")
        os.makedirs(source, exist_ok=True)
        with open(os.path.join(source, "AndroidManifest.xml"), "w") as f:
            f.write("<manifest/>")
        with open(os.path.join(source, "classes.dex"), "w") as f:
            f.write("dex")

        output = os.path.join(temp_dir, "repacked.apk")
        executor._repack_apk(source, output)
        assert os.path.exists(output)
        assert zipfile.is_zipfile(output)


class TestVerify:
    """验证修复测试。"""

    def test_verify_nonexistent(self):
        """测试验证不存在的 APK。"""
        executor = RepairExecutor()
        result = executor.verify("/nonexistent/path.apk")
        assert result["exists"] is False
        assert result["pass"] is False

    def test_rollback_no_backup(self):
        """测试无备份时回滚失败。"""
        executor = RepairExecutor()
        plan = RepairPlan(plan_id="test", apk_path="/tmp/test.apk", backup_path="")
        assert executor.rollback(plan) is False

    def test_rollback_with_backup(self, temp_dir):
        """测试有备份时的回滚。"""
        executor = RepairExecutor()
        # 创建备份文件
        backup_path = os.path.join(temp_dir, "test.apk.backup")
        original_path = os.path.join(temp_dir, "test.apk")
        with open(backup_path, "w") as f:
            f.write("backup data")
        with open(original_path, "w") as f:
            f.write("original")

        plan = RepairPlan(
            plan_id="test",
            apk_path=original_path,
            backup_path=backup_path,
        )
        assert executor.rollback(plan) is True
        assert plan.status == "rolled_back"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
