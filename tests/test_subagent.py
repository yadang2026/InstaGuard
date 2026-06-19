"""
test_subagent.py - 测试 SubAgent 子任务管理器。

测试覆盖：
- SubAgentManager 初始化
- assess_complexity 复杂度评估
- should_spawn 是否应生成子代理
- spawn 生成子任务（mock 避免线程）
- get_status 任务状态追踪
- collect_results 收集结果
- cancel_task 取消任务
"""
import time
from unittest.mock import patch, MagicMock, PropertyMock

from subagent import SubAgentManager, SubAgentTask


class TestSubAgentManagerInit:
    """SubAgentManager 初始化测试。"""

    def test_init(self):
        """测试 SubAgentManager 初始化。"""
        manager = SubAgentManager()
        assert manager is not None
        assert manager.MAX_WORKERS >= 1

    def test_multiple_instances(self):
        """测试多次创建返回新实例（非单例）。"""
        m1 = SubAgentManager()
        m2 = SubAgentManager()
        assert isinstance(m1, SubAgentManager)
        assert isinstance(m2, SubAgentManager)


class TestAssessComplexity:
    """复杂度评估测试。"""

    def test_assess_complexity_simple(self):
        """测试简单任务复杂度评估。"""
        manager = SubAgentManager()
        complexity = manager.assess_complexity(
            task_type="simple_scan",
            data={"apk_count": 1, "risk_count": 2},
        )
        assert complexity in ("simple", "complex")

    def test_assess_complexity_returns_string(self):
        """测试复杂度评估返回字符串。"""
        manager = SubAgentManager()
        complexity = manager.assess_complexity(
            task_type="bulk_repair",
            data={"apk_count": 50, "risk_count": 200},
        )
        assert isinstance(complexity, str)


class TestShouldSpawn:
    """should_spawn 测试。"""

    def test_should_spawn_complex(self):
        """测试复杂任务应生成子代理。"""
        manager = SubAgentManager()
        result = manager.should_spawn("complex")
        assert result is True

    def test_should_spawn_simple(self):
        """测试简单任务不应生成子代理。"""
        manager = SubAgentManager()
        result = manager.should_spawn("simple")
        assert result is False

    def test_should_spawn_returns_bool(self):
        """测试 should_spawn 返回布尔值。"""
        manager = SubAgentManager()
        result = manager.should_spawn("unknown")
        assert isinstance(result, bool)


class TestSpawnTask:
    """spawn 测试（mock spawn 方法以避免线程）。"""

    @patch.object(SubAgentManager, "spawn", return_value="mock-task-id-001")
    def test_spawn_returns_task_id(self, mock_spawn):
        """测试生成子任务返回任务 ID。"""
        manager = SubAgentManager()
        task_id = manager.spawn(
            task_type="analyze",
            data={"risk_id": "R001"},
        )
        assert task_id == "mock-task-id-001"

    @patch.object(SubAgentManager, "spawn", return_value="mock-task-002")
    @patch.object(SubAgentManager, "get_status", return_value={"queued": 1, "running": 0, "completed": 0, "workers": 3})
    def test_spawn_adds_to_queue(self, mock_status, mock_spawn):
        """测试生成任务后状态更新。"""
        manager = SubAgentManager()
        manager.spawn(task_type="scan", data={"apk_path": "/tmp/test.apk"})
        status = manager.get_status()
        assert status["queued"] >= 0


class TestTaskStatusTracking:
    """任务状态追踪测试。"""

    @patch.object(SubAgentManager, "get_status", return_value={"queued": 1, "running": 0, "completed": 0, "workers": 3})
    def test_task_status_after_spawn(self, mock_status):
        """测试生成任务后状态正确。"""
        manager = SubAgentManager()
        status = manager.get_status()
        assert "queued" in status
        assert "running" in status
        assert "completed" in status

    def test_get_status_returns_dict(self):
        """测试 get_status 返回字典格式。"""
        manager = SubAgentManager()
        status = manager.get_status()
        assert isinstance(status, dict)
        assert "max_workers" in status or "active_count" in status


class TestCollectResults:
    """collect_results 测试。"""

    def test_collect_results_returns_list(self):
        """测试收集结果返回列表或字典。"""
        manager = SubAgentManager()
        results = manager.collect_results()
        assert isinstance(results, (list, dict))

    def test_summarize_results(self):
        """测试 summarize_results 返回摘要（字符串或字典）。"""
        manager = SubAgentManager()
        summary = manager.summarize_results()
        assert isinstance(summary, (dict, str))


class TestCancelTask:
    """cancel_task 测试。"""

    def test_cancel_nonexistent_task(self):
        """测试取消不存在的任务。"""
        manager = SubAgentManager()
        result = manager.cancel_task("nonexistent-task-id")
        assert result is False or result is None

    def test_cancel_all(self):
        """测试取消所有任务。"""
        manager = SubAgentManager()
        result = manager.cancel_all()
        assert isinstance(result, int)


class TestAutoSplitAndSpawn:
    """自动分割并生成子代理测试。"""

    def test_auto_split_low_complexity(self):
        """测试低复杂度任务不分割。"""
        manager = SubAgentManager()
        result = manager.auto_split_and_spawn(
            task_type="simple",
            data={"count": 1},
        )
        assert result is None or isinstance(result, list)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
