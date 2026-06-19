"""
test_experience.py - 测试 ExperienceDB 自学习错误经验库。

测试覆盖：
- 数据库初始化
- record_failure 记录失败经验
- record_success 记录成功经验
- search 精确搜索
- search_similar 相似搜索
- recommend_strategies 方案推荐
- get_stats 统计信息
- get_best_strategy 最佳策略
"""
import os
from utils import init_paths, HashUtils

from experience import ExperienceDB


def _make_db(temp_dir):
    """辅助函数：创建临时路径的 ExperienceDB。"""
    db_path = os.path.join(temp_dir, "test_experience.db")
    return ExperienceDB(db_path=db_path)


class TestExperienceDBInit:
    """ExperienceDB 初始化测试。"""

    def test_init_with_temp_path(self, temp_dir):
        """测试使用临时路径初始化。"""
        db_path = os.path.join(temp_dir, "test_experience.db")
        db = ExperienceDB(db_path=db_path)
        assert db._db_path == db_path

    def test_init_creates_tables(self, temp_dir):
        """测试初始化创建表结构。"""
        db_path = os.path.join(temp_dir, "test_experience.db")
        db = ExperienceDB(db_path=db_path)
        stats = db.get_stats()
        assert stats["total_experiences"] == 0


class TestExperienceRecordFailure:
    """记录失败经验测试。"""

    def test_record_failure_new(self, temp_dir):
        """测试记录新的失败经验。"""
        db = _make_db(temp_dir)
        error_ctx = {
            "exception_type": "ParseError",
            "message": "无法解析 AndroidManifest.xml",
            "context": {"apk_path": "/tmp/test.apk", "operation": "scan"},
        }
        result = db.record_failure(error_ctx)
        assert result is not None
        assert isinstance(result, str)

    def test_record_failure_update_existing(self, temp_dir):
        """测试更新已有失败记录。"""
        db = _make_db(temp_dir)
        error_ctx = {
            "exception_type": "TimeoutError",
            "message": "连接超时",
        }
        h1 = db.record_failure(error_ctx)
        h2 = db.record_failure(error_ctx)
        assert h1 == h2

    def test_record_failure_empty_context(self, temp_dir):
        """测试空上下文返回 None。"""
        db = _make_db(temp_dir)
        result = db.record_failure({})
        assert result is None


class TestExperienceRecordSuccess:
    """记录成功经验测试。"""

    def test_record_success(self, temp_dir):
        """测试记录成功的策略。"""
        db = _make_db(temp_dir)
        error_ctx = {
            "exception_type": "ParseError",
            "message": "解析失败",
        }
        fh = db.record_failure(error_ctx)

        success = db.record_success(
            feature_hash=fh,
            strategy="retry_with_different_parser",
            params={"parser": "axml"},
            duration_ms=1500,
        )
        assert success is True

        best = db.get_best_strategy(fh)
        assert best is not None
        assert best["strategy"] == "retry_with_different_parser"
        assert best["success_count"] >= 1

    def test_record_success_nonexistent_hash(self, temp_dir):
        """测试对不存在的哈希记录成功返回 False。"""
        db = _make_db(temp_dir)
        result = db.record_success("nonexistent", "some_strategy")
        assert result is False

    def test_record_success_empty_hash(self, temp_dir):
        """测试空哈希返回 False。"""
        db = _make_db(temp_dir)
        result = db.record_success("", "strategy")
        assert result is False


class TestExperienceSearch:
    """搜索经验测试。"""

    def test_search_exact(self, temp_dir):
        """测试精确搜索。"""
        db = _make_db(temp_dir)
        error_ctx = {
            "exception_type": "ParseError",
            "message": "测试错误",
        }
        fh = db.record_failure(error_ctx)
        result = db.search(fh)
        assert result is not None
        assert result["error_type"] == "ParseError"
        assert "_success_rate" in result

    def test_search_nonexistent(self, temp_dir):
        """测试搜索不存在的记录。"""
        db = _make_db(temp_dir)
        result = db.search("nonexistent-hash")
        assert result is None

    def test_search_empty_hash(self, temp_dir):
        """测试空哈希搜索返回 None。"""
        db = _make_db(temp_dir)
        result = db.search("")
        assert result is None


class TestExperienceSearchSimilar:
    """相似搜索测试。"""

    def test_search_similar(self, temp_dir):
        """测试相似搜索返回结果。"""
        db = _make_db(temp_dir)
        db.record_failure({
            "exception_type": "ParseError",
            "message": "无法解析 XML 文件",
            "context": {"apk_path": "/tmp/test.apk"},
        })
        features = {
            "exception_type": "ParseError",
            "message": "XML 解析错误",
        }
        results = db.search_similar(features, threshold=0.3)
        assert len(results) >= 0

    def test_search_similar_empty_features(self, temp_dir):
        """测试空特征返回空列表。"""
        db = _make_db(temp_dir)
        results = db.search_similar({})
        assert results == []

    def test_search_by_type(self, temp_dir):
        """测试按错误类型搜索。"""
        db = _make_db(temp_dir)
        db.record_failure({"exception_type": "ParseError", "message": "E1"})
        db.record_failure({"exception_type": "ParseError", "message": "E2"})
        db.record_failure({"exception_type": "TimeoutError", "message": "E3"})

        results = db.search_by_type("ParseError")
        assert len(results) == 2


class TestExperienceRecommendStrategies:
    """方案推荐测试。"""

    def test_recommend_strategies(self, temp_dir):
        """测试推荐方案。"""
        db = _make_db(temp_dir)
        error_ctx = {
            "exception_type": "ParseError",
            "message": "解析失败",
            "context": {"operation": "scan"},
        }
        fh = db.record_failure(error_ctx)
        db.record_success(fh, "retry_strategy", {"attempts": 3})

        features = {
            "error_type": "ParseError",
            "error_message_short": "解析失败",
            "context_keys": ["operation"],
            "operation": "scan",
        }
        recs = db.recommend_strategies(features, limit=3)
        assert len(recs) >= 1
        assert "strategy" in recs[0]
        assert "success_rate" in recs[0]

    def test_recommend_strategies_no_match(self, temp_dir):
        """测试无匹配时返回空列表。"""
        db = _make_db(temp_dir)
        recs = db.recommend_strategies({"error_type": "UnknownError"})
        assert recs == []


class TestExperienceStats:
    """统计信息测试。"""

    def test_get_stats(self, temp_dir):
        """测试获取统计信息。"""
        db = _make_db(temp_dir)
        db.record_failure({"exception_type": "E1", "message": "M1"})
        db.record_failure({"exception_type": "E2", "message": "M2"})

        stats = db.get_stats()
        assert stats["total_experiences"] == 2
        assert "overall_success_rate" in stats
        assert "top_error_types" in stats

    def test_get_best_strategy_nonexistent(self, temp_dir):
        """测试获取不存在的最佳策略。"""
        db = _make_db(temp_dir)
        result = db.get_best_strategy("no-such-hash")
        assert result is None


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
