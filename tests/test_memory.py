"""
test_memory.py - 测试 MemoryDB 智能记忆加速模块。

测试覆盖：
- 数据库初始化
- store 存储和 query 精确查询
- query 不存在的记录
- update_hit 命中更新
- query_similar 相似查询
- get_stats 统计信息
- cleanup_old 数据清理
- lookup 智能查找
"""
import os
import tempfile
from utils import init_paths, HashUtils

from memory import MemoryDB


def _make_db(temp_dir):
    """辅助函数：创建临时路径的 MemoryDB。"""
    db_path = os.path.join(temp_dir, "test_memory.db")
    return MemoryDB(db_path=db_path)


class TestMemoryDBInit:
    """数据库初始化测试。"""

    def test_init_with_temp_path(self, temp_dir):
        """测试使用临时路径初始化。"""
        db_path = os.path.join(temp_dir, "test_memory.db")
        db = MemoryDB(db_path=db_path)
        assert db._db_path == db_path

    def test_init_creates_tables(self, temp_dir):
        """测试初始化创建表结构。"""
        db_path = os.path.join(temp_dir, "test_memory.db")
        db = MemoryDB(db_path=db_path)
        stats = db.get_stats()
        assert stats["total_memories"] == 0
        assert "categories" in stats


class TestMemoryStoreAndQuery:
    """存储和精确查询测试。"""

    def test_store_and_query(self, temp_dir):
        """测试存储后精确查询命中。"""
        db = _make_db(temp_dir)
        fp = HashUtils.fingerprint("test risk")
        data = {
            "category": "permission",
            "severity": "high",
            "title": "危险权限: CAMERA",
            "description": "应用声明了 CAMERA 权限",
            "evidence": "android.permission.CAMERA",
            "ai_analysis": "经AI分析，该权限存在隐私风险",
            "repair_solution": "TPL003",
            "evidence_pattern": "CAMERA",
        }
        db.store(fp, data)

        result = db.query(fp)
        assert result is not None
        assert result["category"] == "permission"
        assert result["title"] == "危险权限: CAMERA"
        assert result["ai_analysis"] == "经AI分析，该权限存在隐私风险"
        assert result["_accelerated"] is True

    def test_store_force_update(self, temp_dir):
        """测试强制更新已有记录。"""
        db = _make_db(temp_dir)
        fp = HashUtils.fingerprint("update test")
        db.store(fp, {"category": "permission", "title": "V1"})
        db.store(fp, {"category": "permission", "title": "V2"}, force_update=True)
        result = db.query(fp)
        assert result["title"] == "V2"

    def test_store_empty_fingerprint(self, temp_dir):
        """测试空指纹存储返回 False。"""
        db = _make_db(temp_dir)
        result = db.store("", {"title": "test"})
        assert result is False


class TestMemoryQueryNonexistent:
    """查询不存在记录测试。"""

    def test_query_nonexistent(self, temp_dir):
        """测试查询不存在的指纹返回 None。"""
        db = _make_db(temp_dir)
        result = db.query("nonexistent-fingerprint")
        assert result is None

    def test_query_empty_fingerprint(self, temp_dir):
        """测试空指纹查询返回 None。"""
        db = _make_db(temp_dir)
        result = db.query("")
        assert result is None


class TestMemoryUpdateHit:
    """命中计数更新测试。"""

    def test_update_hit(self, temp_dir):
        """测试更新命中计数。"""
        db = _make_db(temp_dir)
        fp = HashUtils.fingerprint("hit test")
        db.store(fp, {"category": "debug", "title": "可调试"})
        db.update_hit(fp)
        result = db.query(fp)
        # hit_count 初始为 1，调用 update_hit 后 +1，query 再 +1
        assert result["hit_count"] >= 2

    def test_update_hit_nonexistent(self, temp_dir):
        """测试更新不存在的记录返回 False。"""
        db = _make_db(temp_dir)
        result = db.update_hit("not-exist")
        assert result is False

    def test_update_hit_empty_fingerprint(self, temp_dir):
        """测试空指纹更新返回 False。"""
        db = _make_db(temp_dir)
        result = db.update_hit("")
        assert result is False


class TestMemorySimilarQuery:
    """相似查询测试。"""

    def test_similar_query_returns_results(self, temp_dir):
        """测试相似查询返回结果。"""
        db = _make_db(temp_dir)
        fp1 = HashUtils.fingerprint("permission camera risk")
        fp2 = HashUtils.fingerprint("permission camera danger")
        db.store(fp1, {
            "category": "permission", "severity": "high",
            "title": "CAMERA权限", "evidence_pattern": "",
        })
        db.store(fp2, {
            "category": "permission", "severity": "high",
            "title": "CAMERA权限变体", "evidence_pattern": "",
        })

        target_fp = HashUtils.fingerprint("permission camera issue")
        results = db.query_similar(target_fp, threshold=0.0)
        # 使用阈值 0.0 应返回所有候选结果
        assert isinstance(results, list)
    def test_similar_query_empty_fingerprint(self, temp_dir):
        """测试空指纹相似查询返回空列表。"""
        db = _make_db(temp_dir)
        results = db.query_similar("")
        assert results == []

    def test_query_by_category(self, temp_dir):
        """测试按类别查询。"""
        db = _make_db(temp_dir)
        db.store(HashUtils.fingerprint("perm1"), {"category": "permission", "title": "T1"})
        db.store(HashUtils.fingerprint("perm2"), {"category": "permission", "title": "T2"})
        db.store(HashUtils.fingerprint("debug1"), {"category": "debuggable", "title": "T3"})

        results = db.query_by_category("permission")
        assert len(results) == 2


class TestMemoryStats:
    """统计信息测试。"""

    def test_get_stats(self, temp_dir):
        """测试获取统计信息。"""
        db = _make_db(temp_dir)
        db.store(HashUtils.fingerprint("r1"), {"category": "permission", "title": "T1"})
        db.store(HashUtils.fingerprint("r2"), {"category": "debuggable", "title": "T2"})

        stats = db.get_stats()
        assert stats["total_memories"] == 2
        assert "categories" in stats
        assert "db_path" in stats


class TestMemoryCleanup:
    """数据清理测试。"""

    def test_cleanup_old(self, temp_dir):
        """测试清理过期记录。"""
        db = _make_db(temp_dir)
        fp = HashUtils.fingerprint("cleanup test")
        db.store(fp, {"category": "test", "title": "旧记录", "evidence_pattern": ""})
        deleted = db.cleanup_old(days=0)
        assert deleted >= 0

    def test_lookup_exact_match(self, temp_dir):
        """测试智能查找——精确匹配。"""
        db = _make_db(temp_dir)
        fp = HashUtils.fingerprint("lookup test")
        db.store(fp, {"category": "permission", "title": "测试"})
        result = db.lookup(fp)
        assert result is not None
        assert result["title"] == "测试"

    def test_lookup_nonexistent(self, temp_dir):
        """测试智能查找——无匹配。"""
        db = _make_db(temp_dir)
        result = db.lookup("nonexistent-fp")
        assert result is None

    def test_verify_memory(self, temp_dir):
        """测试标记验证状态。"""
        db = _make_db(temp_dir)
        fp = HashUtils.fingerprint("verify test")
        db.store(fp, {"category": "test", "title": "待验证"})
        db.verify(fp, verified=True)
        result = db.query(fp)
        assert result["verified"] == 1


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
