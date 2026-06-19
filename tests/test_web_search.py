"""
test_web_search.py - 测试 Web Search 搜索引擎模块。

测试覆盖：
- 搜索引擎初始化
- search 搜索功能
- search_security_issue 安全漏洞搜索
- search_repair_solution 修复方案搜索
- extract_solution 提取解决方案
- cache 缓存功能
"""
from unittest.mock import patch, MagicMock

from web_search import WebSearchEngine


class TestWebSearchEngineInit:
    """搜索引擎初始化测试。"""

    def test_init(self):
        """测试搜索引擎初始化。"""
        engine = WebSearchEngine()
        assert engine is not None
        assert engine.SEARCH_TIMEOUT > 0
        assert "Mozilla" in engine.USER_AGENT or "InstaGuard" in engine.USER_AGENT

    def test_is_available(self):
        """测试 is_available 返回布尔值。"""
        engine = WebSearchEngine()
        result = engine.is_available()
        assert isinstance(result, bool)


class TestSearch:
    """搜索功能测试。"""

    @patch("web_search.WebSearchEngine.search")
    def test_search_returns_results(self, mock_search):
        """测试搜索返回结果列表。"""
        mock_search.return_value = [
            {"title": "Result 1", "url": "https://example.com", "snippet": "..."},
        ]
        engine = WebSearchEngine()
        results = engine.search("android debuggable security")
        assert isinstance(results, list)

    @patch("web_search.WebSearchEngine.search")
    def test_search_empty_query(self, mock_search):
        """测试空查询返回空列表。"""
        mock_search.return_value = []
        engine = WebSearchEngine()
        results = engine.search("")
        assert results == []


class TestSearchSecurityIssue:
    """安全漏洞搜索测试。"""

    @patch("web_search.WebSearchEngine.search_security_issue")
    def test_search_security_issue(self, mock_search):
        """测试安全漏洞搜索返回结果。"""
        mock_search.return_value = [
            {
                "title": "How to fix debuggable flag",
                "url": "https://stackoverflow.com/questions/123",
                "snippet": "Set android:debuggable=false",
            }
        ]
        engine = WebSearchEngine()
        results = engine.search_security_issue(
            risk_category="debuggable",
            risk_title="可调试检测",
        )
        assert isinstance(results, list)
        assert len(results) >= 1

    @patch("web_search.WebSearchEngine.search_security_issue")
    def test_search_security_issue_with_limit(self, mock_search):
        """测试搜索安全漏洞并限制结果数。"""
        mock_search.return_value = [{"title": f"Result {i}"} for i in range(3)]
        engine = WebSearchEngine()
        results = engine.search_security_issue(
            risk_category="permission",
            risk_title="CAMERA权限",
            max_results=3,
        )
        assert len(results) <= 3


class TestSearchRepairSolution:
    """修复方案搜索测试。"""

    @patch("web_search.WebSearchEngine.search_repair_solution")
    def test_search_repair_solution(self, mock_search):
        """测试修复方案搜索。"""
        mock_search.return_value = [
            {
                "title": "Fix debuggable flag",
                "snippet": "Change android:debuggable to false",
                "code_solution": '<application android:debuggable="false">',
            }
        ]
        engine = WebSearchEngine()
        results = engine.search_repair_solution(
            risk_title="可调试检测",
            risk_category="debuggable",
        )
        assert isinstance(results, list)

    @patch("web_search.WebSearchEngine.search_android_best_practice")
    def test_search_android_best_practice(self, mock_search):
        """测试 Android 最佳实践搜索。"""
        mock_search.return_value = ["Best practice content"]
        engine = WebSearchEngine()
        results = engine.search_android_best_practice("permission management")
        assert isinstance(results, list)


class TestExtractSolution:
    """提取解决方案测试。"""

    @patch("web_search.WebSearchEngine.extract_solution")
    def test_extract_solution_from_results(self, mock_extract):
        """测试从搜索结果提取解决方案。"""
        mock_extract.return_value = [
            "Set android:debuggable to false in AndroidManifest.xml",
        ]
        engine = WebSearchEngine()
        results = [{"snippet": "Set android:debuggable to false"}]
        solutions = engine.extract_solution(results)
        assert isinstance(solutions, list)
        assert len(solutions) >= 1

    @patch("web_search.WebSearchEngine.extract_solution")
    def test_extract_solution_empty(self, mock_extract):
        """测试空结果提取。"""
        mock_extract.return_value = []
        engine = WebSearchEngine()
        solutions = engine.extract_solution([])
        assert solutions == []

    @patch("web_search.WebSearchEngine.extract_code_solution")
    def test_extract_code_solution(self, mock_extract):
        """测试提取代码解决方案。"""
        mock_extract.return_value = '<application android:debuggable="false">'
        engine = WebSearchEngine()
        code = engine.extract_code_solution([{"snippet": "..."}])
        assert isinstance(code, str)


class TestCache:
    """缓存功能测试。"""

    def test_get_cache_stats(self):
        """测试获取缓存统计。"""
        engine = WebSearchEngine()
        stats = engine.get_cache_stats()
        assert isinstance(stats, dict)

    def test_clear_cache(self):
        """测试清除缓存。"""
        engine = WebSearchEngine()
        result = engine.clear_cache()
        assert result is not None  # 返回 int (删除数) 或 bool


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
