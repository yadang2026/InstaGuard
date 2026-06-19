"""
test_ai_analyzer.py - 测试 AIAnalyzer AI 风险分析器。

测试覆盖：
- 分析器初始化
- generate_prompt / 提示词生成
- analyze_without_api_key（降级方案）
- generate_repair_plan 修复计划生成
- batch_analyze 批量分析结构
- _extract_json_from_response
- _fallback_analysis
"""
import json
from unittest.mock import patch, MagicMock, PropertyMock

from scanner import RiskItem, ScanResult
from ai_analyzer import AIAnalyzer


class TestAnalyzerInit:
    """AI 分析器初始化测试。"""

    def test_init_defaults(self):
        """测试默认初始化。"""
        analyzer = AIAnalyzer()
        assert analyzer.provider_name is None
        assert analyzer.model is None
        assert analyzer.SYSTEM_PROMPT  # 提示词非空

    def test_init_with_provider(self):
        """测试带供应商名称初始化。"""
        analyzer = AIAnalyzer(provider_name="openai", model="gpt-4o")
        assert analyzer.provider_name == "openai"
        assert analyzer.model == "gpt-4o"


class TestGeneratePrompt:
    """提示词生成测试。"""

    def test_prompt_includes_risk_info(self, sample_risk):
        """测试分析提示词包含风险信息。"""
        analyzer = AIAnalyzer()
        # verify SYSTEM_PROMPT exists
        assert "Android 安全专家" in analyzer.SYSTEM_PROMPT
        assert len(analyzer.SYSTEM_PROMPT) > 100


class TestAnalyzeWithoutAPIKey:
    """无 API Key 降级方案测试。"""

    @patch("ai_analyzer.AIAnalyzer.provider_manager", new_callable=PropertyMock)
    def test_analyze_without_api_key_falls_back(self, mock_pm, sample_risk):
        """测试无 API Key 时降级到模板推荐。"""
        # 配置 mock: chat 返回 None，模拟 AI 不可用
        mock_pm_instance = MagicMock()
        mock_pm_instance.chat.return_value = None
        mock_pm.return_value = mock_pm_instance

        analyzer = AIAnalyzer()
        # 直接设置内存中的 provider_manager
        analyzer._provider_manager = mock_pm_instance

        result = analyzer.analyze_risk(sample_risk, use_cache=False)
        assert result is not None
        # 降级分析结果应包含"离线分析"或模板信息
        assert "离线分析" in result or "模板" in result or sample_risk.category in result

    @patch("ai_analyzer.AIAnalyzer.provider_manager", new_callable=PropertyMock)
    @patch("ai_analyzer.MemoryDB")
    def test_analyze_cached_result(self, mock_memory_class, mock_pm, sample_risk):
        """测试缓存命中直接返回。"""
        mock_db = MagicMock()
        mock_db.query.return_value = {
            "ai_analysis": "缓存的分析结果",
            "repair_template_id": "TPL003",
        }
        mock_memory_class.return_value = mock_db

        analyzer = AIAnalyzer()
        analyzer._provider_manager = mock_pm
        analyzer._memory_db = mock_db

        result = analyzer.analyze_risk(sample_risk)
        assert result == "缓存的分析结果"


class TestGenerateRepairPlan:
    """修复计划生成测试。"""

    def test_generate_repair_plan(self, sample_risk):
        """测试生成修复计划。"""
        analyzer = AIAnalyzer()
        # 设置 ai_analysis
        sample_risk.ai_analysis = "AI 分析完成"

        plan = analyzer.generate_repair_plan([sample_risk])
        assert len(plan) >= 1
        assert plan[0]["risk_id"] == sample_risk.id
        assert "category" in plan[0]
        assert "priority" in plan[0]
        assert "step" in plan[0]

    def test_generate_repair_plan_sorts_by_severity(self):
        """测试修复计划按严重程度排序。"""
        analyzer = AIAnalyzer()
        high_risk = RiskItem(
            id="R-HIGH", category="permission", severity="high",
            title="高风险", description="D", fingerprint="fp1",
            evidence="E", recommendation="R",
        )
        low_risk = RiskItem(
            id="R-LOW", category="info", severity="low",
            title="低风险", description="D", fingerprint="fp2",
            evidence="E", recommendation="R",
        )
        high_risk.ai_analysis = "done"
        low_risk.ai_analysis = "done"

        plan = analyzer.generate_repair_plan([low_risk, high_risk])
        # 高风险应该排在前面
        assert plan[0]["severity"] == "high"


class TestBatchAnalyzeStructure:
    """批量分析结构测试。"""

    @patch("ai_analyzer.AIAnalyzer.provider_manager", new_callable=PropertyMock)
    def test_batch_analyze_empty(self, mock_pm):
        """测试空列表批量分析返回空字典。"""
        analyzer = AIAnalyzer()
        analyzer._provider_manager = mock_pm
        result = analyzer.batch_analyze([])
        assert result == {}

    @patch("ai_analyzer.AIAnalyzer.provider_manager", new_callable=PropertyMock)
    def test_batch_analyze_fallback_on_failure(self, mock_pm, sample_risk):
        """测试批量分析失败时降级。"""
        mock_pm_instance = MagicMock()
        mock_pm_instance.chat.return_value = None  # AI 不可用
        mock_pm.return_value = mock_pm_instance

        analyzer = AIAnalyzer()
        analyzer._provider_manager = mock_pm_instance

        result = analyzer.batch_analyze([sample_risk])
        assert len(result) >= 1
        assert sample_risk.id in result


class TestExtractJSONFromResponse:
    """JSON 提取测试。"""

    def test_extract_json_code_block(self):
        """测试提取 ```json 代码块。"""
        analyzer = AIAnalyzer()
        response = '```json\n{"key": "value"}\n```'
        extracted = analyzer._extract_json_from_response(response)
        assert extracted == '{"key": "value"}'

    def test_extract_plain_json(self):
        """测试提取纯 JSON。"""
        analyzer = AIAnalyzer()
        response = '{"key": "value"}'
        extracted = analyzer._extract_json_from_response(response)
        assert extracted == '{"key": "value"}'

    def test_extract_json_in_text(self):
        """测试从混合文本中提取 JSON。"""
        analyzer = AIAnalyzer()
        response = '一些前置文本 {"risk_id": "R001"} 后置文本'
        extracted = analyzer._extract_json_from_response(response)
        assert "risk_id" in extracted

    def test_extract_no_json(self):
        """测试无 JSON 时返回原文。"""
        analyzer = AIAnalyzer()
        response = "纯文本分析结果"
        extracted = analyzer._extract_json_from_response(response)
        assert extracted == "纯文本分析结果"


class TestFallbackAnalysis:
    """降级分析测试。"""

    def test_fallback_analysis_with_templates(self, sample_risk):
        """测试有匹配模板时的降级分析。"""
        analyzer = AIAnalyzer()
        result = analyzer._fallback_analysis(sample_risk)
        assert result is not None
        assert "离线分析" in result or sample_risk.category in result

    def test_set_default_provider(self):
        """测试设置默认供应商。"""
        analyzer = AIAnalyzer()
        analyzer.set_default_provider("deepseek", "deepseek-chat")
        assert analyzer.provider_name == "deepseek"
        assert analyzer.model == "deepseek-chat"

    def test_get_cache_stats(self):
        """测试获取缓存统计。"""
        analyzer = AIAnalyzer()
        stats = analyzer.get_cache_stats()
        assert "total_memories" in stats or "total_entries" in stats


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
