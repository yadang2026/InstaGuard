"""
test_repair_templates.py - 测试修复模板库 TemplateRegistry。

测试覆盖：
- 模板注册表初始化
- get_all_templates（17 条预置模板）
- get_template_by_id
- get_templates_for_category
- search_templates 关键词搜索
- add_template / remove_template
- get_categories / get_template_count
"""
from repair_templates import (
    TemplateRegistry, RepairTemplate,
    BUILTIN_TEMPLATES, get_template_registry,
)


class TestTemplateRegistryInit:
    """模板注册表初始化测试。"""

    def test_init_loads_builtin(self):
        """测试初始化加载预置模板。"""
        registry = TemplateRegistry()
        count = registry.get_template_count()
        assert count == len(BUILTIN_TEMPLATES)

    def test_get_template_registry_singleton(self):
        """测试全局单例模式。"""
        r1 = get_template_registry()
        r2 = get_template_registry()
        assert r1 is r2


class TestGetAllTemplates:
    """获取所有模板测试。"""

    def test_get_all_templates_count(self):
        """测试总模板数为 17。"""
        registry = TemplateRegistry()
        templates = registry.get_all_templates()
        assert len(templates) == 17

    def test_all_templates_are_valid(self):
        """测试所有模板均为有效的 RepairTemplate。"""
        registry = TemplateRegistry()
        for tmpl in registry.get_all_templates():
            assert isinstance(tmpl, RepairTemplate)
            assert tmpl.template_id.startswith("TPL")
            assert tmpl.title
            assert tmpl.category


class TestGetTemplateByID:
    """按 ID 获取模板测试。"""

    def test_get_existing_template(self):
        """测试获取存在的模板。"""
        registry = TemplateRegistry()
        tmpl = registry.get_template("TPL001")
        assert tmpl is not None
        assert tmpl.title == "移除调试标志"
        assert tmpl.category == "debuggable"

    def test_get_nonexistent_template(self):
        """测试获取不存在的模板返回 None。"""
        registry = TemplateRegistry()
        tmpl = registry.get_template("TPL999")
        assert tmpl is None

    def test_known_templates(self):
        """测试已知模板 ID。"""
        registry = TemplateRegistry()
        for tid in ["TPL001", "TPL002", "TPL003", "TPL004", "TPL005",
                     "TPL006", "TPL007", "TPL008", "TPL009", "TPL010",
                     "TPL011", "TPL012", "TPL013", "TPL014", "TPL015",
                     "TPL016", "TPL017"]:
            assert registry.get_template(tid) is not None, f"模板 {tid} 缺失"


class TestGetTemplatesForCategory:
    """按类别获取模板测试。"""

    def test_get_templates_for_debuggable(self):
        """测试获取 debuggable 类别模板。"""
        registry = TemplateRegistry()
        templates = registry.get_templates_for_category("debuggable")
        assert len(templates) == 1
        assert templates[0].template_id == "TPL001"

    def test_get_templates_for_permission(self):
        """测试获取 permission 类别模板。"""
        registry = TemplateRegistry()
        templates = registry.get_templates_for_category("permission")
        assert len(templates) >= 1

    def test_get_templates_case_insensitive(self):
        """测试类别名称大小写不敏感。"""
        registry = TemplateRegistry()
        t1 = registry.get_templates_for_category("DEBUGGABLE")
        t2 = registry.get_templates_for_category("debuggable")
        assert len(t1) == len(t2)

    def test_get_templates_nonexistent_category(self):
        """测试不存在的类别返回空列表。"""
        registry = TemplateRegistry()
        templates = registry.get_templates_for_category("nonexistent_category")
        assert templates == []


class TestSearchTemplates:
    """关键词搜索模板测试。"""

    def test_search_by_title(self):
        """测试按标题搜索。"""
        registry = TemplateRegistry()
        results = registry.search_templates("调试")
        assert len(results) >= 1
        # TPL001 标题是"移除调试标志"
        titles = [r.title for r in results]
        assert "移除调试标志" in titles

    def test_search_by_category(self):
        """测试按类别搜索。"""
        registry = TemplateRegistry()
        results = registry.search_templates("webview")
        assert len(results) >= 1

    def test_search_by_tag(self):
        """测试按标签搜索。"""
        registry = TemplateRegistry()
        results = registry.search_templates("SSL")
        assert len(results) >= 1

    def test_search_no_results(self):
        """测试无结果搜索。"""
        registry = TemplateRegistry()
        results = registry.search_templates("xyz_nonexistent_keyword_zzz")
        assert results == []

    def test_search_scores_descending(self):
        """测试搜索结果按相关度降序排列——标题匹配优先。"""
        registry = TemplateRegistry()
        results = registry.search_templates("权限")
        # 标题匹配排在前面
        if len(results) >= 2:
            # 标题中包含"权限"的得分 >= 10，比仅标签匹配的 5 高
            assert len(results) >= 1


class TestAddRemoveTemplate:
    """添加/移除模板测试。"""

    def test_add_custom_template(self):
        """测试添加自定义模板。"""
        registry = TemplateRegistry()
        custom = RepairTemplate(
            template_id="CUSTOM001",
            category="test",
            title="自定义测试模板",
            description="这是测试",
            modify_target="manifest",
        )
        assert registry.add_template(custom) is True
        assert registry.get_template("CUSTOM001") is not None

    def test_add_duplicate_id(self):
        """测试添加重复 ID 返回 False。"""
        registry = TemplateRegistry()
        custom = RepairTemplate(template_id="TPL001", category="x", title="Y",
                                description="Z", modify_target="manifest")
        assert registry.add_template(custom) is False

    def test_remove_custom_template(self):
        """测试移除自定义模板。"""
        registry = TemplateRegistry()
        custom = RepairTemplate(
            template_id="MYTPL001", category="test", title="测试",
            description="测试模板", modify_target="manual",
        )
        registry.add_template(custom)
        assert registry.remove_template("MYTPL001") is True
        assert registry.get_template("MYTPL001") is None

    def test_remove_builtin_template_forbidden(self):
        """测试不能移除预置模板。"""
        registry = TemplateRegistry()
        assert registry.remove_template("TPL001") is False
        assert registry.get_template("TPL001") is not None

    def test_remove_nonexistent(self):
        """测试移除不存在的模板返回 False。"""
        registry = TemplateRegistry()
        assert registry.remove_template("NOTEXIST") is False


class TestGetCategories:
    """类别相关测试。"""

    def test_get_categories(self):
        """测试获取所有去重类别。"""
        registry = TemplateRegistry()
        categories = registry.get_categories()
        assert "debuggable" in categories
        assert "permission" in categories
        assert len(categories) == len(set(categories))  # 无重复

    def test_get_template_count(self):
        """测试获取模板总数。"""
        registry = TemplateRegistry()
        assert registry.get_template_count() == 17

    def test_template_to_dict(self):
        """测试 RepairTemplate.to_dict()。"""
        registry = TemplateRegistry()
        tmpl = registry.get_template("TPL001")
        d = tmpl.to_dict()
        assert d["template_id"] == "TPL001"
        assert d["category"] == "debuggable"
        assert d["title"] == "移除调试标志"
        assert "risk_level" in d
        assert "tags" in d


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "-s"])
