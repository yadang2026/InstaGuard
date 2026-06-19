"""
InstaGuard - AI 风险分析器

调用 AI 对扫描发现的安全风险进行深度分析，
生成详细分析报告、风险等级调整建议和修复方案。
支持结果缓存到 MemoryDB（⚡ 记忆加速）。

Author: InstaGuard Team
Version: 1.0.0
"""

import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils import log, HashUtils, Config, safe_execute
from provider_manager import get_provider_manager, ProviderManager
from scanner import RiskItem, ScanResult, ScannerCallback
from memory import MemoryDB
from repair_templates import get_template_registry, RepairTemplate


# ─── AI 分析器 ────────────────────────────────────────────────────────────────

class AIAnalyzer:
    """
    AI 风险分析器。

    功能：
    1. 接收 RiskItem 列表，调用 AI 进行深度分析
    2. 为每个风险生成：详细分析（中文）、风险等级调整、修复方案
    3. 支持批量分析和单个分析
    4. 分析结果写入 RiskItem.ai_analysis 字段
    5. 调用 ProviderManager.chat() 进行 AI 调用
    6. 结果缓存到 MemoryDB（⚡ 记忆加速）
    """

    # AI 分析系统提示词
    SYSTEM_PROMPT = """你是一位资深的 Android 安全专家，精通 APK 逆向工程和安全加固。

你的任务是分析 Android APK 扫描发现的安全风险，并提供专业的中文分析报告。

对于每个安全风险，请按以下格式输出分析结果（JSON 格式）：

```json
{
  "risk_id": "风险ID",
  "risk_assessment": "风险评估（1-2段，详细说明该风险的技术原理、潜在危害和攻击场景）",
  "severity_adjustment": "adjusted_severity（如果原始严重程度需要调整，否则填 original_severity）",
  "adjustment_reason": "调整原因（如不需要调整则填'无'）",
  "repair_solution": "具体修复方案（分步骤说明，包含代码示例或配置修改细节）",
  "repair_template_id": "推荐的修复模板ID（如 TPL001），如没有匹配模板则填null",
  "precautions": "注意事项（1-2条关键提醒）",
  "related_cwes": ["CWE-xxx"],
  "confidence": 0.0-1.0
}
```

请保持分析专业、准确、实用。使用中文输出。"""

    def __init__(self, provider_name: Optional[str] = None, model: Optional[str] = None):
        """
        初始化 AI 分析器。

        Args:
            provider_name: 默认 AI 供应商名称（None 则自动选择）
            model: 默认模型（None 则使用供应商活跃模型）
        """
        self.provider_name = provider_name
        self.model = model
        self._provider_manager: Optional[ProviderManager] = None
        self._memory_db: Optional[MemoryDB] = None
        self._template_registry = get_template_registry()

    @property
    def provider_manager(self) -> ProviderManager:
        """懒加载 ProviderManager。"""
        if self._provider_manager is None:
            self._provider_manager = get_provider_manager()
        return self._provider_manager

    @property
    def memory_db(self) -> MemoryDB:
        """懒加载 MemoryDB。"""
        if self._memory_db is None:
            self._memory_db = MemoryDB()
        return self._memory_db

    # ─── 单个风险分析 ──────────────────────────────────────────────────────

    def analyze_risk(
        self,
        risk: RiskItem,
        provider_name: Optional[str] = None,
        model: Optional[str] = None,
        use_cache: bool = True,
    ) -> Optional[str]:
        """
        分析单个风险项。

        流程：
        1. 生成问题指纹
        2. 检查 MemoryDB 缓存（⚡ 记忆加速）
        3. 缓存命中直接返回，否则调用 AI
        4. 结果写入 risk.ai_analysis 并缓存

        Args:
            risk: 风险项
            provider_name: AI 供应商名称（None 使用默认）
            model: 模型名称（None 使用默认）
            use_cache: 是否使用缓存

        Returns:
            AI 分析结果文本，失败返回 None
        """
        # 确保风险有动态属性（RiskItem 是 dataclass，可能缺少某些字段）
        if not hasattr(risk, 'repair_template_id') or risk.repair_template_id is getattr(risk, 'repair_template_id', None) is None:
            setattr(risk, 'repair_template_id', None)
        if not hasattr(risk, 'repairable'):
            setattr(risk, 'repairable', True)

        # 1. 生成指纹
        fingerprint_text = f"{risk.category}|{risk.title}|{risk.description}"
        if not risk.fingerprint:
            risk.fingerprint = HashUtils.fingerprint(fingerprint_text)

        # 2. 检查缓存
        if use_cache:
            cached = self.memory_db.query(risk.fingerprint)
            if cached:
                log.info(f"⚡ 记忆命中: {risk.title} (指纹: {risk.fingerprint[:16]}...)")
                risk.ai_analysis = cached.get("ai_analysis", "")
                risk.repair_template_id = cached.get("repair_template_id") or cached.get("repair_solution", "")
                return risk.ai_analysis

        # 3. 搜索相似问题的缓存
        if use_cache:
            similar = self.memory_db.query_similar(risk.fingerprint, limit=3)
            if similar:
                best_match = similar[0]
                log.info(f"⚡ 相似记忆命中: {risk.title} → {best_match.get('title', 'N/A')}")
                risk.ai_analysis = best_match.get("ai_analysis", "")
                risk.repair_template_id = best_match.get("repair_template_id") or best_match.get("repair_solution", "")
                return risk.ai_analysis

        # 4. 构建 AI 请求消息
        matching_templates = self._template_registry.get_templates_for_category(risk.category)
        template_hints = ""
        if matching_templates:
            template_hints = "\n可用的修复模板：\n" + "\n".join(
                f"  - {t.template_id}: {t.title}" for t in matching_templates[:3]
            )

        # 获取推荐信息
        recommendation = getattr(risk, 'recommendation', risk.description)

        user_message = f"""请分析以下 Android APK 安全风险：

风险ID: {risk.id}
风险类别: {risk.category}
风险标题: {risk.title}
严重程度: {risk.severity}
风险描述: {risk.description}
证据: {risk.evidence or 'N/A'}
修复建议: {recommendation or 'N/A'}
{template_hints}

请给出详细分析结果（JSON 格式）。"""

        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]

        # 5. 调用 AI
        use_provider = provider_name or self.provider_name
        use_model = model or self.model

        log.info(f"📡 调用 AI 分析: {risk.title} (provider={use_provider}, model={use_model})")

        result = self.provider_manager.chat(
            messages=messages,
            provider_name=use_provider,
            model=use_model,
            temperature=0.3,
            max_tokens=2048,
        )

        if not result:
            log.error(f"AI 分析失败: {risk.title}")
            # 降级：使用模板推荐
            return self._fallback_analysis(risk)

        # 6. 提取 JSON 结果
        analysis_text = self._extract_json_from_response(result)
        if not analysis_text:
            log.warning(f"AI 返回格式异常，使用原始回复: {risk.title}")
            analysis_text = result

        # 7. 解析分析结果，提取修复模板 ID
        try:
            parsed = json.loads(analysis_text) if analysis_text.startswith("{") else None
            if parsed:
                risk.repair_template_id = parsed.get("repair_template_id")
        except json.JSONDecodeError:
            pass

        # 8. 存储结果
        risk.ai_analysis = analysis_text

        # 9. 写入缓存
        if use_cache:
            self.memory_db.store(
                fingerprint=risk.fingerprint,
                data={
                    "category": risk.category,
                    "severity": risk.severity,
                    "title": risk.title,
                    "description": risk.description,
                    "evidence": risk.evidence,
                    "ai_analysis": analysis_text,
                    "repair_solution": risk.repair_template_id or "",
                    "tags": [use_provider or "auto", use_model or "auto"],
                },
            )

        log.info(f"✅ AI 分析完成: {risk.title}")
        return risk.ai_analysis

    def _extract_json_from_response(self, response: str) -> str:
        """
        从 AI 回复中提取 JSON 内容。

        处理 AI 输出中可能包含的 markdown 代码块标记。

        Args:
            response: AI 原始回复

        Returns:
            提取的 JSON 字符串
        """
        # 尝试提取 ```json ... ``` 代码块
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            if end > start:
                return response[start:end].strip()
        if "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            if end > start:
                return response[start:end].strip()
        # 尝试找 { ... }
        brace_start = response.find("{")
        brace_end = response.rfind("}")
        if brace_start >= 0 and brace_end > brace_start:
            return response[brace_start:brace_end + 1].strip()
        return response.strip()

    def _fallback_analysis(self, risk: RiskItem) -> Optional[str]:
        """
        降级分析：AI 不可用时使用模板推荐。

        Args:
            risk: 风险项

        Returns:
            降级分析文本
        """
        templates = self._template_registry.get_templates_for_category(risk.category)
        if templates:
            best = templates[0]
            risk.repair_template_id = best.template_id
            fallback = (
                f"[离线分析] 风险类别: {risk.category}\n"
                f"推荐修复模板: {best.template_id} - {best.title}\n"
                f"修复方法: {best.description}\n"
                f"注意: 此分析未经过 AI 验证，建议待 AI 服务恢复后重新分析。"
            )
            risk.ai_analysis = fallback
            return fallback
        risk.ai_analysis = f"[离线分析] 风险类别: {risk.category}，暂无匹配模板，需人工评估。"
        return risk.ai_analysis

    # ─── 批量分析 ──────────────────────────────────────────────────────────

    def analyze_scan_result(
        self,
        result: ScanResult,
        callback: Optional[Callable] = None,
        provider_name: Optional[str] = None,
    ) -> ScanResult:
        """
        批量分析扫描结果中的所有风险。

        按严重程度排序（critical > high > medium > low），
        逐个调用 AI 分析，通过 callback 报告进度。

        Args:
            result: 扫描结果
            callback: 进度回调 callable(risk_index, total, risk, analysis)
            provider_name: AI 供应商名称

        Returns:
            分析完成后的 ScanResult（已原地修改）
        """
        if not result.risks:
            log.info("扫描结果无风险项，跳过分析")
            return result

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_risks = sorted(
            result.risks,
            key=lambda r: severity_order.get(r.severity.lower(), 99)
        )

        total = len(sorted_risks)
        log.info(f"开始批量 AI 分析: {total} 个风险项")

        success_count = 0
        for i, risk in enumerate(sorted_risks):
            log.info(f"分析进度: [{i+1}/{total}] {risk.title}")
            analysis = self.analyze_risk(risk, provider_name=provider_name)

            if analysis:
                success_count += 1

            if callback:
                try:
                    callback(i, total, risk, analysis)
                except Exception as e:
                    log.warning(f"回调执行异常: {e}")

            # 分析间隔（避免 API 限流）
            if i < total - 1:
                time.sleep(0.3)

        result.analyzed = True
        log.info(f"批量分析完成: {success_count}/{total} 成功")
        return result

    # ─── 生成修复计划 ──────────────────────────────────────────────────────

    def generate_repair_plan(self, risks: List[RiskItem]) -> List[Dict[str, Any]]:
        """
        根据 AI 分析结果生成修复计划。

        整合 AI 分析、模板推荐和经验库数据，生成可执行的修复计划。

        Args:
            risks: 风险项列表（已完成 AI 分析）

        Returns:
            修复计划列表，每项包含：
            {
                "risk_id": str,
                "title": str,
                "category": str,
                "severity": str,
                "ai_analysis": str,
                "template_id": str,
                "repair_action": str,
                "priority": int,
                "estimated_difficulty": str,
            }
        """
        plan: List[Dict[str, Any]] = []
        severity_priority = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}

        for risk in risks:
            # 确定修复模板
            template_id = getattr(risk, 'repair_template_id', None)
            template = None
            if template_id:
                template = self._template_registry.get_template(template_id)
            if not template:
                # 尝试类别匹配
                category_templates = self._template_registry.get_templates_for_category(risk.category)
                if category_templates:
                    template = category_templates[0]
                    template_id = template.template_id

            # 确定修复难度
            difficulty = "medium"
            if template:
                if template.risk_level == "low":
                    difficulty = "easy"
                elif template.risk_level == "high":
                    difficulty = "hard"

            plan_item = {
                "risk_id": risk.id,
                "title": risk.title,
                "category": risk.category,
                "severity": risk.severity,
                "ai_analysis": risk.ai_analysis,
                "template_id": template_id,
                "template_title": template.title if template else "无匹配模板",
                "repair_action": template.description if template else "需人工评估修复方案",
                "modify_target": template.modify_target if template else "manual",
                "priority": severity_priority.get(risk.severity.lower(), 99),
                "estimated_difficulty": difficulty,
                "repairable": getattr(risk, 'repairable', True) and template is not None,
            }
            plan.append(plan_item)

        # 按优先级排序
        plan.sort(key=lambda x: (x["priority"], 0 if x["repairable"] else 1))

        # 添加步骤号
        for i, item in enumerate(plan):
            item["step"] = i + 1

        log.info(f"修复计划已生成: {len(plan)} 项")
        return plan

    # ─── 批量分析（使用单次 AI 调用） ─────────────────────────────────────

    def batch_analyze(
        self,
        risks: List[RiskItem],
        provider_name: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        使用单次 AI 调用批量分析多个风险（节省 Token）。

        适用于风险数量较多（>5）且希望减少 API 调用次数的场景。

        Args:
            risks: 风险项列表
            provider_name: AI 供应商名称
            model: 模型名称

        Returns:
            {risk_id: analysis_text} 字典
        """
        if not risks:
            return {}

        # 构建批量分析请求
        risk_list_text = ""
        for i, risk in enumerate(risks):
            risk_list_text += (
                f"\n--- 风险 #{i+1} ---\n"
                f"ID: {risk.id}\n"
                f"类别: {risk.category}\n"
                f"标题: {risk.title}\n"
                f"严重程度: {risk.severity}\n"
                f"描述: {risk.description}\n"
            )

        batch_prompt = f"""请批量分析以下 {len(risks)} 个 Android APK 安全风险。

每个风险请输出独立 JSON 对象，所有结果放在一个 JSON 数组中：
```json
[
  {{"risk_id": "...", "risk_assessment": "...", "repair_solution": "...", "repair_template_id": "..."}},
  ...
]
```

风险列表：
{risk_list_text}"""

        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": batch_prompt},
        ]

        use_provider = provider_name or self.provider_name
        use_model = model or self.model

        log.info(f"📡 批量 AI 分析: {len(risks)} 个风险")

        result = self.provider_manager.chat(
            messages=messages,
            provider_name=use_provider,
            model=use_model,
            temperature=0.3,
            max_tokens=4096,
        )

        results: Dict[str, str] = {}

        if not result:
            log.error("批量 AI 分析失败")
            for risk in risks:
                results[risk.id] = self._fallback_analysis(risk) or ""
            return results

        # 解析批量结果
        try:
            json_text = self._extract_json_from_response(result)
            parsed_list = json.loads(json_text)
            if isinstance(parsed_list, list):
                for item in parsed_list:
                    risk_id = item.get("risk_id", "")
                    if risk_id:
                        analysis_text = json.dumps(item, ensure_ascii=False, indent=2)
                        results[risk_id] = analysis_text
                        # 更新对应 RiskItem
                        for risk in risks:
                            if risk.id == risk_id:
                                risk.ai_analysis = analysis_text
                                risk.repair_template_id = item.get("repair_template_id")
                                # 缓存
                                if not risk.fingerprint:
                                    risk.fingerprint = HashUtils.fingerprint(
                                        f"{risk.category}|{risk.title}|{risk.description}"
                                    )
                                self.memory_db.store(
                                    fingerprint=risk.fingerprint,
                                    data={
                                        "category": risk.category,
                                        "severity": risk.severity,
                                        "title": risk.title,
                                        "description": risk.description,
                                        "evidence": risk.evidence,
                                        "ai_analysis": analysis_text,
                                        "repair_solution": risk.repair_template_id or "",
                                        "tags": [use_provider or "auto", use_model or "auto"],
                                    },
                                )
                                break
        except (json.JSONDecodeError, TypeError) as e:
            log.warning(f"批量分析结果解析失败: {e}，回退为逐个分析")

        # 对未获得结果的风险，进行单独分析
        for risk in risks:
            if risk.id not in results:
                analysis = self.analyze_risk(risk, provider_name=provider_name)
                results[risk.id] = analysis or ""

        return results

    # ─── 工具方法 ──────────────────────────────────────────────────────────

    def get_cache_stats(self) -> Dict[str, Any]:
        """获取记忆缓存统计信息。"""
        return self.memory_db.get_stats()

    def clear_cache(self) -> bool:
        """清空记忆缓存。"""
        return self.memory_db.clear_all()

    def set_default_provider(self, provider_name: str, model: Optional[str] = None) -> None:
        """
        设置默认 AI 供应商和模型。

        Args:
            provider_name: 供应商名称
            model: 模型名称
        """
        self.provider_name = provider_name
        if model:
            self.model = model
        log.info(f"AI 分析器默认供应商: {provider_name}, 模型: {model or '自动'}")
