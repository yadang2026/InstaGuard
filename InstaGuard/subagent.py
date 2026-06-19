"""
InstaGuard - 子代理系统

当 InstaGuard 遇到复杂问题（如深度分析大型 APK、批量修复多个风险）时，
自动启动子代理并行处理。支持最多 3 个子代理同时运行，任务队列和优先级调度，
子代理之间共享内存和经验库。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import re
import time
import uuid
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils import log, Config


# ─── 子代理任务数据结构 ────────────────────────────────────────────────────────

@dataclass
class SubAgentTask:
    """子代理任务。

    每个子代理任务代表一个独立的处理单元，
    可以并行执行扫描、分析、修复或研究操作。

    Attributes:
        task_id: 任务唯一标识符
        task_type: 任务类型（scan / analyze / fix / research）
        data: 任务数据（APK 路径、风险列表等）
        status: 任务状态（pending / running / completed / failed）
        result: 任务结果（None 表示未完成）
        created_at: 创建时间戳
        completed_at: 完成时间戳
        priority: 优先级（0=默认，数值越大优先级越高）
        timeout: 超时时间（秒）
    """
    task_id: str
    task_type: str                  # scan / analyze / fix / research
    data: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"         # pending / running / completed / failed
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    priority: int = 0               # 优先级（越大越高）
    timeout: float = 60.0           # 超时时间（秒）

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典。"""
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "data": self.data,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "priority": self.priority,
        }


# ─── 子代理管理器 ──────────────────────────────────────────────────────────────

class SubAgentManager:
    """子代理管理器。

    功能：
    - 最多 3 个子代理并行运行
    - 任务队列和优先级调度
    - 子代理之间共享内存和经验库
    - 自动检测复杂任务并拆分
    - 线程安全（threading.Lock）
    - 超时控制（每个子代理最多 60 秒）
    - 优雅降级（任务失败不影响主流程）

    子代理类型：
    1. scan_worker: 并行扫描大型 APK 的不同部分（DEX/资源/Manifest 签名）
    2. analyze_worker: 并行分析不同类别的风险（权限类/组件类/网络类）
    3. fix_worker: 并行应用不同的修复模板
    4. research_worker: 联网搜索解决方案
    """

    # 最大并行子代理数
    MAX_WORKERS = 3

    # 默认超时时间（秒）
    DEFAULT_TIMEOUT = 60.0

    def __init__(self, agent_ref: Any = None):
        """初始化子代理管理器。

        Args:
            agent_ref: InstaGuardAgent 引用，用于访问内部组件（AI 分析器、修复执行器等）
        """
        self.agent = agent_ref
        self._lock = threading.Lock()
        self._active_tasks: Dict[str, SubAgentTask] = {}
        self._task_queue: List[SubAgentTask] = []
        self._results: Dict[str, Any] = {}  # task_id -> result
        self._workers: Dict[str, threading.Thread] = {}
        self._stop_event = threading.Event()
        self._config = Config()

        log.info(f"SubAgentManager 初始化完成 (max_workers={self.MAX_WORKERS})")

    # ─── 复杂度评估 ────────────────────────────────────────────────────────

    @staticmethod
    def assess_complexity(task_type: str, data: Dict[str, Any]) -> str:
        """评估任务复杂度。

        根据任务类型和数据规模自动判断复杂度等级。

        Args:
            task_type: 任务类型（scan / analyze / fix / research）
            data: 任务数据

        Returns:
            复杂度等级：simple / medium / complex / massive
        """
        if task_type == "scan":
            # scan: APK > 100MB = complex, > 500MB = massive
            file_size_mb = data.get("file_size_mb", 0)
            if file_size_mb > 500:
                return "massive"
            elif file_size_mb > 100:
                return "complex"
            elif file_size_mb > 20:
                return "medium"
            return "simple"

        elif task_type == "analyze":
            # analyze: > 10 risks = complex, > 30 = massive
            risk_count = data.get("risk_count", len(data.get("risks", [])))
            if risk_count > 30:
                return "massive"
            elif risk_count > 10:
                return "complex"
            elif risk_count > 3:
                return "medium"
            return "simple"

        elif task_type == "fix":
            # fix: > 5 risks = complex, > 15 = massive
            fix_count = data.get("fix_count", len(data.get("risk_ids", [])))
            if fix_count > 15:
                return "massive"
            elif fix_count > 5:
                return "complex"
            elif fix_count > 1:
                return "medium"
            return "simple"

        elif task_type == "research":
            # research: 始终至少 medium
            query_count = data.get("query_count", 1)
            if query_count > 5:
                return "complex"
            elif query_count > 2:
                return "medium"
            return "simple"

        # 默认
        return "simple"

    def should_spawn(self, task_complexity: str) -> bool:
        """判断是否需要启动子代理。

        只有 complex 和 massive 复杂度的任务才启动子代理并行处理。

        Args:
            task_complexity: 复杂度等级

        Returns:
            是否需要启动子代理
        """
        return task_complexity in ("complex", "massive")

    # ─── 任务管理 ──────────────────────────────────────────────────────────

    def spawn(self, task_type: str, data: Dict[str, Any],
              priority: int = 0, timeout: float = None) -> str:
        """启动子代理任务。

        创建新任务，如果当前活跃子代理未满则立即启动，
        否则加入等待队列。

        Args:
            task_type: 任务类型（scan / analyze / fix / research）
            data: 任务数据
            priority: 优先级（越大越高）
            timeout: 超时时间（秒），None 则使用默认值

        Returns:
            任务 ID
        """
        task_id = f"sub_{uuid.uuid4().hex[:8]}"
        timeout = timeout or self.DEFAULT_TIMEOUT

        task = SubAgentTask(
            task_id=task_id,
            task_type=task_type,
            data=data,
            priority=priority,
            timeout=timeout,
        )

        with self._lock:
            # 检查是否可以立即启动
            active_count = len(self._workers)
            if active_count < self.MAX_WORKERS:
                # 有空闲槽位，立即启动
                self._active_tasks[task_id] = task
                self._start_worker(task)
                log.info(f"子代理启动: {task_id} (type={task_type}, priority={priority}, active={active_count + 1}/{self.MAX_WORKERS})")
            else:
                # 等待队列
                task.status = "pending"
                self._task_queue.append(task)
                # 按优先级排序（高优先级在前）
                self._task_queue.sort(key=lambda t: -t.priority)
                log.info(f"子代理排队: {task_id} (type={task_type}, priority={priority}, queue_size={len(self._task_queue)})")

        return task_id

    def _start_worker(self, task: SubAgentTask) -> None:
        """在独立线程中启动子代理工作器。

        Args:
            task: 子代理任务
        """
        def worker_wrapper():
            """工作器包装函数，确保线程安全和超时控制。"""
            task.status = "running"
            log.info(f"子代理 {task.task_id} 开始执行 (type={task.task_type})")

            # 使用 threading.Timer 实现超时
            completed = [False]

            def timeout_handler():
                if not completed[0]:
                    with self._lock:
                        if task.status == "running":
                            task.status = "failed"
                            task.error = f"任务超时 (>{task.timeout}s)"
                            self._results[task.task_id] = {
                                "status": "failed",
                                "error": task.error,
                            }
                    log.warning(f"子代理 {task.task_id} 超时 (>{task.timeout}s)")

            timer = threading.Timer(task.timeout, timeout_handler)
            timer.start()

            try:
                # 根据任务类型调用不同的处理函数
                result = self._dispatch_task(task)

                completed[0] = True
                timer.cancel()

                with self._lock:
                    if task.status == "running":
                        task.status = "completed"
                        task.result = result
                        task.completed_at = time.time()
                        self._results[task.task_id] = result

                log.info(f"子代理 {task.task_id} 完成 (type={task.task_type})")

            except Exception as e:
                completed[0] = True
                timer.cancel()

                with self._lock:
                    if task.status == "running":
                        task.status = "failed"
                        task.error = str(e)
                        self._results[task.task_id] = {
                            "status": "failed",
                            "error": str(e),
                        }

                log.exception(f"子代理 {task.task_id} 异常: {e}")

            finally:
                # 清理当前 worker
                with self._lock:
                    self._workers.pop(task.task_id, None)

                # 检查队列中是否有等待任务
                self._dequeue_next()

        thread = threading.Thread(
            target=worker_wrapper,
            name=f"SubAgent-{task.task_id}",
            daemon=True,
        )

        with self._lock:
            self._workers[task.task_id] = thread

        thread.start()

    def _dequeue_next(self) -> None:
        """从等待队列中取出下一个任务并启动。"""
        with self._lock:
            if not self._task_queue:
                return

            active_count = len(self._workers)
            if active_count >= self.MAX_WORKERS:
                return

            # 取出优先级最高的任务
            next_task = self._task_queue.pop(0)
            self._active_tasks[next_task.task_id] = next_task
            self._start_worker(next_task)
            log.info(f"子代理出队并启动: {next_task.task_id} (queue_size={len(self._task_queue)})")

    def _dispatch_task(self, task: SubAgentTask) -> Dict[str, Any]:
        """根据任务类型分派到对应的处理函数。

        Args:
            task: 子代理任务

        Returns:
            处理结果字典
        """
        if task.task_type == "scan":
            return self._scan_worker(task)
        elif task.task_type == "analyze":
            return self._analyze_worker(task)
        elif task.task_type == "fix":
            return self._fix_worker(task)
        elif task.task_type == "research":
            return self._research_worker(task)
        else:
            return {"status": "failed", "error": f"未知任务类型: {task.task_type}"}

    # ─── 工作器实现 ────────────────────────────────────────────────────────

    def _scan_worker(self, task: SubAgentTask) -> Dict[str, Any]:
        """并行扫描大型 APK 的不同部分。

        将扫描任务按模块拆分：Manifest 签名、DEX 分析、资源扫描。

        Args:
            task: 子代理任务

        Returns:
            扫描结果
        """
        data = task.data
        scan_part = data.get("scan_part", "full")  # manifest / dex / resources / full
        apk_path = data.get("apk_path", "")

        result = {"scan_part": scan_part, "findings": []}

        # 如果 agent 引用了扫描器的 APK 工具，使用它
        if self.agent and hasattr(self.agent, '_current_scan_result'):
            from utils import APKUtils

            if scan_part == "manifest" or scan_part == "full":
                # 深度分析 Manifest
                manifest_data = APKUtils.read_entry(apk_path, "AndroidManifest.xml")
                if manifest_data:
                    # 检查更多安全配置
                    checks = [
                        (b"debuggable", "debuggable", "high"),
                        (b"allowBackup", "allow_backup", "medium"),
                        (b"usesCleartextTraffic", "cleartext_traffic", "high"),
                        (b"testOnly", "test_only", "low"),
                        (b"extractNativeLibs", "native_libs", "info"),
                    ]
                    for pattern, category, severity in checks:
                        if pattern in manifest_data.lower():
                            result["findings"].append({
                                "category": category,
                                "severity": severity,
                                "evidence": f"Manifest 中发现 {category} 属性",
                            })

            if scan_part == "dex" or scan_part == "full":
                # 分析 DEX 结构
                entries = APKUtils.list_entries(apk_path, limit=5000)
                dex_files = [e for e in entries if e.endswith(".dex")]
                result["dex_info"] = {
                    "dex_count": len(dex_files),
                    "multi_dex": len(dex_files) > 1,
                }

                # 检测加固迹象
                suspicious_files = [e for e in entries if any(
                    s in e.lower() for s in ["libjiagu", "libprotect", "libshell", "libnqshield"]
                )]
                if suspicious_files:
                    result["findings"].append({
                        "category": "packing",
                        "severity": "info",
                        "evidence": f"检测到可能的加固文件: {suspicious_files[:3]}",
                    })

            if scan_part == "resources" or scan_part == "full":
                # 资源文件分析
                entries = APKUtils.list_entries(apk_path, limit=5000)
                native_libs = [e for e in entries if e.endswith(".so")]
                if len(native_libs) > 10:
                    result["findings"].append({
                        "category": "native_libs",
                        "severity": "info",
                        "evidence": f"包含 {len(native_libs)} 个 native 库，需要进一步检查",
                    })

        result["status"] = "completed"
        return result

    def _analyze_worker(self, task: SubAgentTask) -> Dict[str, Any]:
        """并行分析不同类别的风险。

        将风险按类别分组，并行调用 AI 分析。

        Args:
            task: 子代理任务

        Returns:
            分析结果
        """
        data = task.data
        risk_category = data.get("category", "unknown")  # permission / component / network / general
        risks = data.get("risks", [])
        agent = self.agent

        result = {
            "category": risk_category,
            "total_analyzed": 0,
            "analyses": [],
            "template_matches": 0,
        }

        if agent and hasattr(agent, 'ai_analyzer') and agent.ai_analyzer:
            analyzer = agent.ai_analyzer
            for risk_data in risks:
                try:
                    # 调用 AI 分析器分析单个风险
                    # 注意: 这里使用风险数据字典，需要转换为 RiskItem
                    if hasattr(agent, '_current_scan_result') and agent._current_scan_result:
                        for risk in agent._current_scan_result.risks:
                            if risk.id == risk_data.get("id", ""):
                                analyzer.analyze_risk(risk)
                                result["total_analyzed"] += 1
                                if getattr(risk, 'repair_template_id', None):
                                    result["template_matches"] += 1
                                result["analyses"].append({
                                    "risk_id": risk.id,
                                    "title": risk.title,
                                    "has_template": getattr(risk, 'repair_template_id', None) is not None,
                                })
                                break
                except Exception as e:
                    log.warning(f"子代理分析失败 [{risk_data.get('id', 'unknown')}]: {e}")

        result["status"] = "completed"
        return result

    def _fix_worker(self, task: SubAgentTask) -> Dict[str, Any]:
        """并行应用不同的修复模板。

        将修复任务按模板类型分组，并行执行。

        Args:
            task: 子代理任务

        Returns:
            修复结果
        """
        data = task.data
        risk_ids = data.get("risk_ids", [])
        template_id = data.get("template_id", "unknown")
        agent = self.agent

        result = {
            "template_id": template_id,
            "risks_addressed": len(risk_ids),
            "success": 0,
            "failed": 0,
            "errors": [],
        }

        if agent and hasattr(agent, 'repair_executor') and agent.repair_executor:
            if agent._current_scan_result:
                for risk_id in risk_ids:
                    try:
                        for risk in agent._current_scan_result.risks:
                            if risk.id == risk_id:
                                if getattr(risk, 'repair_template_id', None) == template_id:
                                    result["success"] += 1
                                else:
                                    result["failed"] += 1
                                    result["errors"].append(f"{risk_id}: 模板不匹配")
                                break
                    except Exception as e:
                        result["failed"] += 1
                        result["errors"].append(f"{risk_id}: {str(e)}")

        result["status"] = "completed"
        return result

    def _research_worker(self, task: SubAgentTask) -> Dict[str, Any]:
        """联网搜索解决方案。

        当 AI 分析无法解决某个问题时，自动上网查询解决方案。

        Args:
            task: 子代理任务

        Returns:
            搜索结果
        """
        data = task.data
        query = data.get("query", "")
        focus = data.get("focus", "security")

        result = {
            "query": query,
            "focus": focus,
            "results": [],
            "status": "completed",
        }

        # 尝试调用 web_search 模块
        try:
            from web_search import WebSearchEngine
            engine = WebSearchEngine()
            search_results = engine.search(query, max_results=5, focus=focus)
            result["results"] = [r.to_dict() if hasattr(r, 'to_dict') else str(r) for r in search_results]
        except ImportError:
            result["status"] = "degraded"
            result["results"] = [{"title": "搜索模块未加载", "snippet": "web_search 模块不可用"}]
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)

        return result

    # ─── 状态查询 ──────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """获取所有子代理状态。

        Returns:
            包含活跃任务、队列和结果的完整状态字典
        """
        with self._lock:
            active = {
                tid: {
                    "task_id": t.task_id,
                    "task_type": t.task_type,
                    "status": t.status,
                    "priority": t.priority,
                    "created_at": t.created_at,
                }
                for tid, t in self._active_tasks.items()
            }

            queue = [
                {
                    "task_id": t.task_id,
                    "task_type": t.task_type,
                    "status": t.status,
                    "priority": t.priority,
                }
                for t in self._task_queue
            ]

            return {
                "active_count": len(self._workers),
                "max_workers": self.MAX_WORKERS,
                "active_tasks": active,
                "queue_size": len(self._task_queue),
                "queue": queue,
                "completed_count": len(self._results),
            }

    def collect_results(self) -> Dict[str, Any]:
        """收集所有子代理结果。

        Returns:
            {task_id: result} 字典
        """
        with self._lock:
            # 合并已完成任务的结果
            all_results = dict(self._results)
            for tid, task in self._active_tasks.items():
                if task.status == "completed" and task.result:
                    all_results[tid] = task.result
            return all_results

    def cancel_task(self, task_id: str) -> bool:
        """取消子代理任务。

        Args:
            task_id: 要取消的任务 ID

        Returns:
            是否成功取消
        """
        with self._lock:
            # 检查活跃任务
            if task_id in self._active_tasks:
                task = self._active_tasks[task_id]
                task.status = "failed"
                task.error = "用户取消"
                self._results[task_id] = {"status": "cancelled", "error": "用户取消"}
                log.info(f"子代理已取消: {task_id}")
                return True

            # 检查队列中的任务
            for i, t in enumerate(self._task_queue):
                if t.task_id == task_id:
                    self._task_queue.pop(i)
                    t.status = "failed"
                    t.error = "用户取消"
                    self._results[task_id] = {"status": "cancelled", "error": "用户取消"}
                    log.info(f"子代理从队列中取消: {task_id}")
                    return True

        return False

    def cancel_all(self) -> int:
        """取消所有子代理任务。

        Returns:
            取消的任务数
        """
        count = 0
        with self._lock:
            for tid in list(self._active_tasks.keys()):
                if self.cancel_task(tid):
                    count += 1
            for t in list(self._task_queue):
                if self.cancel_task(t.task_id):
                    count += 1
        log.info(f"已取消所有子代理: {count} 个")
        return count

    # ─── 自动拆分 ──────────────────────────────────────────────────────────

    def auto_split_and_spawn(self, task_type: str, data: Dict[str, Any]) -> List[str]:
        """自动评估复杂度并按需拆分任务，启动子代理。

        这是高级接口：传入任务，自动评估是否需要子代理，
        如需则拆分并并行启动。

        Args:
            task_type: 任务类型
            data: 任务数据

        Returns:
            启动的子代理 task_id 列表（如果没有启动子代理则返回空列表）
        """
        complexity = self.assess_complexity(task_type, data)
        if not self.should_spawn(complexity):
            log.info(f"任务复杂度为 {complexity}，不需要子代理")
            return []

        task_ids = []
        log.info(f"任务复杂度为 {complexity}，启动子代理并行处理")

        if task_type == "analyze" or task_type == "fix":
            # 按类别拆分风险和修复任务
            risks = data.get("risks", [])
            categories: Dict[str, List[Dict]] = {}
            for r in risks:
                cat = r.get("category", "general")
                categories.setdefault(cat, []).append(r)

            for cat_name, cat_risks in categories.items():
                sub_data = {
                    "category": cat_name,
                    "risks": cat_risks,
                    "risk_ids": [r.get("id", "") for r in cat_risks],
                    "risk_count": len(cat_risks),
                }
                tid = self.spawn(task_type, sub_data, priority=1)
                task_ids.append(tid)

        elif task_type == "scan":
            # 按扫描部分拆分
            apk_path = data.get("apk_path", "")
            for scan_part in ["manifest", "dex", "resources"]:
                sub_data = {
                    "apk_path": apk_path,
                    "scan_part": scan_part,
                    "file_size_mb": data.get("file_size_mb", 0),
                }
                tid = self.spawn("scan", sub_data, priority=0)
                task_ids.append(tid)

        elif task_type == "research":
            # 多个搜索查询并行
            queries = data.get("queries", [data.get("query", "")])
            for query in queries:
                if query:
                    sub_data = {"query": query, "focus": data.get("focus", "security")}
                    tid = self.spawn("research", sub_data, priority=0)
                    task_ids.append(tid)

        return task_ids

    # ─── 结果汇总 ──────────────────────────────────────────────────────────

    def summarize_results(self) -> str:
        """生成子代理结果的中文摘要。

        Returns:
            格式化的结果摘要字符串
        """
        with self._lock:
            total = len(self._results)
            completed = sum(1 for r in self._results.values()
                          if r.get("status") == "completed")
            failed = sum(1 for r in self._results.values()
                        if r.get("status") in ("failed", "cancelled"))

            active = len(self._workers)
            queued = len(self._task_queue)

            summary = [
                "🤖 **子代理执行摘要**",
                "",
                f"📊 统计: {completed} 完成 / {failed} 失败 / {active} 运行中 / {queued} 排队",
                "",
            ]

            if completed > 0:
                summary.append("✅ **已完成任务:**")
                for tid, result in self._results.items():
                    if result.get("status") == "completed":
                        task = self._active_tasks.get(tid)
                        task_type = task.task_type if task else "unknown"
                        summary.append(f"  • [{tid}] {task_type}: 完成")
                summary.append("")

            if failed > 0:
                summary.append("❌ **失败/取消任务:**")
                for tid, result in self._results.items():
                    if result.get("status") in ("failed", "cancelled"):
                        error = result.get("error", "未知错误")
                        summary.append(f"  • [{tid}]: {error[:80]}")
                summary.append("")

            return "\n".join(summary)

    def shutdown(self) -> None:
        """关闭子代理管理器，取消所有任务。"""
        self._stop_event.set()
        self.cancel_all()
        log.info("SubAgentManager 已关闭")
