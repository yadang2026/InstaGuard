"""
InstaGuard - 智能记忆加速模块

SQLite 数据库存储 AI 分析结果与修复方案，为每个风险生成问题指纹。
扫描时优先查询本地记忆库，命中则返回缓存结果并标注"⚡记忆加速"。
支持相似问题匹配（模糊查询），相似度阈值可调。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import sqlite3
import json
import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from threading import Lock

from utils import (
    log, HashUtils, Config, safe_execute,
    MEMORY_DB_PATH, init_paths,
)


class MemoryDB:
    """
    智能记忆数据库。

    功能：
    - 精确指纹查询：O(1) 命中，直接返回缓存结果
    - 相似问题匹配：通过汉明距离计算相似度，复用相近问题的分析
    - 命中计数：统计每个问题的查询频次
    - 数据清理：自动清理过期/低质量记录
    - 验证标记：支持人工验证分析结果质量
    """

    # 默认相似度阈值（0.0 - 1.0，越高越严格）
    DEFAULT_SIMILARITY_THRESHOLD: float = 0.85

    def __init__(self, db_path: Optional[str] = None):
        """
        初始化记忆数据库。

        Args:
            db_path: 数据库文件路径，None 则使用全局 MEMORY_DB_PATH
        """
        self._db_path = db_path or MEMORY_DB_PATH
        self._lock = Lock()
        self._config = Config()
        self._ensure_db()

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接（每次新建，线程安全）。"""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-8000")  # 8MB 缓存
        return conn

    def _ensure_db(self) -> None:
        """确保数据库和表结构存在。"""
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS memories (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        fingerprint     TEXT    NOT NULL UNIQUE,
                        category        TEXT    NOT NULL DEFAULT '',
                        severity        TEXT    NOT NULL DEFAULT 'info',
                        title           TEXT    NOT NULL DEFAULT '',
                        description     TEXT    NOT NULL DEFAULT '',
                        evidence        TEXT    NOT NULL DEFAULT '',
                        ai_analysis     TEXT    DEFAULT NULL,
                        repair_solution TEXT    DEFAULT NULL,
                        evidence_pattern TEXT   NOT NULL DEFAULT '',
                        hit_count       INTEGER NOT NULL DEFAULT 0,
                        created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                        last_hit_at     TEXT    DEFAULT NULL,
                        verified        INTEGER NOT NULL DEFAULT 0,
                        tags            TEXT    DEFAULT '[]'
                    )
                """)

                # 创建索引
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_memories_fingerprint
                    ON memories(fingerprint)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_memories_category
                    ON memories(category)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_memories_severity
                    ON memories(severity)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_memories_hit_count
                    ON memories(hit_count DESC)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_memories_last_hit
                    ON memories(last_hit_at)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_memories_verified
                    ON memories(verified)
                """)

                conn.commit()
                log.info(f"记忆数据库已就绪: {self._db_path}")
            except Exception as e:
                log.error(f"创建记忆数据库失败: {e}")
                raise
            finally:
                conn.close()

    # ─── 查询方法 ──────────────────────────────────────────────────────────

    def query(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """
        精确指纹查询。

        Args:
            fingerprint: 问题的特征指纹（SHA256）

        Returns:
            命中返回记忆字典（含 ai_analysis, repair_solution 等），未命中返回 None
        """
        if not fingerprint:
            return None

        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM memories WHERE fingerprint = ?",
                    (fingerprint,)
                ).fetchone()

                if row:
                    # 更新命中计数和时间
                    conn.execute(
                        "UPDATE memories SET hit_count = hit_count + 1, "
                        "last_hit_at = datetime('now') WHERE fingerprint = ?",
                        (fingerprint,)
                    )
                    conn.commit()

                    result = dict(row)
                    result["_accelerated"] = True  # 标记为记忆加速
                    log.info(f"⚡记忆加速命中: {result.get('category')}/{result.get('title', '')[:30]}")
                    return result

                return None
            except Exception as e:
                log.error(f"记忆查询失败: {e}")
                return None
            finally:
                conn.close()

    def query_similar(
        self,
        fingerprint: str,
        threshold: Optional[float] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        相似问题模糊匹配查询。

        先按类别和严重度筛选候选集，再使用汉明距离计算相似度。
        适用于指纹不完全相同但问题本质相似的情况。

        Args:
            fingerprint: 问题的特征指纹
            threshold: 相似度阈值（0.0-1.0），None 则使用配置值
            limit: 最多返回条数

        Returns:
            相似记忆列表，按相似度降序排列
        """
        if not fingerprint:
            return []

        threshold = threshold or self._config.get_setting(
            "memory_similarity_threshold", self.DEFAULT_SIMILARITY_THRESHOLD
        )

        with self._lock:
            conn = self._get_conn()
            try:
                # 获取最近命中的候选记忆（减少计算量）
                candidates = conn.execute(
                    "SELECT * FROM memories ORDER BY last_hit_at DESC LIMIT 200"
                ).fetchall()

                scored: List[tuple] = []
                for row in candidates:
                    row_dict = dict(row)
                    stored_fp = row_dict.get("fingerprint", "")
                    if not stored_fp:
                        continue

                    sim = HashUtils.similarity(fingerprint, stored_fp)
                    if sim >= threshold:
                        scored.append((sim, row_dict))

                # 按相似度降序
                scored.sort(key=lambda x: x[0], reverse=True)

                # 更新命中计数
                for _, item in scored[:limit]:
                    conn.execute(
                        "UPDATE memories SET hit_count = hit_count + 1, "
                        "last_hit_at = datetime('now') WHERE id = ?",
                        (item["id"],)
                    )
                conn.commit()

                results = []
                for sim, item in scored[:limit]:
                    item["_similarity"] = round(sim, 4)
                    item["_accelerated"] = True
                    item["_similar_match"] = True
                    results.append(item)

                if results:
                    log.info(
                        f"记忆相似匹配: 找到 {len(results)} 条 (最高相似度: {results[0]['_similarity']})"
                    )

                return results
            except Exception as e:
                log.error(f"相似记忆查询失败: {e}")
                return []
            finally:
                conn.close()

    def query_by_category(
        self,
        category: str,
        severity: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        按类别和严重度查询记忆。

        Args:
            category: 风险类别（如 'permission', 'export'）
            severity: 可选严重度过滤
            limit: 最大返回数

        Returns:
            匹配的记忆列表
        """
        with self._lock:
            conn = self._get_conn()
            try:
                if severity:
                    rows = conn.execute(
                        "SELECT * FROM memories WHERE category = ? AND severity = ? "
                        "ORDER BY hit_count DESC LIMIT ?",
                        (category, severity, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM memories WHERE category = ? "
                        "ORDER BY hit_count DESC LIMIT ?",
                        (category, limit)
                    ).fetchall()
                return [dict(r) for r in rows]
            except Exception as e:
                log.error(f"类别查询失败: {e}")
                return []
            finally:
                conn.close()

    # ─── 存储方法 ──────────────────────────────────────────────────────────

    def store(
        self,
        fingerprint: str,
        data: Dict[str, Any],
        force_update: bool = False,
    ) -> bool:
        """
        存储分析结果到记忆库。

        Args:
            fingerprint: 特征指纹
            data: 包含以下字段的字典：
                - category: 风险类别
                - severity: 严重度
                - title: 标题
                - description: 描述
                - evidence: 证据
                - ai_analysis: AI 分析结果
                - repair_solution: 修复方案
                - evidence_pattern: 证据模式
                - tags: 标签列表 (optional)
            force_update: 是否强制覆盖已有记录

        Returns:
            是否存储成功
        """
        if not fingerprint:
            log.warning("存储失败: 指纹为空")
            return False

        with self._lock:
            conn = self._get_conn()
            try:
                # 检查是否已存在
                existing = conn.execute(
                    "SELECT id FROM memories WHERE fingerprint = ?",
                    (fingerprint,)
                ).fetchone()

                if existing and not force_update:
                    # 仅更新命中计数
                    conn.execute(
                        "UPDATE memories SET hit_count = hit_count + 1, "
                        "last_hit_at = datetime('now') WHERE fingerprint = ?",
                        (fingerprint,)
                    )
                    conn.commit()
                    log.debug(f"记忆已存在，更新命中: {fingerprint[:16]}...")
                    return True

                tags_json = json.dumps(data.get("tags", []), ensure_ascii=False)

                if existing:
                    # 更新记录
                    conn.execute("""
                        UPDATE memories SET
                            category = ?,
                            severity = ?,
                            title = ?,
                            description = ?,
                            evidence = ?,
                            ai_analysis = ?,
                            repair_solution = ?,
                            evidence_pattern = ?,
                            hit_count = hit_count + 1,
                            last_hit_at = datetime('now'),
                            verified = ?,
                            tags = ?
                        WHERE fingerprint = ?
                    """, (
                        data.get("category", ""),
                        data.get("severity", "info"),
                        data.get("title", ""),
                        data.get("description", ""),
                        data.get("evidence", ""),
                        data.get("ai_analysis"),
                        data.get("repair_solution"),
                        data.get("evidence_pattern", ""),
                        1 if data.get("verified") else 0,
                        tags_json,
                        fingerprint,
                    ))
                else:
                    # 插入新记录
                    conn.execute("""
                        INSERT INTO memories (
                            fingerprint, category, severity, title, description,
                            evidence, ai_analysis, repair_solution, evidence_pattern,
                            hit_count, created_at, last_hit_at, verified, tags
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'), ?, ?)
                    """, (
                        fingerprint,
                        data.get("category", ""),
                        data.get("severity", "info"),
                        data.get("title", ""),
                        data.get("description", ""),
                        data.get("evidence", ""),
                        data.get("ai_analysis"),
                        data.get("repair_solution"),
                        data.get("evidence_pattern", ""),
                        1 if data.get("verified") else 0,
                        tags_json,
                    ))

                conn.commit()
                action = "更新" if existing else "新增"
                log.info(f"记忆{action}: {data.get('category')}/{data.get('title', '')[:30]}")
                return True

            except sqlite3.IntegrityError as e:
                log.warning(f"记忆存储冲突: {e}")
                return False
            except Exception as e:
                log.error(f"记忆存储失败: {e}")
                return False
            finally:
                conn.close()

    def update_hit(self, fingerprint: str) -> bool:
        """
        更新命中计数。

        Args:
            fingerprint: 特征指纹

        Returns:
            是否更新成功
        """
        if not fingerprint:
            return False

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE memories SET hit_count = hit_count + 1, "
                    "last_hit_at = datetime('now') WHERE fingerprint = ?",
                    (fingerprint,)
                )
                conn.commit()
                return conn.total_changes > 0
            except Exception as e:
                log.error(f"更新命中计数失败: {e}")
                return False
            finally:
                conn.close()

    def verify(self, fingerprint: str, verified: bool = True) -> bool:
        """
        标记记忆为已验证/未验证。

        Args:
            fingerprint: 特征指纹
            verified: True=已验证，False=未验证

        Returns:
            是否更新成功
        """
        if not fingerprint:
            return False

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE memories SET verified = ? WHERE fingerprint = ?",
                    (1 if verified else 0, fingerprint)
                )
                conn.commit()
                return conn.total_changes > 0
            except Exception as e:
                log.error(f"标记验证状态失败: {e}")
                return False
            finally:
                conn.close()

    # ─── 记忆查询加速流程 ─────────────────────────────────────────────────

    def lookup(
        self,
        fingerprint: str,
        category: str = "",
        similar: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """
        智能查找：先精确匹配，再相似匹配。

        这是扫描时调用的主入口函数。

        Args:
            fingerprint: 特征指纹
            category: 风险类别（用于相似查询时优化候选人筛选）
            similar: 是否启用相似匹配

        Returns:
            最佳匹配的记忆，None 表示需 AI 分析
        """
        # 1. 精确匹配
        exact = self.query(fingerprint)
        if exact:
            return exact

        # 2. 相似匹配
        if similar:
            similar_results = self.query_similar(fingerprint)
            if similar_results:
                best = similar_results[0]
                log.info(
                    f"相似记忆匹配 (相似度={best.get('_similarity', 0):.2%}): "
                    f"{best.get('title', '')[:40]}"
                )
                return best

        return None

    # ─── 维护方法 ──────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """
        获取记忆数据库统计信息。

        Returns:
            统计字典，包含总数、分类分布、命中率、存储大小等
        """
        with self._lock:
            conn = self._get_conn()
            try:
                total = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
                verified = conn.execute(
                    "SELECT COUNT(*) FROM memories WHERE verified = 1"
                ).fetchone()[0]
                total_hits = conn.execute(
                    "SELECT COALESCE(SUM(hit_count), 0) FROM memories"
                ).fetchone()[0]
                avg_hits = conn.execute(
                    "SELECT COALESCE(AVG(hit_count), 0) FROM memories"
                ).fetchone()[0]

                # 分类统计
                categories = conn.execute("""
                    SELECT category, COUNT(*) as cnt, SUM(hit_count) as hits
                    FROM memories GROUP BY category ORDER BY cnt DESC
                """).fetchall()

                # 严重度分布
                severities = conn.execute("""
                    SELECT severity, COUNT(*) as cnt
                    FROM memories GROUP BY severity ORDER BY cnt DESC
                """).fetchall()

                # 最近活动
                recent = conn.execute("""
                    SELECT COUNT(*) FROM memories
                    WHERE last_hit_at > datetime('now', '-7 days')
                """).fetchone()[0]

                # 数据库文件大小
                db_size_mb = 0.0
                if os.path.exists(self._db_path):
                    db_size_mb = os.path.getsize(self._db_path) / (1024 * 1024)

                return {
                    "total_memories": total,
                    "verified_memories": verified,
                    "total_hits": total_hits,
                    "average_hits": round(avg_hits, 2),
                    "active_7days": recent,
                    "stale_rate": round(1.0 - (recent / max(total, 1)), 2),
                    "categories": {r["category"]: r["cnt"] for r in categories},
                    "severities": {r["severity"]: r["cnt"] for r in severities},
                    "db_size_mb": round(db_size_mb, 2),
                    "db_path": self._db_path,
                }
            except Exception as e:
                log.error(f"获取统计信息失败: {e}")
                return {"error": str(e)}
            finally:
                conn.close()

    def cleanup_old(self, days: int = 90) -> int:
        """
        清理过期和低质量记录。

        Args:
            days: 保留最近 N 天的记录，超过的删除

        Returns:
            清理的记录数
        """
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        with self._lock:
            conn = self._get_conn()
            try:
                # 删除超过 N 天未命中且命中次数低的记录
                result = conn.execute("""
                    DELETE FROM memories
                    WHERE (last_hit_at IS NULL OR last_hit_at < ?)
                    AND hit_count <= 1
                    AND verified = 0
                """, (cutoff,))

                deleted = result.rowcount
                conn.commit()

                # VACUUM 回收空间
                if deleted > 100:
                    conn.execute("VACUUM")

                if deleted > 0:
                    log.info(f"记忆清理: 删除 {deleted} 条过期/低质量记录")
                return deleted

            except Exception as e:
                log.error(f"记忆清理失败: {e}")
                return 0
            finally:
                conn.close()

    def optimize(self) -> None:
        """优化数据库性能。"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("PRAGMA optimize")
                conn.execute("PRAGMA analysis_limit=400")
                conn.execute("PRAGMA optimize")
                log.debug("记忆数据库已优化")
            except Exception as e:
                log.error(f"数据库优化失败: {e}")
            finally:
                conn.close()

    def export(self, output_path: Optional[str] = None) -> Optional[str]:
        """
        导出记忆库为 JSON 文件（用于备份或迁移）。

        Args:
            output_path: 输出文件路径，None 则自动生成

        Returns:
            输出文件路径，失败返回 None
        """
        if output_path is None:
            output_path = os.path.join(
                os.path.dirname(self._db_path),
                f"memory_export_{datetime.now():%Y%m%d_%H%M%S}.json"
            )

        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute("SELECT * FROM memories ORDER BY hit_count DESC").fetchall()
                data = [dict(r) for r in rows]

                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "export_time": datetime.now().isoformat(),
                        "total_records": len(data),
                        "memories": data,
                    }, f, indent=2, ensure_ascii=False)

                log.info(f"记忆库已导出: {output_path} ({len(data)} 条)")
                return output_path
            except Exception as e:
                log.error(f"记忆库导出失败: {e}")
                return None
            finally:
                conn.close()

    def import_from(self, input_path: str, merge: bool = True) -> int:
        """
        从 JSON 文件导入记忆库。

        Args:
            input_path: JSON 导入文件路径
            merge: True=合并模式（跳过重复），False=覆盖模式

        Returns:
            导入的记录数
        """
        if not os.path.exists(input_path):
            log.error(f"导入文件不存在: {input_path}")
            return 0

        try:
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            memories = data.get("memories", [])
            imported = 0

            for record in memories:
                fp = record.get("fingerprint", "")
                if not fp:
                    continue
                if self.store(fp, record, force_update=not merge):
                    imported += 1

            log.info(f"记忆库导入: {imported}/{len(memories)} 条")
            return imported
        except Exception as e:
            log.error(f"记忆库导入失败: {e}")
            return 0


# ─── 全局单例 ─────────────────────────────────────────────────────────────────

_global_memory_db: Optional[MemoryDB] = None


def get_memory_db(db_path: Optional[str] = None) -> MemoryDB:
    """
    获取全局 MemoryDB 单例。

    Args:
        db_path: 数据库路径（仅首次调用有效）

    Returns:
        MemoryDB 实例
    """
    global _global_memory_db
    if _global_memory_db is None:
        _global_memory_db = MemoryDB(db_path=db_path)
    return _global_memory_db
