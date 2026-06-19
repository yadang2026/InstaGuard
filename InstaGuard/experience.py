"""
InstaGuard - 自学习错误经验库

SQLite 数据库存储失败特征、原因分析（AI 生成）、解决策略与适用参数。
当扫描或修复出错时，自动提取错误特征、搜索历史经验、尝试安全方案，
成功后将策略存入经验库，实现自我进化。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from threading import Lock

from utils import (
    log, HashUtils, Config, capture_error_context, safe_execute,
    EXPERIENCE_DB_PATH, init_paths,
)


class ExperienceDB:
    """
    自学习错误经验数据库。

    功能：
    - 记录失败特征和上下文（特征哈希去重）
    - 搜索历史经验（精确 + 相似特征匹配）
    - AI 分析原因并生成解决策略
    - 记录策略成功/失败次数，优选方案
    - 生成经验洞见报告
    """

    # 默认相似度阈值
    DEFAULT_SIMILARITY_THRESHOLD: float = 0.75

    def __init__(self, db_path: Optional[str] = None):
        """
        初始化经验数据库。

        Args:
            db_path: 数据库文件路径，None 则使用全局 EXPERIENCE_DB_PATH
        """
        self._db_path = db_path or EXPERIENCE_DB_PATH
        self._lock = Lock()
        self._config = Config()
        self._ensure_db()

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接。"""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _ensure_db(self) -> None:
        """确保数据库和表结构存在。"""
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                # 主经验表
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS experiences (
                        id                INTEGER PRIMARY KEY AUTOINCREMENT,
                        feature_hash      TEXT    NOT NULL UNIQUE,
                        error_type        TEXT    NOT NULL DEFAULT '',
                        error_message     TEXT    NOT NULL DEFAULT '',
                        context_json      TEXT    NOT NULL DEFAULT '{}',
                        ai_analysis       TEXT    DEFAULT NULL,
                        solution_strategy TEXT    DEFAULT NULL,
                        solution_params   TEXT    NOT NULL DEFAULT '{}',
                        success_count     INTEGER NOT NULL DEFAULT 0,
                        fail_count        INTEGER NOT NULL DEFAULT 0,
                        total_attempts    INTEGER NOT NULL DEFAULT 0,
                        last_success_at   TEXT    DEFAULT NULL,
                        last_attempt_at   TEXT    DEFAULT NULL,
                        created_at        TEXT    NOT NULL DEFAULT (datetime('now')),
                        tags              TEXT    DEFAULT '[]',
                        confidence        REAL   NOT NULL DEFAULT 0.0
                    )
                """)

                # 策略尝试历史表
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS attempt_history (
                        id                INTEGER PRIMARY KEY AUTOINCREMENT,
                        experience_id     INTEGER NOT NULL,
                        strategy_used     TEXT    NOT NULL DEFAULT '',
                        params_used       TEXT    NOT NULL DEFAULT '{}',
                        success           INTEGER NOT NULL DEFAULT 0,
                        error_detail      TEXT    DEFAULT NULL,
                        duration_ms       INTEGER NOT NULL DEFAULT 0,
                        attempted_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                        FOREIGN KEY (experience_id) REFERENCES experiences(id) ON DELETE CASCADE
                    )
                """)

                # 创建索引
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_experiences_feature_hash
                    ON experiences(feature_hash)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_experiences_error_type
                    ON experiences(error_type)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_experiences_success_rate
                    ON experiences(success_count DESC, fail_count ASC)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_experiences_confidence
                    ON experiences(confidence DESC)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_experiences_last_attempt
                    ON experiences(last_attempt_at)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_attempt_history_experience
                    ON attempt_history(experience_id)
                """)

                conn.commit()
                log.info(f"经验数据库已就绪: {self._db_path}")
            except Exception as e:
                log.error(f"创建经验数据库失败: {e}")
                raise
            finally:
                conn.close()

    # ─── 搜索方法 ──────────────────────────────────────────────────────────

    def search(self, feature_hash: str) -> Optional[Dict[str, Any]]:
        """
        按特征哈希精确搜索经验。

        Args:
            feature_hash: 错误特征哈希

        Returns:
            经验记录字典，未找到返回 None
        """
        if not feature_hash:
            return None

        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM experiences WHERE feature_hash = ?",
                    (feature_hash,)
                ).fetchone()

                if row:
                    result = dict(row)
                    # 计算成功率
                    total = result["success_count"] + result["fail_count"]
                    result["_success_rate"] = round(
                        result["success_count"] / max(total, 1), 3
                    )
                    log.info(f"经验命中: {result['error_type']} (成功率={result['_success_rate']:.0%})")
                    return result

                return None
            except Exception as e:
                log.error(f"经验搜索失败: {e}")
                return None
            finally:
                conn.close()

    def search_similar(
        self,
        features: Dict[str, Any],
        threshold: Optional[float] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        按特征字典相似搜索经验。

        通过 HashUtils.feature_hash 生成特征哈希后，
        与库中记录进行汉明距离相似度计算。

        Args:
            features: 错误特征字典（如 {"error_type": "ParseError", "apk_size": 50000000}）
            threshold: 相似度阈值，None 使用默认值
            limit: 最多返回条数

        Returns:
            相似经验列表，按成功率×相似度降序排列
        """
        if not features:
            return []

        threshold = threshold or self._config.get_setting(
            "experience_similarity_threshold", self.DEFAULT_SIMILARITY_THRESHOLD
        )

        target_hash = HashUtils.feature_hash(features)

        with self._lock:
            conn = self._get_conn()
            try:
                # 优先按 error_type 筛选候选
                error_type = features.get("error_type", "")
                if error_type:
                    candidates = conn.execute(
                        "SELECT * FROM experiences WHERE error_type = ? "
                        "ORDER BY success_count DESC LIMIT 200",
                        (error_type,)
                    ).fetchall()
                else:
                    candidates = conn.execute(
                        "SELECT * FROM experiences "
                        "ORDER BY success_count DESC LIMIT 200"
                    ).fetchall()

                scored: List[Tuple[float, float, Dict]] = []
                for row in candidates:
                    row_dict = dict(row)
                    stored_hash = row_dict.get("feature_hash", "")
                    if not stored_hash:
                        continue

                    # 特征哈希相似度
                    hash_sim = HashUtils.similarity(target_hash, stored_hash)

                    # 额外：上下文字段相似度（简单关键词重叠）
                    context_sim = 1.0
                    if features and row_dict.get("context_json"):
                        try:
                            stored_ctx = json.loads(row_dict["context_json"])
                            context_sim = self._context_similarity(features, stored_ctx)
                        except Exception:
                            pass

                    # 综合相似度：哈希相似度 * 0.7 + 上下文相似度 * 0.3
                    combined_sim = hash_sim * 0.7 + context_sim * 0.3

                    if combined_sim >= threshold:
                        # 计算成功率
                        total = row_dict["success_count"] + row_dict["fail_count"]
                        success_rate = row_dict["success_count"] / max(total, 1)
                        scored.append((combined_sim, success_rate, row_dict))

                # 按综合得分排序：成功率 × 相似度
                scored.sort(key=lambda x: x[1] * x[0], reverse=True)

                results = []
                for sim, rate, item in scored[:limit]:
                    item["_similarity"] = round(sim, 4)
                    item["_success_rate"] = round(rate, 3)
                    results.append(item)

                if results:
                    log.info(
                        f"经验相似匹配: 找到 {len(results)} 条 "
                        f"(最高相似度={results[0]['_similarity']:.2%}, "
                        f"成功率={results[0]['_success_rate']:.0%})"
                    )

                return results
            except Exception as e:
                log.error(f"相似经验搜索失败: {e}")
                return []
            finally:
                conn.close()

    def _context_similarity(self, ctx1: Dict[str, Any], ctx2: Dict[str, Any]) -> float:
        """计算两个上下文字典的简单语义相似度。"""
        # 提取关键词集合
        def extract_keywords(d: Dict[str, Any]) -> set:
            keywords = set()
            for k, v in d.items():
                keywords.add(k.lower())
                if isinstance(v, str):
                    keywords.add(v.lower()[:50])
                elif isinstance(v, (int, float)):
                    keywords.add(str(v)[:10])
            return keywords

        k1 = extract_keywords(ctx1)
        k2 = extract_keywords(ctx2)

        if not k1 or not k2:
            return 1.0 if k1 == k2 else 0.0

        intersection = len(k1 & k2)
        union = len(k1 | k2)
        return intersection / union if union > 0 else 0.0

    def search_by_type(
        self,
        error_type: str,
        min_success_rate: float = 0.0,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        按错误类型搜索经验。

        Args:
            error_type: 错误类型（如 'ParseError', 'TimeoutError'）
            min_success_rate: 最低成功率过滤
            limit: 最大返回数

        Returns:
            匹配的经验列表
        """
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute("""
                    SELECT * FROM experiences
                    WHERE error_type = ?
                    ORDER BY success_count DESC, fail_count ASC
                    LIMIT ?
                """, (error_type, limit)).fetchall()

                results = []
                for row in rows:
                    item = dict(row)
                    total = item["success_count"] + item["fail_count"]
                    rate = item["success_count"] / max(total, 1)
                    if rate >= min_success_rate:
                        item["_success_rate"] = round(rate, 3)
                        results.append(item)

                return results
            except Exception as e:
                log.error(f"按类型搜索失败: {e}")
                return []
            finally:
                conn.close()

    # ─── 记录方法 ──────────────────────────────────────────────────────────

    @safe_execute(default_return=False)
    def record_failure(
        self,
        error_context: Dict[str, Any],
        ai_analysis: Optional[str] = None,
    ) -> Optional[str]:
        """
        记录失败经验。

        自动提取错误特征、生成特征哈希、存储到经验库。
        如果相同特征已存在，更新计数和最后尝试时间。

        Args:
            error_context: 错误上下文字典，至少包含:
                - exception_type (或 error_type): 异常类型
                - message (或 error_message): 错误消息
                - 可选: traceback, context, apk_info, operation 等
            ai_analysis: AI 对错误原因的分析（可选）

        Returns:
            特征哈希，或 None（记录失败时）
        """
        if not error_context:
            log.warning("记录失败: 错误上下文为空")
            return None

        # 提取核心特征
        error_type = error_context.get("exception_type") \
                  or error_context.get("error_type", "UnknownError")
        error_message = error_context.get("message") \
                      or error_context.get("error_message", "")
        context_data = error_context.get("context", {})

        # 构建特征字典
        features = {
            "error_type": error_type,
            "error_message_short": error_message[:100] if error_message else "",
            "context_keys": sorted(context_data.keys()) if isinstance(context_data, dict) else [],
        }

        # 添加上下文中的关键指标
        if isinstance(context_data, dict):
            for key in ["apk_path", "apk_size", "operation", "module", "function"]:
                if key in context_data:
                    features[key] = str(context_data[key])[:50]

        # 生成特征哈希
        feature_hash = HashUtils.feature_hash(features)
        context_json = json.dumps(error_context, ensure_ascii=False, default=str)

        with self._lock:
            conn = self._get_conn()
            try:
                existing = conn.execute(
                    "SELECT id, fail_count, success_count FROM experiences WHERE feature_hash = ?",
                    (feature_hash,)
                ).fetchone()

                if existing:
                    conn.execute("""
                        UPDATE experiences SET
                            fail_count = fail_count + 1,
                            total_attempts = total_attempts + 1,
                            error_message = ?,
                            context_json = ?,
                            ai_analysis = COALESCE(?, ai_analysis),
                            last_attempt_at = datetime('now'),
                            confidence = ROUND(
                                CAST(success_count AS REAL) / 
                                MAX(CAST(success_count + fail_count + 1 AS REAL), 1), 3
                            )
                        WHERE feature_hash = ?
                    """, (
                        error_message[:500],
                        context_json,
                        ai_analysis,
                        feature_hash,
                    ))

                    # 记录尝试历史
                    conn.execute("""
                        INSERT INTO attempt_history (experience_id, strategy_used, success)
                        VALUES (?, 'no_strategy', 0)
                    """, (existing["id"],))

                    conn.commit()
                    log.info(
                        f"经验记录(更新): {error_type} "
                        f"(失败{existing['fail_count']+1}次, "
                        f"成功{existing['success_count']}次)"
                    )
                else:
                    conn.execute("""
                        INSERT INTO experiences (
                            feature_hash, error_type, error_message,
                            context_json, ai_analysis,
                            fail_count, success_count, total_attempts,
                            last_attempt_at, confidence
                        ) VALUES (?, ?, ?, ?, ?, 1, 0, 1, datetime('now'), 0.0)
                    """, (
                        feature_hash,
                        error_type,
                        error_message[:500],
                        context_json,
                        ai_analysis,
                    ))

                    exp_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

                    conn.execute("""
                        INSERT INTO attempt_history (experience_id, strategy_used, success)
                        VALUES (?, 'no_strategy', 0)
                    """, (exp_id,))

                    conn.commit()
                    log.info(f"经验记录(新建): {error_type} (hash={feature_hash})")

                return feature_hash

            except sqlite3.IntegrityError:
                log.debug(f"经验特征哈希冲突: {feature_hash}")
                return feature_hash
            except Exception as e:
                log.error(f"经验记录失败: {e}")
                return None
            finally:
                conn.close()

    @safe_execute(default_return=False)
    def record_success(
        self,
        feature_hash: str,
        strategy: str,
        params: Optional[Dict[str, Any]] = None,
        duration_ms: int = 0,
    ) -> bool:
        """
        记录策略成功。

        当某个解决策略成功解决问题后调用，更新经验库中的成功计数。

        Args:
            feature_hash: 错误特征哈希
            strategy: 使用的解决策略名称
            params: 策略参数
            duration_ms: 策略执行耗时（毫秒）

        Returns:
            是否记录成功
        """
        if not feature_hash or not strategy:
            return False

        params_json = json.dumps(params or {}, ensure_ascii=False)

        with self._lock:
            conn = self._get_conn()
            try:
                result = conn.execute("""
                    UPDATE experiences SET
                        success_count = success_count + 1,
                        total_attempts = total_attempts + 1,
                        solution_strategy = COALESCE(?, solution_strategy),
                        solution_params = ?,
                        last_success_at = datetime('now'),
                        last_attempt_at = datetime('now'),
                        confidence = ROUND(
                            CAST(success_count + 1 AS REAL) / 
                            MAX(CAST(success_count + fail_count + 1 AS REAL), 1), 3
                        )
                    WHERE feature_hash = ?
                """, (
                    strategy,
                    params_json,
                    feature_hash,
                ))

                if result.rowcount == 0:
                    log.warning(f"记录成功失败: 未找到特征哈希 {feature_hash}")
                    return False

                # 获取 experience_id
                exp = conn.execute(
                    "SELECT id FROM experiences WHERE feature_hash = ?",
                    (feature_hash,)
                ).fetchone()

                if exp:
                    conn.execute("""
                        INSERT INTO attempt_history (
                            experience_id, strategy_used, params_used,
                            success, duration_ms
                        ) VALUES (?, ?, ?, 1, ?)
                    """, (exp["id"], strategy, params_json, duration_ms))

                conn.commit()

                log.info(f"经验成功记录: {strategy} (hash={feature_hash})")
                return True

            except Exception as e:
                log.error(f"记录成功失败: {e}")
                return False
            finally:
                conn.close()

    # ─── 智能方案推荐 ─────────────────────────────────────────────────────

    def get_best_strategy(self, feature_hash: str) -> Optional[Dict[str, Any]]:
        """
        获取指定特征的最佳解决策略。

        Args:
            feature_hash: 错误特征哈希

        Returns:
            策略信息字典 {strategy, params, success_rate, total_attempts}，未找到返回 None
        """
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT solution_strategy, solution_params, success_count, "
                    "fail_count, total_attempts, confidence "
                    "FROM experiences WHERE feature_hash = ? AND solution_strategy IS NOT NULL",
                    (feature_hash,)
                ).fetchone()

                if not row:
                    return None

                total = row["success_count"] + row["fail_count"]
                rate = row["success_count"] / max(total, 1)

                params = {}
                if row["solution_params"]:
                    try:
                        params = json.loads(row["solution_params"])
                    except json.JSONDecodeError:
                        pass

                return {
                    "strategy": row["solution_strategy"],
                    "params": params,
                    "success_rate": round(rate, 3),
                    "success_count": row["success_count"],
                    "fail_count": row["fail_count"],
                    "total_attempts": row["total_attempts"],
                    "confidence": round(row["confidence"], 3),
                }
            except Exception as e:
                log.error(f"获取最佳策略失败: {e}")
                return None
            finally:
                conn.close()

    def recommend_strategies(
        self,
        features: Dict[str, Any],
        limit: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        根据错误特征推荐解决方案。

        综合精确匹配和相似匹配，返回按成功率排序的策略列表。

        Args:
            features: 错误特征字典
            limit: 最多返回策略数

        Returns:
            推荐策略列表 [{strategy, params, success_rate, similarity, source}, ...]
        """
        recommendations = []

        # 1. 精确匹配
        feature_hash = HashUtils.feature_hash(features)
        best = self.get_best_strategy(feature_hash)
        if best:
            best["similarity"] = 1.0
            best["source"] = "exact_match"
            recommendations.append(best)

        # 2. 相似匹配
        similar = self.search_similar(features, limit=limit)
        for item in similar:
            if item.get("solution_strategy"):
                rec = {
                    "strategy": item["solution_strategy"],
                    "params": {},
                    "success_rate": item.get("_success_rate", 0),
                    "similarity": item.get("_similarity", 0),
                    "source": f"similar_match ({item.get('error_type', '')})",
                    "success_count": item.get("success_count", 0),
                    "fail_count": item.get("fail_count", 0),
                    "ai_analysis": item.get("ai_analysis"),
                }
                if item.get("solution_params"):
                    try:
                        rec["params"] = json.loads(item["solution_params"])
                    except json.JSONDecodeError:
                        pass
                recommendations.append(rec)

        # 去重：按策略名去重，保留相似度最高的
        seen = set()
        unique = []
        for rec in sorted(recommendations, key=lambda x: x["similarity"], reverse=True):
            key = rec["strategy"]
            if key not in seen:
                seen.add(key)
                unique.append(rec)

        if unique:
            log.info(f"经验推荐: {len(unique)} 条策略 (最佳: {unique[0]['strategy']}, "
                     f"成功率={unique[0]['success_rate']:.0%})")

        return unique[:limit]

    # ─── 统计与洞见 ─────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """
        获取经验库统计信息。

        Returns:
            统计字典
        """
        with self._lock:
            conn = self._get_conn()
            try:
                total = conn.execute("SELECT COUNT(*) FROM experiences").fetchone()[0]
                total_attempts = conn.execute(
                    "SELECT COALESCE(SUM(total_attempts), 0) FROM experiences"
                ).fetchone()[0]
                total_success = conn.execute(
                    "SELECT COALESCE(SUM(success_count), 0) FROM experiences"
                ).fetchone()[0]
                total_fail = conn.execute(
                    "SELECT COALESCE(SUM(fail_count), 0) FROM experiences"
                ).fetchone()[0]

                overall_rate = total_success / max(total_success + total_fail, 1)

                # 有解决方案的比例
                with_solution = conn.execute(
                    "SELECT COUNT(*) FROM experiences "
                    "WHERE solution_strategy IS NOT NULL AND solution_strategy != ''"
                ).fetchone()[0]

                # 错误类型分布
                error_types = conn.execute("""
                    SELECT error_type, COUNT(*) as cnt,
                           SUM(success_count) as succ, SUM(fail_count) as fail
                    FROM experiences
                    GROUP BY error_type ORDER BY cnt DESC
                    LIMIT 10
                """).fetchall()

                # 成功率分布
                high_confidence = conn.execute(
                    "SELECT COUNT(*) FROM experiences WHERE confidence >= 0.7"
                ).fetchone()[0]

                # 最近活动
                recent_exp = conn.execute(
                    "SELECT COUNT(*) FROM experiences "
                    "WHERE last_attempt_at > datetime('now', '-7 days')"
                ).fetchone()[0]

                # 数据库大小
                db_size_mb = 0.0
                if os.path.exists(self._db_path):
                    db_size_mb = os.path.getsize(self._db_path) / (1024 * 1024)

                return {
                    "total_experiences": total,
                    "total_attempts": total_attempts,
                    "total_success": total_success,
                    "total_failures": total_fail,
                    "overall_success_rate": round(overall_rate, 3),
                    "experiences_with_solution": with_solution,
                    "solution_coverage": round(with_solution / max(total, 1), 3),
                    "high_confidence_experiences": high_confidence,
                    "active_7days": recent_exp,
                    "top_error_types": [
                        {
                            "type": r["error_type"],
                            "count": r["cnt"],
                            "success_rate": round(
                                r["succ"] / max(r["succ"] + r["fail"], 1), 3
                            ),
                        }
                        for r in error_types
                    ],
                    "db_size_mb": round(db_size_mb, 2),
                    "db_path": self._db_path,
                }
            except Exception as e:
                log.error(f"获取统计失败: {e}")
                return {"error": str(e)}
            finally:
                conn.close()

    def get_insights(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        获取经验洞见 — 最有价值的经验总结。

        返回高置信度、经过多次验证的成功经验。

        Args:
            limit: 最多返回条数

        Returns:
            洞见列表
        """
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute("""
                    SELECT * FROM experiences
                    WHERE solution_strategy IS NOT NULL
                      AND solution_strategy != ''
                      AND success_count >= 1
                      AND confidence >= 0.5
                    ORDER BY confidence DESC, success_count DESC
                    LIMIT ?
                """, (limit,)).fetchall()

                insights = []
                for row in rows:
                    item = dict(row)
                    total = item["success_count"] + item["fail_count"]
                    rate = item["success_count"] / max(total, 1)

                    insight = {
                        "error_type": item["error_type"],
                        "pattern": item["error_message"][:120] if item["error_message"] else "",
                        "strategy": item["solution_strategy"],
                        "success_rate": round(rate, 3),
                        "success_count": item["success_count"],
                        "fail_count": item["fail_count"],
                        "confidence": round(item["confidence"], 3),
                        "ai_analysis": item.get("ai_analysis"),
                        "last_success_at": item.get("last_success_at"),
                    }

                    if item["solution_params"]:
                        try:
                            insight["params"] = json.loads(item["solution_params"])
                        except json.JSONDecodeError:
                            insight["params"] = {}

                    insights.append(insight)

                return insights
            except Exception as e:
                log.error(f"获取经验洞见失败: {e}")
                return []
            finally:
                conn.close()

    # ─── 维护方法 ──────────────────────────────────────────────────────────

    def cleanup_old(self, days: int = 180) -> int:
        """
        清理过期和低质量经验记录。

        Args:
            days: 保留最近 N 天的记录

        Returns:
            清理的记录数
        """
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        with self._lock:
            conn = self._get_conn()
            try:
                # 删除长期未使用且成功率低的记录
                result = conn.execute("""
                    DELETE FROM experiences
                    WHERE (last_attempt_at IS NULL OR last_attempt_at < ?)
                    AND total_attempts <= 2
                    AND confidence < 0.3
                    AND solution_strategy IS NULL
                """, (cutoff,))

                deleted = result.rowcount
                conn.commit()

                if deleted > 50:
                    conn.execute("VACUUM")

                if deleted > 0:
                    log.info(f"经验清理: 删除 {deleted} 条低质量记录")
                return deleted

            except Exception as e:
                log.error(f"经验清理失败: {e}")
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
                log.debug("经验数据库已优化")
            except Exception as e:
                log.error(f"数据库优化失败: {e}")
            finally:
                conn.close()

    def export(self, output_path: Optional[str] = None) -> Optional[str]:
        """
        导出经验库为 JSON 文件。

        Args:
            output_path: 输出文件路径

        Returns:
            输出文件路径
        """
        if output_path is None:
            output_path = os.path.join(
                os.path.dirname(self._db_path),
                f"experience_export_{datetime.now():%Y%m%d_%H%M%S}.json"
            )

        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM experiences ORDER BY confidence DESC"
                ).fetchall()
                data = [dict(r) for r in rows]

                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "export_time": datetime.now().isoformat(),
                        "total_records": len(data),
                        "experiences": data,
                    }, f, indent=2, ensure_ascii=False)

                log.info(f"经验库已导出: {output_path} ({len(data)} 条)")
                return output_path
            except Exception as e:
                log.error(f"经验库导出失败: {e}")
                return None
            finally:
                conn.close()

    def import_from(self, input_path: str, merge: bool = True) -> int:
        """
        从 JSON 文件导入经验库。

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

            experiences = data.get("experiences", [])
            imported = 0

            with self._lock:
                conn = self._get_conn()
                try:
                    for record in experiences:
                        fh = record.get("feature_hash", "")
                        if not fh:
                            continue

                        existing = conn.execute(
                            "SELECT id FROM experiences WHERE feature_hash = ?",
                            (fh,)
                        ).fetchone()

                        if existing and not merge:
                            conn.execute("""
                                UPDATE experiences SET
                                    error_type = ?, error_message = ?,
                                    context_json = ?, ai_analysis = ?,
                                    solution_strategy = ?, solution_params = ?,
                                    success_count = ?, fail_count = ?,
                                    confidence = ?
                                WHERE feature_hash = ?
                            """, (
                                record.get("error_type", ""),
                                record.get("error_message", ""),
                                record.get("context_json", "{}"),
                                record.get("ai_analysis"),
                                record.get("solution_strategy"),
                                record.get("solution_params", "{}"),
                                record.get("success_count", 0),
                                record.get("fail_count", 0),
                                record.get("confidence", 0.0),
                                fh,
                            ))
                            imported += 1
                        elif not existing:
                            conn.execute("""
                                INSERT INTO experiences (
                                    feature_hash, error_type, error_message,
                                    context_json, ai_analysis,
                                    solution_strategy, solution_params,
                                    success_count, fail_count, total_attempts,
                                    last_success_at, last_attempt_at, confidence
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                fh,
                                record.get("error_type", ""),
                                record.get("error_message", ""),
                                record.get("context_json", "{}"),
                                record.get("ai_analysis"),
                                record.get("solution_strategy"),
                                record.get("solution_params", "{}"),
                                record.get("success_count", 0),
                                record.get("fail_count", 0),
                                record.get("total_attempts", 0),
                                record.get("last_success_at"),
                                record.get("last_attempt_at"),
                                record.get("confidence", 0.0),
                            ))
                            imported += 1

                    conn.commit()
                except Exception as e:
                    log.error(f"导入失败: {e}")
                finally:
                    conn.close()

            log.info(f"经验库导入: {imported}/{len(experiences)} 条")
            return imported
        except Exception as e:
            log.error(f"经验库导入失败: {e}")
            return 0


# ─── 全局单例 ─────────────────────────────────────────────────────────────────

_global_experience_db: Optional[ExperienceDB] = None


def get_experience_db(db_path: Optional[str] = None) -> ExperienceDB:
    """
    获取全局 ExperienceDB 单例。

    Args:
        db_path: 数据库路径（仅首次调用有效）

    Returns:
        ExperienceDB 实例
    """
    global _global_experience_db
    if _global_experience_db is None:
        _global_experience_db = ExperienceDB(db_path=db_path)
    return _global_experience_db
