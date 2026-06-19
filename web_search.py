"""
InstaGuard - 联网搜索模块

当 AI 分析无法解决某个问题时，自动上网查询解决方案。
支持多搜索引擎（Google / Bing / DuckDuckGo），
结果去重和排序，聚焦 Android 安全领域。

包含搜索缓存机制（SQLite），避免重复搜索，
TTL 24 小时，查询指纹去重。

Author: InstaGuard Team
Version: 1.0.0
"""

import os
import re
import json
import time
import sqlite3
import hashlib
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

from utils import log, Config, HashUtils, safe_execute


# ─── 搜索结果数据结构 ──────────────────────────────────────────────────────────

@dataclass
class SearchResult:
    """搜索结果。

    Attributes:
        title: 结果标题
        url: 结果 URL
        snippet: 结果摘要
        source: 来源引擎（google / bing / duckduckgo / stackoverflow）
        relevance: 相关性评分（0.0 - 1.0）
        retrieved_at: 检索时间戳
    """
    title: str
    url: str
    snippet: str
    source: str = "unknown"          # google / bing / duckduckgo / stackoverflow
    relevance: float = 0.0           # 0.0 - 1.0
    retrieved_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典。"""
        return {
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "source": self.source,
            "relevance": self.relevance,
        }

    def __hash__(self) -> int:
        """基于 URL 的哈希，用于去重。"""
        return hash(self.url)

    def __eq__(self, other: object) -> bool:
        """基于 URL 的相等比较，用于去重。"""
        if not isinstance(other, SearchResult):
            return False
        return self.url == other.url


# ─── 搜索缓存 ──────────────────────────────────────────────────────────────────

class SearchCache:
    """搜索结果缓存。

    使用 SQLite 存储搜索查询和结果，避免重复搜索。
    TTL 为 24 小时，使用查询指纹去重。

    功能：
    - 自动存储搜索结果
    - 查询指纹去重（基于查询文本的 MD5）
    - TTL 过期清理
    - 缓存命中统计
    """

    # 缓存有效期（秒）
    CACHE_TTL = 24 * 60 * 60  # 24 小时

    def __init__(self, db_path: Optional[str] = None):
        """初始化搜索缓存。

        Args:
            db_path: SQLite 数据库路径，None 则使用默认路径
        """
        if db_path is None:
            from utils import DB_DIR
            os.makedirs(DB_DIR, exist_ok=True)
            db_path = os.path.join(DB_DIR, "search_cache.db")

        self._db_path = db_path
        self._lock = Lock()

        self._init_db()
        self._cleanup_expired()
        log.info(f"SearchCache 初始化完成 (db={db_path})")

    def _init_db(self) -> None:
        """初始化数据库表。"""
        with self._lock:
            conn = sqlite3.connect(self._db_path, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS search_cache (
                    fingerprint TEXT PRIMARY KEY,
                    query TEXT NOT NULL,
                    focus TEXT DEFAULT 'security',
                    results_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    hit_count INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_search_cache_created
                ON search_cache(created_at)
            """)
            conn.commit()
            conn.close()

    def _cleanup_expired(self) -> int:
        """清理过期缓存。

        Returns:
            清理的条目数
        """
        now = time.time()
        cutoff = now - self.CACHE_TTL

        with self._lock:
            conn = sqlite3.connect(self._db_path, timeout=5)
            cursor = conn.execute(
                "DELETE FROM search_cache WHERE created_at < ?",
                (cutoff,),
            )
            deleted = cursor.rowcount
            conn.commit()
            conn.close()

        if deleted > 0:
            log.info(f"SearchCache 清理 {deleted} 条过期记录")
        return deleted

    @staticmethod
    def _make_fingerprint(query: str, focus: str) -> str:
        """生成查询指纹。

        基于查询文本和焦点的 MD5 哈希。

        Args:
            query: 搜索查询文本
            focus: 搜索焦点

        Returns:
            指纹字符串
        """
        raw = f"{query.strip().lower()}|{focus}".encode("utf-8")
        return hashlib.md5(raw).hexdigest()

    def get(self, query: str, focus: str = "security") -> Optional[List[Dict[str, Any]]]:
        """从缓存获取搜索结果。

        Args:
            query: 搜索查询
            focus: 搜索焦点

        Returns:
            结果列表，缓存未命中返回 None
        """
        fingerprint = self._make_fingerprint(query, focus)

        with self._lock:
            conn = sqlite3.connect(self._db_path, timeout=5)
            cursor = conn.execute(
                "SELECT results_json, created_at FROM search_cache WHERE fingerprint = ?",
                (fingerprint,),
            )
            row = cursor.fetchone()
            conn.close()

            if row is None:
                return None

            results_json, created_at = row

            # 检查是否过期
            if time.time() - created_at > self.CACHE_TTL:
                # 过期，删除并返回 None
                with self._lock:
                    conn = sqlite3.connect(self._db_path, timeout=5)
                    conn.execute(
                        "DELETE FROM search_cache WHERE fingerprint = ?",
                        (fingerprint,),
                    )
                    conn.commit()
                    conn.close()
                return None

            # 更新命中计数
            with self._lock:
                conn = sqlite3.connect(self._db_path, timeout=5)
                conn.execute(
                    "UPDATE search_cache SET hit_count = hit_count + 1 WHERE fingerprint = ?",
                    (fingerprint,),
                )
                conn.commit()
                conn.close()

            try:
                results = json.loads(results_json)
                log.info(f"⚡ 搜索缓存命中: {query[:50]}... ({len(results)} 条结果)")
                return results
            except json.JSONDecodeError:
                return None

    def put(self, query: str, focus: str, results: List[Dict[str, Any]]) -> None:
        """将搜索结果存入缓存。

        Args:
            query: 搜索查询
            focus: 搜索焦点
            results: 搜索结果字典列表
        """
        fingerprint = self._make_fingerprint(query, focus)
        results_json = json.dumps(results, ensure_ascii=False)

        with self._lock:
            conn = sqlite3.connect(self._db_path, timeout=5)
            conn.execute(
                """INSERT OR REPLACE INTO search_cache
                   (fingerprint, query, focus, results_json, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (fingerprint, query, focus, results_json, time.time()),
            )
            conn.commit()
            conn.close()

        log.info(f"SearchCache 存储: {query[:50]}... ({len(results)} 条)")

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计。

        Returns:
            统计信息字典
        """
        with self._lock:
            conn = sqlite3.connect(self._db_path, timeout=5)
            cursor = conn.execute("SELECT COUNT(*), SUM(hit_count) FROM search_cache")
            row = cursor.fetchone()
            total = row[0] or 0
            total_hits = row[1] or 0

            cursor = conn.execute(
                "SELECT COUNT(*) FROM search_cache WHERE created_at > ?",
                (time.time() - 24 * 60 * 60,),
            )
            last_24h = cursor.fetchone()[0]
            conn.close()

        return {
            "total_entries": total,
            "total_hits": total_hits,
            "last_24h": last_24h,
            "ttl_hours": self.CACHE_TTL / 3600,
        }

    def clear(self) -> int:
        """清除所有缓存。

        Returns:
            清除的条目数
        """
        with self._lock:
            conn = sqlite3.connect(self._db_path, timeout=5)
            cursor = conn.execute("DELETE FROM search_cache")
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
        return deleted


# ─── 搜索引擎 ──────────────────────────────────────────────────────────────────

class WebSearchEngine:
    """联网搜索引擎。

    功能：
    - 多引擎支持：Google / Bing / DuckDuckGo（自动选择可用引擎）
    - 结果去重（基于 URL）和相关性排序
    - 聚焦安全领域：自动添加 Android 安全关键词
    - 安全问题的智能搜索
    - 修复方案的提取
    - 优雅降级：搜索不可用时返回空结果
    """

    # User-Agent（模拟浏览器请求）
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    # 搜索超时（秒）
    SEARCH_TIMEOUT = 10

    def __init__(self, cache: Optional[SearchCache] = None):
        """初始化搜索引擎。

        Args:
            cache: 搜索缓存实例，None 则自动创建
        """
        self._cache = cache or SearchCache()
        self._config = Config()
        self._lock = Lock()
        log.info("WebSearchEngine 初始化完成")

    @property
    def cache(self) -> SearchCache:
        """获取搜索缓存。"""
        return self._cache

    # ─── 核心搜索 ──────────────────────────────────────────────────────────

    def search(self, query: str, max_results: int = 10,
               focus: str = "security") -> List[SearchResult]:
        """执行搜索，返回结果列表。

        自动选择可用引擎，检查缓存，去重和排序结果。

        Args:
            query: 搜索查询
            max_results: 最大结果数
            focus: 搜索焦点（security / repair / general）

        Returns:
            搜索结果列表
        """
        if not query.strip():
            return []

        # 1. 检查缓存
        cached = self._cache.get(query, focus)
        if cached:
            results = []
            for item in cached[:max_results]:
                r = SearchResult(
                    title=item.get("title", ""),
                    url=item.get("url", ""),
                    snippet=item.get("snippet", ""),
                    source=item.get("source", "cache"),
                    relevance=item.get("relevance", 0.0),
                )
                results.append(r)
            return results

        # 2. 尝试多个搜索引擎，取第一个成功的
        engines = [
            self._search_duckduckgo,
            self._search_bing,
            self._search_google,
        ]

        all_results: List[SearchResult] = []
        for engine_fn in engines:
            try:
                results = engine_fn(query, focus)
                if results:
                    all_results.extend(results)
                    break  # 成功则停止
            except Exception as e:
                log.debug(f"搜索引擎 {engine_fn.__name__} 失败: {e}")
                continue

        # 如果所有引擎都失败，尝试 stackoverflow API
        if not all_results:
            try:
                results = self._search_stackoverflow(query)
                if results:
                    all_results.extend(results)
            except Exception as e:
                log.debug(f"StackOverflow 搜索失败: {e}")

        # 3. 去重（基于 URL）
        seen_urls: set = set()
        deduped: List[SearchResult] = []
        for r in all_results:
            if r.url not in seen_urls:
                seen_urls.add(r.url)
                deduped.append(r)
        all_results = deduped

        # 4. 计算相关性并排序
        all_results = self._rank_results(all_results, query)

        # 5. 限制数量
        all_results = all_results[:max_results]

        # 6. 存入缓存
        if all_results:
            self._cache.put(query, focus, [r.to_dict() for r in all_results])

        return all_results

    # ─── 搜索引擎实现 ──────────────────────────────────────────────────────

    def _search_duckduckgo(self, query: str, focus: str) -> List[SearchResult]:
        """使用 DuckDuckGo HTML 搜索（无需 API Key）。

        Args:
            query: 搜索查询
            focus: 搜索焦点

        Returns:
            搜索结果列表
        """
        # 构建搜索 URL（DuckDuckGo HTML 版本）
        encoded = urllib.parse.quote_plus(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded}"

        req = urllib.request.Request(url, headers={
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        })

        try:
            with urllib.request.urlopen(req, timeout=self.SEARCH_TIMEOUT) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            log.debug(f"DuckDuckGo 请求失败: {e}")
            return []

        # 解析 HTML 结果
        results: List[SearchResult] = []
        # 匹配 DuckDuckGo HTML 结果格式
        link_pattern = re.compile(
            r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
            re.DOTALL | re.IGNORECASE,
        )
        snippet_pattern = re.compile(
            r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>',
            re.DOTALL | re.IGNORECASE,
        )

        links = link_pattern.findall(html)
        snippets = snippet_pattern.findall(html)

        for i, (url_match, title) in enumerate(links):
            if i >= 20:
                break
            # 清理 URL（DuckDuckGo 会重定向）
            url_match = urllib.parse.unquote(url_match)
            # 提取实际 URL
            actual_url_match = re.search(r'uddg=(https?://[^&]+)', url_match)
            if actual_url_match:
                url_match = urllib.parse.unquote(actual_url_match.group(1))

            title_clean = re.sub(r'<[^>]+>', '', title).strip()
            snippet_clean = ""
            if i < len(snippets):
                snippet_clean = re.sub(r'<[^>]+>', '', snippets[i]).strip()

            if title_clean and url_match.startswith("http"):
                results.append(SearchResult(
                    title=title_clean,
                    url=url_match,
                    snippet=snippet_clean,
                    source="duckduckgo",
                ))

        return results

    def _search_bing(self, query: str, focus: str) -> List[SearchResult]:
        """使用 Bing 搜索（无需 API Key，使用网页搜索）。

        Args:
            query: 搜索查询
            focus: 搜索焦点

        Returns:
            搜索结果列表
        """
        encoded = urllib.parse.quote_plus(query)
        url = f"https://www.bing.com/search?q={encoded}&count=20"

        req = urllib.request.Request(url, headers={
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

        try:
            with urllib.request.urlopen(req, timeout=self.SEARCH_TIMEOUT) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            log.debug(f"Bing 请求失败: {e}")
            return []

        results: List[SearchResult] = []
        # 解析 Bing 结果 - 匹配 <li class="b_algo"> 中的链接和摘要
        # Bing 有多种结果格式，逐个匹配
        block_pattern = re.compile(
            r'<li class="b_algo"[^>]*>(.*?)</li>',
            re.DOTALL,
        )
        blocks = block_pattern.findall(html)

        for block in blocks[:20]:
            # 提取链接
            link_match = re.search(
                r'<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
                block, re.DOTALL,
            )
            if not link_match:
                continue

            url_match = link_match.group(1)
            title_clean = re.sub(r'<[^>]+>', '', link_match.group(2)).strip()

            # 提取摘要
            snippet_match = re.search(
                r'(?:<p[^>]*>|class="b_caption"[^>]*>)(.*?)(?:</p>|$)',
                block, re.DOTALL,
            )
            snippet_clean = ""
            if snippet_match:
                snippet_clean = re.sub(r'<[^>]+>', '', snippet_match.group(1)).strip()

            if title_clean and url_match.startswith("http"):
                results.append(SearchResult(
                    title=title_clean,
                    url=url_match,
                    snippet=snippet_clean[:300],
                    source="bing",
                ))

        return results

    def _search_google(self, query: str, focus: str) -> List[SearchResult]:
        """使用 Google 搜索（网页抓取，可能被速率限制）。

        注意：Google 可能会返回验证页面，这时自动回退到其他引擎。

        Args:
            query: 搜索查询
            focus: 搜索焦点

        Returns:
            搜索结果列表
        """
        encoded = urllib.parse.quote_plus(query)
        # 使用 Google 搜索的简化版本
        url = f"https://www.google.com/search?q={encoded}&num=20&hl=zh-CN"

        req = urllib.request.Request(url, headers={
            "User-Agent": self.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "zh-CN,zh;q=0.9",
        })

        try:
            with urllib.request.urlopen(req, timeout=self.SEARCH_TIMEOUT) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            log.debug(f"Google 请求失败: {e}")
            return []

        # 检测是否被要求验证
        if "captcha" in html.lower() or "verify" in html.lower():
            log.debug("Google 要求验证，跳过")
            return []

        results: List[SearchResult] = []
        # 匹配 Google 搜索结果格式
        # 链接格式: <a href="/url?q=REAL_URL&..."
        link_pattern = re.compile(
            r'<a[^>]*href="/url\?q=(https?://[^&"]+)[^"]*"[^>]*>'
            r'(.*?)'
            r'</a>',
            re.DOTALL,
        )

        matches = link_pattern.findall(html)
        for url_match, title_html in matches[:20]:
            title_clean = re.sub(r'<[^>]+>', '', title_html).strip()
            url_match = urllib.parse.unquote(url_match)

            if title_clean and url_match.startswith("http") and "google" not in url_match:
                results.append(SearchResult(
                    title=title_clean,
                    url=url_match,
                    snippet="",
                    source="google",
                ))

        return results

    def _search_stackoverflow(self, query: str) -> List[SearchResult]:
        """使用 StackOverflow 搜索（通过网页搜索）。

        Args:
            query: 搜索查询

        Returns:
            搜索结果列表
        """
        so_query = f"{query} site:stackoverflow.com"
        return self._search_duckduckgo(so_query, "security")

    # ─── 结果排序 ──────────────────────────────────────────────────────────

    def _rank_results(self, results: List[SearchResult],
                      query: str) -> List[SearchResult]:
        """对搜索结果进行相关性排序。

        优先级：
        1. stackoverflow.com / developer.android.com → 高权重
        2. 标题或摘要包含查询关键词 → 中等权重
        3. 安全相关域名 → 额外加分

        Args:
            results: 搜索结果列表
            query: 原始查询

        Returns:
            排序后的结果列表
        """
        query_lower = query.lower()
        keywords = set(query_lower.split())

        # 安全相关域名加分
        security_domains = {
            "stackoverflow.com": 0.9,
            "developer.android.com": 0.85,
            "android-developers.googleblog.com": 0.8,
            "github.com": 0.7,
            "medium.com": 0.6,
            "owasp.org": 0.85,
            "cwe.mitre.org": 0.8,
            "android.stackexchange.com": 0.75,
        }

        for r in results:
            score = 0.0

            # 域名加分
            for domain, weight in security_domains.items():
                if domain in r.url:
                    score = max(score, weight)
                    break

            # 标题匹配
            title_lower = r.title.lower()
            keyword_matches = sum(1 for kw in keywords if kw in title_lower)
            score += keyword_matches * 0.1

            # 摘要匹配
            snippet_lower = r.snippet.lower()
            keyword_matches += sum(1 for kw in keywords if kw in snippet_lower)
            score += keyword_matches * 0.05

            # android 关键词特别加分
            if "android" in title_lower:
                score += 0.1
            if "security" in title_lower or "安全" in r.title:
                score += 0.1

            r.relevance = min(score, 1.0)

        # 按相关性降序排序
        results.sort(key=lambda r: -r.relevance)
        return results

    # ─── 专用搜索方法 ──────────────────────────────────────────────────────

    def search_security_issue(self, risk_title: str,
                              risk_category: str) -> List[SearchResult]:
        """搜索特定安全问题的解决方案。

        自动添加 Android 安全关键词，聚焦 StackOverflow 和 Android 开发者文档。

        Args:
            risk_title: 风险标题
            risk_category: 风险类别

        Returns:
            搜索结果列表
        """
        # 构建优化搜索查询
        query = f"Android security fix {risk_title} {risk_category}"

        # 添加目标站点
        query += " site:stackoverflow.com OR site:developer.android.com"

        log.info(f"搜索安全问题: {risk_title} ({risk_category})")
        return self.search(query, max_results=10, focus="security")

    def search_repair_solution(self, error_message: str) -> List[SearchResult]:
        """搜索修复方案。

        针对错误消息搜索具体的修复步骤。

        Args:
            error_message: 错误消息

        Returns:
            搜索结果列表
        """
        query = f"Android APK repair fix {error_message}"
        log.info(f"搜索修复方案: {error_message[:80]}...")
        return self.search(query, max_results=10, focus="repair")

    def search_android_best_practice(self, topic: str) -> List[SearchResult]:
        """搜索 Android 最佳实践。

        Args:
            topic: 主题（如 permission、manifest、signing）

        Returns:
            搜索结果列表
        """
        query = f"Android best practice {topic} security developer.android.com"
        return self.search(query, max_results=5, focus="security")

    # ─── 方案提取 ──────────────────────────────────────────────────────────

    def extract_solution(self, results: List[SearchResult]) -> Optional[str]:
        """从搜索结果中提取最佳解决方案。

        分析搜索结果，提取最相关的代码示例或步骤说明。

        Args:
            results: 搜索结果列表

        Returns:
            解决方案文本，无有效结果返回 None
        """
        if not results:
            return None

        # 优先使用高相关性结果
        sorted_results = sorted(results, key=lambda r: -r.relevance)

        # 构建方案摘要
        parts: List[str] = []
        parts.append("🔍 **联网搜索结果**\n")

        for i, r in enumerate(sorted_results[:5], 1):
            source_icon = {
                "duckduckgo": "🦆", "bing": "🔵", "google": "🔴",
                "stackoverflow": "📚", "cache": "⚡",
            }.get(r.source, "🌐")

            parts.append(f"{i}. {source_icon} **{r.title}**")
            parts.append(f"   链接: {r.url}")
            if r.snippet:
                parts.append(f"   摘要: {r.snippet[:200]}")
            parts.append(f"   相关度: {r.relevance:.0%}\n")

        if len(sorted_results) > 5:
            parts.append(f"... 还有 {len(sorted_results) - 5} 条结果\n")

        parts.append("\n💡 请根据以上结果手动确认最佳方案。")

        return "\n".join(parts)

    def extract_code_solution(self, results: List[SearchResult]) -> Optional[str]:
        """尝试从搜索结果中提取代码示例。

        Args:
            results: 搜索结果列表

        Returns:
            代码解决方案文本，无则返回 None
        """
        if not results:
            return None

        # 查找可能包含代码的结果
        code_keywords = ["```", "code", "example", "snippet", "<?xml", "<manifest",
                         "android:", "public class", "def ", "function"]
        code_results = []

        for r in results:
            snippet_lower = r.snippet.lower()
            if any(kw.lower() in snippet_lower for kw in code_keywords):
                code_results.append(r)

        if not code_results:
            return None

        parts = ["💻 **搜索到的代码示例**\n"]
        for i, r in enumerate(code_results[:3], 1):
            parts.append(f"{i}. {r.title}")
            parts.append(f"   来源: {r.url}")
            parts.append(f"   预览: {r.snippet[:250]}\n")

        return "\n".join(parts)

    # ─── 工具方法 ──────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """检测搜索引擎是否可用。

        执行快速网络检查。

        Returns:
            是否可用
        """
        try:
            test_url = "https://html.duckduckgo.com/html/?q=test"
            req = urllib.request.Request(test_url, headers={"User-Agent": self.USER_AGENT})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_cache_stats(self) -> Dict[str, Any]:
        """获取搜索缓存统计。

        Returns:
            统计信息字典
        """
        return self._cache.get_stats()

    def clear_cache(self) -> int:
        """清除搜索缓存。

        Returns:
            清除的条目数
        """
        return self._cache.clear()


# ─── 单例 ──────────────────────────────────────────────────────────────────────

_search_engine_instance: Optional[WebSearchEngine] = None


def get_search_engine() -> WebSearchEngine:
    """获取 WebSearchEngine 单例。

    Returns:
        搜索引擎实例
    """
    global _search_engine_instance
    if _search_engine_instance is None:
        _search_engine_instance = WebSearchEngine()
    return _search_engine_instance
