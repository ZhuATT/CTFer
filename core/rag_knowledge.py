"""
RAG 知识检索 - 直接模式组件
基于关键词的简单 RAG，从 wooyun knowledge 目录检索相似题目知识
从 H-Pentest `tools/knowledge.py` 简化迁移

P2 增强版本：
- 中文分词 (jieba)
- 句子级相似度 (TF-IDF + 余弦相似度)
- 同义词扩展 (CTF 相关术语)
"""
import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class RAGKnowledge:
    """
    P2 增强版 RAG 实现

    检索流程：
    1. 同义词扩展 → 2. 中文分词 (jieba) → 3. TF-IDF 句子相似度 → 4. 返回 top_k 结果

   搜索目录（按优先级）：
    1. memories/experiences/<type>.md - 历史成功经验（最高）
    2. skills/<type>/SKILL.md - 题型技能知识
    3. wooyun/knowledge/<category>.md - WooYun 技术手册
    4. wooyun/plugins/wooyun-legacy/categories/ - WooYun 精简案例库
    """

    # CTF 相关同义词映射
    SYNONYMS: Dict[str, Set[str]] = {
        # 命令执行类
        "rce": {"远程代码执行", "命令注入", "代码执行", "command injection", "code execution", "exec", "os.system", "shell_exec"},
        "exec": {"执行", "命令执行", "system", "popen", "shell"},
        "bypass": {"绕过", "绕过限制", "逃逸", "escape", "disable functions"},
        "disable_functions": {"禁用函数", "disable_functions", "绕过disable", "绕waf"},
        # SQL注入类
        "sqli": {"sql注入", "sql injection", "union", "联合查询", "布尔盲注", "时间盲注", "报错注入"},
        "union": {"联合查询", "联合注入", "union select"},
        "blind": {"盲注", "boolean blind", "time based", "布尔", "时间"},
        "waf": {"waf", "防火墙", "过滤", "拦截", "bypass"},
        # 文件操作类
        "lfi": {"本地文件包含", "file inclusion", "include", "require", "文件包含"},
        "rfi": {"远程文件包含", "远程包含", "file inclusion", "远程"},
        "upload": {"上传", "文件上传", "getshell", "webshell", "绕过"},
        "path": {"路径", "directory", "目录遍历", "traversal", "../"},
        # Web安全
        "xss": {"跨站脚本", "xss", "弹窗", "alert", "script", "dom"},
        "csrf": {"跨站请求伪造", "csrf", "token", "csrf token"},
        "ssrf": {"服务端请求伪造", "ssrf", "curl", "file_get_contents"},
        "ssti": {"模板注入", "ssti", "jinja2", "twig", "模板引擎"},
        "反序列化": {"unserialize", "serialize", "反序列化漏洞", "php unserialize", "java deserialization", "pickle"},
        "序列化": {"serialize", " unserialize", "json encode", "msgpack"},
        # 认证类
        "auth": {"认证", "登录", "密码", "password", "brute", "暴力破解", "jwt", "token", "session"},
        "jwt": {"json web token", "token伪造", "算法绕过", "none algorithm"},
        "brute": {"暴力破解", "爆破", "字典", "password crack"},
        # 其他
        "info": {"信息泄露", "info disclosure", "敏感信息", "robots.txt", "备份文件"},
        "recon": {"reconnaissance", "信息收集", "目录扫描", "dirsearch", "御剑"},
    }

    def __init__(self, knowledge_dir: Optional[str] = None):
        """
        Args:
            knowledge_dir: 知识库目录，默认使用 wooyun/knowledge/
        """
        if knowledge_dir is None:
            project_root = Path(__file__).parent.parent
            self.knowledge_dir = str(project_root / "wooyun" / "knowledge")
            self.experiences_dir = str(project_root / "memories" / "experiences")
            self.skills_dir = str(project_root / "skills")
            # WooYun 精简案例库（轻量安装版本）
            self.wooyun_categories_dir = str(project_root / "wooyun" / "plugins" / "wooyun-legacy" / "categories")
        else:
            self.knowledge_dir = knowledge_dir
            self.experiences_dir = None
            self.skills_dir = None
            self.wooyun_categories_dir = None

        self.cache: Dict[Path, str] = {}
        self._jieba_available = self._check_jieba()

    def _check_jieba(self) -> bool:
        """检查 jieba 是否可用"""
        try:
            import jieba
            jieba.initialize()
            return True
        except ImportError:
            return False

    def _segment_chinese(self, text: str) -> List[str]:
        """中英文混合分词"""
        text = text.lower()

        if self._jieba_available:
            import jieba
            words = list(jieba.cut(text))
        else:
            # 回退：简单按中英文混合分割
            words = re.findall(r"[\w]+|[^\s\w]", text)

        # 过滤停用词和短词
        stopwords = {
            "a", "an", "the", "to", "of", "and", "or", "in", "on", "at", "for", "with", "by",
            "is", "are", "was", "were", "be", "been", "being", "have", "has", "had",
            "do", "does", "did", "will", "would", "could", "should", "may", "might",
            "must", "shall", "can", "need", "dare", "ought", "used", "this", "that",
            "these", "those", "i", "you", "he", "she", "it", "we", "they", "what",
            "which", "who", "whom", "whose", "where", "when", "why", "how",
            "的", "了", "在", "是", "我", "有", "和", "就", "不", "人", "都", "一",
            "一个", "上", "也", "很", "到", "说", "要", "去", "你", "会", "着", "没有",
            "看", "好", "自己", "这", "那", "但", "却", "而", "与", "或", "之", "于",
            "被", "由", "对", "以", "及", "等", "其", "并", "可", "中", "后", "前",
            "来", "下", "过", "还", "又", "么", "得", "地", "能", "如", "因", "所",
            "为", "从", "此", "者", "当", "时", "使", "用", "把", "给", "越", "越",
        }
        return [w for w in words if w not in stopwords and len(w) > 1]

    def _expand_synonyms(self, keywords: List[str]) -> Set[str]:
        """同义词扩展"""
        expanded: Set[str] = set()

        for kw in keywords:
            kw_lower = kw.lower()
            expanded.add(kw_lower)

            # 精确匹配同义词
            for key, synonyms in self.SYNONYMS.items():
                if kw_lower == key.lower() or kw_lower in {s.lower() for s in synonyms}:
                    expanded.update(synonyms)
                    expanded.add(key)
                    break

            # 部分匹配（如 "命令" 应该匹配到 "rce" 的同义词组）
            for key, synonyms in self.SYNONYMS.items():
                if kw_lower in key.lower() or any(kw_lower in s.lower() for s in synonyms):
                    expanded.update(synonyms)
                    expanded.add(key)

        return expanded

    def _calculate_tf_idf(self, query_words: List[str], content_words: List[str]) -> float:
        """计算 TF-IDF 余弦相似度"""
        if not query_words or not content_words:
            return 0.0

        # 词频统计
        query_tf = Counter(query_words)
        content_tf = Counter(content_words)

        # 计算 TF
        query_len = len(query_words)
        content_len = len(content_words)

        # 向量
        all_words = set(query_tf.keys()) | set(content_tf.keys())

        if not all_words:
            return 0.0

        # 简单余弦相似度
        dot_product = sum(query_tf[w] * content_tf[w] for w in all_words)
        query_norm = math.sqrt(sum((query_tf[w] / query_len) ** 2 for w in all_words))
        content_norm = math.sqrt(sum((content_tf[w] / content_len) ** 2 for w in all_words))

        if query_norm == 0 or content_norm == 0:
            return 0.0

        return dot_product / (query_norm * content_norm)

    def _split_sentences(self, content: str) -> List[str]:
        """将内容分割为句子"""
        # 按行分割，每行作为一个句子单元
        lines = content.split("\n")
        sentences = []
        for line in lines:
            line = line.strip()
            if line and len(line) > 10:  # 过滤短行
                sentences.append(line)
        return sentences

    def search(
        self,
        query: str,
        category: str = "",
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        检索所有知识库

        Args:
            query: 查询字符串
            category: 可选，限定类别（如 "command-execution"）
            top_k: 返回前 k 条

        Returns:
            [{"title": ..., "method": ..., "content": ..., "relevance": float, "source": ...}]
            source 取值: "experiences" | "skills" | "wooyun" | "wooyun_cases"
        """
        results = []

        # 1. 同义词扩展
        base_keywords = self._extract_keywords(query)
        expanded_keywords = self._expand_synonyms(base_keywords)
        query_segmented = self._segment_chinese(" ".join(expanded_keywords))

        # 2. 搜索 memories/experiences/
        if self.experiences_dir:
            results.extend(self._search_dir(
                self.experiences_dir, query_segmented, category,
                "experiences", top_k
            ))

        # 3. 搜索 skills/
        if self.skills_dir:
            results.extend(self._search_dir(
                self.skills_dir, query_segmented, category,
                "skills", top_k
            ))

        # 4. 搜索 wooyun/knowledge/
        if self.knowledge_dir:
            results.extend(self._search_dir(
                self.knowledge_dir, query_segmented, category,
                "wooyun", top_k
            ))

        # 5. 搜索 wooyun 精简案例库（wooyun-legacy）
        if self.wooyun_categories_dir:
            results.extend(self._search_dir(
                self.wooyun_categories_dir, query_segmented, category,
                "wooyun_cases", top_k
            ))

        # 排序并返回 top_k
        results.sort(key=lambda x: x["relevance"], reverse=True)
        return results[:top_k]

    def _search_dir(
        self,
        dir_path: str,
        query_segmented: List[str],
        category: str,
        source: str,
        top_k: int,
    ) -> List[Dict[str, Any]]:
        """搜索指定目录"""
        results = []
        dir_path = Path(dir_path)

        if not dir_path.exists():
            return results

        # 确定要搜索的文件
        if category and source in ["experiences", "wooyun"]:
            # 按类别过滤
            if source == "experiences":
                files = [dir_path / f"{category}.md"]
            else:
                files = [dir_path / f"{category}.md"]
        else:
            files = list(dir_path.glob("**/*.md"))[:50]  # 限制数量

        for file_path in files:
            if not file_path.exists():
                continue

            content = self._read_file(file_path)
            sections = self._split_sections(content)

            for section in sections:
                sentences = self._split_sentences(section["content"])
                best_score = 0.0

                for sent in sentences:
                    sent_words = self._segment_chinese(sent)
                    score = self._calculate_tf_idf(query_segmented, sent_words)
                    best_score = max(best_score, score)

                title_words = self._segment_chinese(section["title"])
                title_score = self._calculate_tf_idf(query_segmented, title_words)
                final_score = best_score * 0.7 + title_score * 0.3

                if final_score > 0.03:
                    results.append({
                        "title": section["title"] or file_path.stem,
                        "method": section.get("method", ""),
                        "content": section["content"][:500],
                        "relevance": round(final_score, 4),
                        "source": source,
                        "file": str(file_path.relative_to(dir_path.parent)),
                    })

        return results

    def _extract_keywords(self, text: str) -> List[str]:
        """从文本中提取关键词"""
        text = re.sub(r"[^\w\s]", " ", text.lower())
        words = text.split()
        stopwords = {"a", "an", "the", "to", "of", "and", "or", "in", "on", "at", "for", "with", "by", "is", "are", "was", "were"}
        return [w for w in words if w not in stopwords and len(w) > 2]

    def _read_file(self, path: Path) -> str:
        """读取文件（带缓存）"""
        if path not in self.cache:
            try:
                self.cache[path] = path.read_text(encoding="utf-8")
            except Exception:
                self.cache[path] = ""
        return self.cache[path]

    def _split_sections(self, content: str) -> List[Dict[str, str]]:
        """将 markdown 内容分割为段落"""
        sections = []
        # 按 ## 标题 分割
        parts = re.split(r"\n(?=##\s)", content)

        current_title = ""
        for part in parts:
            part = part.strip()
            if not part:
                continue

            # 提取标题
            title_match = re.match(r"##\s+(.+)", part)
            if title_match:
                current_title = title_match.group(1).strip()
                part = re.sub(r"##\s+.+\n", "", part).strip()

            if part:
                sections.append({
                    "title": current_title,
                    "content": part,
                })

        return sections


# 全局实例（延迟初始化）
_rag_instance: Optional[RAGKnowledge] = None


def get_rag() -> RAGKnowledge:
    """获取 RAG 实例（单例）"""
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = RAGKnowledge()
    return _rag_instance


def search_knowledge(
    query: str,
    category: str = "",
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """快捷函数：搜索知识"""
    results = get_rag().search(query, category, top_k)

    # 自动标记知识已查询（触发Hook放行后续攻击命令）
    if results:
        try:
            from pathlib import Path
            marker_file = Path(__file__).parent.parent / "workspace" / ".knowledge_checked"
            marker_file.parent.mkdir(parents=True, exist_ok=True)
            marker_file.touch()
        except Exception:
            pass  # 静默失败，不影响正常流程

    return results


def get_knowledge_for_llm(query: str, category: str = "", top_k: int = 10) -> str:
    """
    获取格式化好的知识文本，直接供 LLM 使用

    检索所有相关知识，格式化为易读的文本段落

    Args:
        query: 查询字符串（如题型、关键词）
        category: 可选，限定类别
        top_k: 返回前 k 条结果

    Returns:
        格式化好的知识文本，可直接作为 LLM 上下文
    """
    from skills.encoding_fix import encode_for_terminal

    def to_str(val):
        """将 encode_for_terminal 的返回值转为 str"""
        result = encode_for_terminal(val)
        if isinstance(result, bytes):
            return result.decode('utf-8')
        return result

    results = search_knowledge(query, category, top_k)

    if not results:
        return ""

    # 按来源分组
    sources = {}
    for r in results:
        src = r.get("source", "unknown")
        if src not in sources:
            sources[src] = []
        sources[src].append(r)

    # 构建格式化文本
    lines = ["=== 知识检索结果 ===\n"]

    source_names = {
        "experiences": "【成功经验】",
        "skills": "【技能知识】",
        "wooyun": "【漏洞库】",
    }

    for source_name, items in sources.items():
        name = source_names.get(source_name, f"【{source_name}】")
        lines.append(f"\n{name}\n")
        lines.append("-" * 40)

        for i, item in enumerate(items, 1):
            title = to_str(item.get("title", ""))
            method = to_str(item.get("method", ""))
            content = to_str(item.get("content", ""))
            relevance = item.get("relevance", 0)

            lines.append(f"\n[{i}] {title}")
            if method:
                lines.append(f"    方法: {method}")
            lines.append(f"    相关度: {relevance:.2f}")
            lines.append(f"    内容: {content[:300]}..." if len(content) > 300 else f"    内容: {content}")

    lines.append("\n=== 知识检索结束 ===")
    return "\n".join(lines)


def get_all_type_knowledge(challenge_type: str) -> str:
    """
    获取指定题型的全部知识（供 LLM 使用）

    同时检索：
    1. skills/<type>/SKILL.md - 技能知识
    2. memories/experiences/<type>.md - 成功经验
    3. wooyun/knowledge/<category>.md - 类似题目

    Args:
        challenge_type: 题型（如 "rce", "sqli"）

    Returns:
        格式化好的知识文本
    """
    # 记录知识调用日志（供 Hook 验证）
    try:
        from pathlib import Path
        import time
        log_file = Path(__file__).parent.parent / "workspace" / ".knowledge_log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"{time.time()}|get_all_type_knowledge|{challenge_type}\n")
    except Exception:
        pass  # 静默失败

    # 题型到 wooyun 类别的映射
    type_to_category = {
        "rce": "command-execution",
        "sqli": "sql-injection",
        "lfi": "file-traversal",
        "upload": "file-upload",
        "xss": "xss",
        "auth": "unauthorized-access",
        "ssrf": "ssrf",
        "ssti": "ssti",
    }

    category = type_to_category.get(challenge_type.lower(), challenge_type.lower())

    # 并行检索多个来源
    skill_knowledge = search_knowledge(challenge_type, category="", top_k=5)
    exp_knowledge = search_knowledge(category, category=category, top_k=5)
    all_knowledge = search_knowledge(challenge_type, category=category, top_k=10)

    # 去重合并
    seen = set()
    merged = []
    for item in skill_knowledge + exp_knowledge + all_knowledge:
        key = item.get("title", "") + item.get("source", "")
        if key not in seen:
            seen.add(key)
            merged.append(item)

    # 按相关度排序
    merged.sort(key=lambda x: x.get("relevance", 0), reverse=True)

    return format_knowledge_results(merged[:15])


def format_knowledge_results(results: List[Dict[str, Any]]) -> str:
    """将检索结果格式化为易读文本

    Returns:
        str: 格式化后的知识文本
    """
    from skills.encoding_fix import encode_for_terminal, safe_print
    import sys

    def encode_val(val):
        """将 encode_for_terminal 的返回值转为可输出的形式"""
        result = encode_for_terminal(val)
        if isinstance(result, bytes):
            return result.decode('utf-8', errors='replace')
        return result

    if not results:
        return ""

    lines = ["=== 相关知识 ===\n"]

    for i, item in enumerate(results, 1):
        title = encode_val(item.get("title", ""))
        method = encode_val(item.get("method", ""))
        content = encode_val(item.get("content", ""))
        source = item.get("source", "")
        file_path = item.get("file", "")

        lines.append(f"\n【{i}】{title}")
        if method:
            lines.append(f"    方法: {method}")
        lines.append(f"    来源: {source} -> {file_path}")
        # 限制内容长度
        if len(content) > 400:
            content = content[:400] + "..."
        lines.append(f"    {content}")

    lines.append("\n=== 知识结束 ===")

    # 检测是否需要使用 safe_print 输出
    stdout_enc = sys.stdout.encoding or ''
    msys2_utf8 = (
        stdout_enc.lower() in ('gbk', 'gb2312', 'gb18030', 'cp1252', 'cp936')
        and hasattr(sys.stdout, 'buffer')
    )

    if msys2_utf8:
        # 使用 safe_print 输出，避免编码问题
        # safe_print 已经输出了内容，直接返回空字符串避免 print 重复输出
        output = "\n".join(lines)
        safe_print(output)
        return ""  # 返回空字符串，因为内容已通过 safe_print 输出
    else:
        return "\n".join(lines)
