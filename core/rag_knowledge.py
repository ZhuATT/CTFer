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

    # 题型相似性映射
    SIMILAR_TYPES: Dict[str, List[str]] = {
        "lfi": ["file-inclusion", "rfi", "file-traversal"],
        "rce": ["command-injection", "exec", "command-execution"],
        "sqli": ["sql-injection", "injection", "sql"],
        "auth": ["bypass", "unauthorized-access", "authentication"],
        "upload": ["file-upload", "upload"],
        "xss": ["xss", "cross-site"],
        "ssrf": ["ssrf", "server-side-request-forgery"],
        "ssti": ["ssti", "template-injection", "template"],
        "反序列化": ["deserialization", "unserialize", "serialize"],
    }

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
        challenge_type: str = "",
    ) -> List[Dict[str, Any]]:
        """
        检索所有知识库

        Args:
            query: 查询字符串
            category: 映射后的类别（如 "file-traversal"，用于 wooyun）
            top_k: 返回前 k 条
            challenge_type: 原始题型（如 "lfi"，用于 experiences 文件名匹配）

        Returns:
            [{"title": ..., "method": ..., "content": ..., "relevance": float, "source": ...}]
            source 取值: "experiences" | "skills"
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
                "experiences", top_k, challenge_type
            ))

        # 3. 搜索 skills/
        if self.skills_dir:
            results.extend(self._search_dir(
                self.skills_dir, query_segmented, category,
                "skills", top_k
            ))

        # 排序并返回 top_k
        # 使用 sort_by_type_priority 确保同题型 experiences/skills 优先
        sorted_results = sort_by_type_priority(results, challenge_type)
        return sorted_results[:top_k]

    def _search_dir(
        self,
        dir_path: str,
        query_segmented: List[str],
        category: str,
        source: str,
        top_k: int,
        challenge_type: str = "",
    ) -> List[Dict[str, Any]]:
        """搜索指定目录"""
        results = []
        dir_path = Path(dir_path)

        if not dir_path.exists():
            return results

        # 确定要搜索的文件
        if category and source == "wooyun":
            # wooyun 使用 category 映射
            files = [dir_path / f"{category}.md"]
        elif source == "experiences" and challenge_type:
            # experiences 使用原始 challenge_type 作为文件名
            files = [dir_path / f"{challenge_type}.md"]
        else:
            files = list(dir_path.glob("**/*.md"))[:50]  # 限制数量

        for file_path in files:
            if not file_path.exists():
                continue

            content = self._read_file(file_path)
            sections = self._split_sections(content)

            for section in sections:
                # 对主内容和代码块分别计算分数
                main_text = section["content"]
                main_sentences = self._split_sentences(main_text)
                best_main_score = 0.0

                for sent in main_sentences:
                    sent_words = self._segment_chinese(sent)
                    score = self._calculate_tf_idf(query_segmented, sent_words)
                    best_main_score = max(best_main_score, score)

                # 代码块分数（payload 通常在代码块中，权重更高）
                code_blocks = section.get("code_blocks", [])
                best_code_score = 0.0
                for cb in code_blocks:
                    cb_words = self._segment_chinese(cb)
                    cb_score = self._calculate_tf_idf(query_segmented, cb_words)
                    best_code_score = max(best_code_score, cb_score)

                # 综合分数：内容分数 + 代码块分数（1.5倍权重）
                content_score = max(best_main_score, best_code_score * 0.7)

                # 标题分数
                title_words = self._segment_chinese(section["title"])
                title_score = self._calculate_tf_idf(query_segmented, title_words)

                # 最终分数：内容 70% + 标题 30%
                final_score = content_score * 0.7 + title_score * 0.3

                # 代码块存在时提升分数（payload 相关性高）
                if code_blocks:
                    final_score *= 1.2

                if final_score > 0.02:
                    results.append({
                        "title": section["title"] or file_path.stem,
                        "method": section.get("method", ""),
                        # 保留完整内容，不截断，但限制最大长度防止过大
                        "content": main_text[:2000] if len(main_text) > 2000 else main_text,
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
        """多级细粒度分割 markdown 内容

        分割层级：
        1. 按 ## 分割大块（顶级标题）
        2. 大块内按 ### 分割子块
        3. 代码块（```...```）独立保留

        每个单元包含：
        - title: 完整标题路径
        - content: 原始内容（不截断）
        - code_blocks: 提取的代码块列表
        """
        sections = []

        # 移除 frontmatter
        content = re.sub(r'^---\n.*?\n---\n', '', content, flags=re.DOTALL)

        # 按 ## 分割大块
        major_parts = re.split(r"\n(?=##\s)", content)

        for major in major_parts:
            major = major.strip()
            if not major:
                continue

            # 提取主标题
            major_match = re.match(r"##\s+(.+)", major)
            if major_match:
                major_title = major_match.group(1).strip()
                major = re.sub(r"##\s+.+\n", "", major).strip()
            else:
                major_title = ""

            # 按 ### 分割子块
            sub_parts = re.split(r"\n(?=###\s)", major)

            for sub in sub_parts:
                sub = sub.strip()
                if not sub:
                    continue

                # 提取子标题
                sub_match = re.match(r"###\s+(.+)", sub)
                if sub_match:
                    sub_title = sub_match.group(1).strip()
                    sub = re.sub(r"###\s+.+\n", "", sub).strip()
                else:
                    sub_title = ""

                # 构建完整标题
                if sub_title:
                    full_title = f"{major_title} - {sub_title}" if major_title else sub_title
                else:
                    full_title = major_title

                if not full_title:
                    full_title = "未分类"

                # 提取代码块（保留完整，不截断）
                code_blocks = re.findall(r'```[\s\S]*?```', sub)

                sections.append({
                    "title": full_title,
                    "content": sub,  # 保留完整内容
                    "code_blocks": code_blocks,
                })

        return sections


def extract_type_from_path(file_path: str) -> str:
    """从文件路径中提取题型

    Examples:
        memories/experiences/lfi.md -> lfi
        experiences/lfi.md -> lfi
        skills/rce/SKILL.md -> rce
        rce/SKILL.md -> rce
        wooyun/knowledge/command-execution.md -> command-execution
    """
    import re

    # 统一反斜杠为正斜杠（兼容 Windows 路径）
    file_path = file_path.replace('\\', '/')

    # 尝试多种路径格式
    patterns = [
        # 完整路径
        r'memories/experiences/([\w-]+)\.md$',
        r'skills/([\w-]+)/SKILL\.md$',
        r'knowledge/([\w-]+)\.md$',
        r'categories/([\w-]+)\.md$',
        # 相对路径（无前缀）
        r'experiences/([\w-]+)\.md$',
        r'([\w-]+)/SKILL\.md$',
    ]

    for pattern in patterns:
        match = re.search(pattern, file_path)
        if match:
            return match.group(1).lower()

    return ""


def is_similar_type(t1: str, t2: str) -> bool:
    """判断两个题型是否相似

    Args:
        t1: 题型1（如 "lfi"）
        t2: 题型2（如 "file-inclusion"）

    Returns:
        True 如果两个题型相似或相同
    """
    t1_lower = t1.lower()
    t2_lower = t2.lower()

    # 完全相同
    if t1_lower == t2_lower:
        return True

    # 在 SIMILAR_TYPES 中查找
    for base, aliases in RAGKnowledge.SIMILAR_TYPES.items():
        all_types = [base] + aliases
        if t1_lower in all_types and t2_lower in all_types:
            return True

    return False


def sort_by_type_priority(results: List[Dict], challenge_type: str) -> List[Dict]:
    """按题型优先级排序

    优先级顺序：
    1. experiences 同题型
    2. skills 同题型
    3. wooyun 同题型
    4. experiences 跨题型
    5. skills 跨题型
    6. wooyun 跨题型

    Args:
        results: 检索结果列表
        challenge_type: 当前挑战题型

    Returns:
        排序后的结果列表
    """

    def get_priority(item: Dict) -> tuple:
        source = item.get("source", "")
        file_path = item.get("file", "")
        item_type = extract_type_from_path(file_path)

        is_same = is_similar_type(item_type, challenge_type)

        # 来源优先级: experiences=0, skills=1, wooyun/wooyun_cases=2
        source_priority_map = {"experiences": 0, "skills": 1, "wooyun": 2, "wooyun_cases": 2}
        source_priority = source_priority_map.get(source, 3)

        # 题型优先级: 同题型=0, 跨题型=1
        type_priority = 0 if is_same else 1

        return (type_priority, source_priority)

    return sorted(results, key=get_priority)


def format_structured_output(results: List[Dict], challenge_type: str) -> str:
    """生成结构化输出，直接喂给 LLM

    Args:
        results: 排序后的检索结果
        challenge_type: 当前挑战题型

    Returns:
        结构化的 markdown 格式文本
    """
    from skills.encoding_fix import encode_for_terminal

    def to_str(val):
        """将值转为字符串（供 LLM 使用，保持 Unicode 原文）"""
        if val is None:
            return ""
        if isinstance(val, bytes):
            return val.decode('utf-8', errors='replace')
        return str(val)

    # 按题型和来源分组
    groups = {
        "experiences_same": [],
        "skills_same": [],
        "wooyun_same": [],
        "cross_type": [],
    }

    for item in results:
        source = item.get("source", "")
        file_path = item.get("file", "")
        item_type = extract_type_from_path(file_path)
        is_same = is_similar_type(item_type, challenge_type)

        key = None
        if is_same:
            if source == "experiences":
                key = "experiences_same"
            elif source == "skills":
                key = "skills_same"
            elif source in ("wooyun", "wooyun_cases"):
                key = "wooyun_same"

        if key:
            groups[key].append(item)
        else:
            groups["cross_type"].append(item)

    lines = [f"## 【{challenge_type.upper()} 题型知识】\n"]

    # 同题型经验
    if groups["experiences_same"]:
        lines.append("## 【SUCCESSFUL EXPERIENCES - 同题型】")
        for i, item in enumerate(groups["experiences_same"], 1):
            lines.append(f"\n### [{i}] {to_str(item['title'])}")
            lines.append(f"**来源**: {to_str(item['file'])}")
            lines.append(f"**内容**:\n{to_str(item['content'])}")
            lines.append("---")

    # 同题型技能
    if groups["skills_same"]:
        lines.append("\n## 【SKILLS - 同题型】")
        for i, item in enumerate(groups["skills_same"], 1):
            lines.append(f"\n### [{i}] {to_str(item['title'])}")
            lines.append(f"**来源**: {to_str(item['file'])}")
            lines.append(f"**内容**:\n{to_str(item['content'])}")
            lines.append("---")

    # 同题型案例
    if groups["wooyun_same"]:
        lines.append("\n## 【WOOYUN CASES - 同题型】")
        for i, item in enumerate(groups["wooyun_same"], 1):
            lines.append(f"\n### [{i}] {to_str(item['title'])}")
            lines.append(f"**来源**: {to_str(item['file'])}")
            lines.append(f"**内容**:\n{to_str(item['content'])}")
            lines.append("---")

    # 跨题型参考
    if groups["cross_type"]:
        lines.append("\n## 【CROSS-TYPE - 参考】")
        for i, item in enumerate(groups["cross_type"], 1):
            lines.append(f"\n### [{i}] {to_str(item['title'])} ({item['source']})")
            lines.append(f"**来源**: {to_str(item['file'])}")
            lines.append(f"**内容**:\n{to_str(item['content'])}")
            lines.append("---")

    return "\n".join(lines)


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
    challenge_type: str = "",
) -> List[Dict[str, Any]]:
    """快捷函数：搜索知识"""
    results = get_rag().search(query, category, top_k, challenge_type)

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

    # 【调整】只检索 experiences + skills，wooyun 不参与 RAG

    # 1. 主要来源：experiences（成功经验，最重要）
    exp_knowledge = search_knowledge(challenge_type, category="", top_k=5, challenge_type=challenge_type)

    # 2. 主要来源：skills（技能知识）
    skill_knowledge = search_knowledge(challenge_type, category="", top_k=8, challenge_type=challenge_type)

    # 去重合并
    seen = set()
    merged = []
    for item in exp_knowledge + skill_knowledge:
        key = item.get("title", "") + item.get("source", "")
        if key not in seen:
            seen.add(key)
            merged.append(item)

    # 同题型优先排序
    sorted_results = sort_by_type_priority(merged, challenge_type)

    # 结构化输出（最多 15 条）
    return format_structured_output(sorted_results[:15], challenge_type)


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
