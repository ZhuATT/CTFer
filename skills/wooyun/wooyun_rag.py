"""
WooYun RAG 检索引擎
=================

职责：
- 构建和维护WooYun知识库的索引
- 提供统一的RAG检索接口 retrieve_knowledge()
- 基于BM25相似度的轻量级检索（无外部依赖）
- 支持题目上下文增强

作者：Claude Code
日期：2026-03-18
"""

import re
import json
import math
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# WooYun仓库路径
WOOYUN_PATH = Path("wooyun")
KNOWLEDGE_PATH = WOOYUN_PATH / "knowledge"
CATEGORIES_PATH = WOOYUN_PATH / "categories"
EXAMPLES_PATH = WOOYUN_PATH / "examples"
CACHE_PATH = Path(".cache")
INDEX_FILE = CACHE_PATH / "wooyun_index.json"

# 日志配置
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BM25:
    """
    BM25算法实现（轻量级，无依赖）
    参考：https://en.wikipedia.org/wiki/Okapi_BM25
    """

    def __init__(self, k1=1.5, b=0.75):
        self.k1 = k1
        self.b = b
        self.avg_doc_len = 0
        self.doc_freq = {}
        self.idf = {}

    def fit(self, documents: List[str]):
        """计算IDF"""
        n_docs = len(documents)
        doc_lens = []

        # 统计文档频率
        for doc in documents:
            tokens = self.tokenize(doc)
            doc_lens.append(len(tokens))
            unique_tokens = set(tokens)

            for token in unique_tokens:
                self.doc_freq[token] = self.doc_freq.get(token, 0) + 1

        self.avg_doc_len = sum(doc_lens) / n_docs

        # 计算IDF
        for token, freq in self.doc_freq.items():
            self.idf[token] = math.log((n_docs - freq + 0.5) / (freq + 0.5) + 1)

    def score(self, query: str, document: str) -> float:
        """计算BM25评分"""
        if not self.idf:
            return 0.0

        query_tokens = self.tokenize(query)
        doc_tokens = self.tokenize(document)
        doc_len = len(doc_tokens)
        doc_token_counts = {}

        # 统计文档中词频
        for token in doc_tokens:
            doc_token_counts[token] = doc_token_counts.get(token, 0) + 1

        score = 0.0
        for token in query_tokens:
            if token not in self.idf:
                continue

            tf = doc_token_counts.get(token, 0)
            numerator = tf * (self.k1 + 1)
            denominator = tf + self.k1 * (1 - self.b + self.b * doc_len / self.avg_doc_len)

            score += self.idf[token] * numerator / denominator

        return score

    @staticmethod
    def tokenize(text: str) -> List[str]:
        """简单的分词（转为小写，按非字母数字分割）"""
        return re.findall(r'[a-z0-9]+', text.lower())


class WooyunRAGEngine:
    """WooYun RAG检索引擎"""

    def __init__(self):
        self.index = None
        self.bm25 = BM25()
        self.loaded = False

    def build_index(self, force_rebuild: bool = False) -> bool:
        """
        构建或加载索引

        Args:
            force_rebuild: 强制重建索引

        Returns:
            成功返回True
        """
        try:
            # 如果索引已存在且不重
            if INDEX_FILE.exists() and not force_rebuild:
                self._load_index()
                return True

            # 创建缓存目录
            CACHE_PATH.mkdir(exist_ok=True)

            # 开始构建索引（限25）
            logger.info("正在构建WooYun索引...")
            logger.info(f"扫描目录: {KNOWLEDGE_PATH}")

            index = {
                "version": "1.0",
                "generated_at": "2026-03-18T00:00:00",
                "total_entries": 0,
                "knowledge": {},
                "cases": {},
                "examples": {}
            }

            # 1. 解析knowledge文件（重点）
            self._parse_knowledge(index)

            # 2. 解析categories案例摘要（只取前50个）
            self._parse_categories(index, limit=50)

            # 3. 解析examples
            self._parse_examples(index)

            # 4. 保存索引
            with open(INDEX_FILE, 'w', encoding='utf-8') as f:
                json.dump(index, f, ensure_ascii=False, indent=2)

            self.index = index
            self.loaded = True

            logger.info(f"索引构建完成！总计 {index['total_entries']} 条记录")
            return True

        except Exception as e:
            logger.error(f"构建索引失败: {e}")
            return False

    def _load_index(self):
        """加载索引"""
        try:
            with open(INDEX_FILE, 'r', encoding='utf-8') as f:
                self.index = json.load(f)
            self.loaded = True
            logger.info(f"索引加载完成，共 {self.index['total_entries']} 条记录")
        except Exception as e:
            logger.error(f"加载索引失败: {e}")

    def _parse_knowledge(self, index: Dict[str, Any]):
        """解析knowledge目录"""
        if not KNOWLEDGE_PATH.exists():
            logger.warning(f"knowledge目录不存在: {KNOWLEDGE_PATH}")
            return

        total_parsed = 0

        for knowledge_file in KNOWLEDGE_PATH.glob("*.md"):
            vuln_type = knowledge_file.stem
            logger.info(f"解析: {knowledge_file}")

            with open(knowledge_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # 提取高频参数
            high_freq_params = self._extract_table_data(
                content,
                r'## 一.*漏洞参数.*\n\n.*?\n\n([^#]*)',
                ["参数名", "出现次数", "典型场景"]
            )

            # 提取Payload模式
            payload_patterns = self._extract_code_blocks(content, r'```\w*\n(.*?)\n```')

            # 提取攻击策略
            attack_strategies = self._extract_list_items(content, r'.*策略.*\n\n\n(\d+\..*?\n)\n\n')

            index["knowledge"][vuln_type] = {
                "metadata": {
                    "source": str(knowledge_file),
                    "file_size": len(content),
                    "last_modified": ""
                },
                "high_freq_params": high_freq_params[:20],  # 只保留20条
                "payload_patterns": payload_patterns[:50],  # 只保留50条
                "attack_strategies": attack_strategies[:20]
            }

            total_parsed += len(high_freq_params) + len(payload_patterns)

        index["total_entries"] += total_parsed
        logger.info(f"knowledge解析完成，共 {total_parsed} 条记录")

    def _parse_categories(self, index: Dict[str, Any], limit: int = 50):
        """解析categories案例（只提取前N个）"""
        if not CATEGORIES_PATH.exists():
            logger.warning(f"categories目录不存在: {CATEGORIES_PATH}")
            return

        total_cases = 0

        for category_file in CATEGORIES_PATH.glob("*.md"):
            vuln_type = category_file.stem
            logger.info(f"提取案例摘要: {category_file}")

            with open(category_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # 按标题分割案例（假设以"## "或"### "开头）
            case_pattern = r'##?\s+([^\n]+)\n\n([^#]{0,500})'
            matches = re.findall(case_pattern, content)[:limit]

            cases = []
            for match in matches:
                title = match[0]
                description = match[1]

                # 提取关键信息
                severity = "未知"
                date_match = re.search(r'(\d{4})-(\d{2})-(\d{2})', title)
                date = date_match.group(0) if date_match else "未知"

                cases.append({
                    "id": f"{vuln_type}_{len(cases)+1}",
                    "title": title[:200],
                    "preview": description[:300].strip(),
                    "severity": severity,
                    "date": date,
                    "keywords": self._extract_keywords(title + " " + description)
                })

            index["cases"][vuln_type] = {
                "total_available": len(matches),
                "sample_cases": cases
            }

            total_cases += len(matches)

        index["total_entries"] += total_cases
        logger.info(f"categories解析完成，共 {total_cases} 个案例")

    def _parse_examples(self, index: Dict[str, Any]):
        """解析examples"""
        if not EXAMPLES_PATH.exists():
            logger.warning(f"examples目录不存在: {EXAMPLES_PATH}")
            return

        total_examples = 0

        for example_file in EXAMPLES_PATH.glob("*.md"):
            field_type = example_file.stem.replace("-penetration", "")
            logger.info(f"解析实例: {example_file}")

            with open(example_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # 提取标题和关键点
            title_match = re.search(r'^#\s+(.+)', content)
            title = title_match.group(1) if title_match else example_file.stem

            key_points = self._extract_list_items(content, r'\n#\s+[^\n]+\n\n([^#]{0,1000})')

            index["examples"][field_type] = {
                "title": title,
                "file": str(example_file),
                "key_points": key_points[:30],
                "full_content": content[:2000]  # 保存前2000字符
            }

            total_examples += 1

        index["total_entries"] += total_examples
        logger.info(f"examples解析完成，共 {total_examples} 个实例")

    @staticmethod
    def _extract_table_data(content: str, pattern: str, headers: List[str]) -> List[Dict[str, Any]]:
        """提取表格数据"""
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            return []

        table_text = match.group(1)
        rows = []

        # 简单的表格解析
        for line in table_text.split('\n'):
            if '|' in line and '---' not in line:
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if len(cells) == len(headers):
                    row = {}
                    for i, header in enumerate(headers):
                        row[header] = cells[i]
                    rows.append(row)

        return rows

    @staticmethod
    def _extract_code_blocks(content: str, pattern: str) -> List[str]:
        """提取代码块"""
        matches = re.findall(pattern, content, re.DOTALL)
        return [m.strip()[:1000] for m in matches]

    @staticmethod
    def _extract_list_items(content: str, pattern: str) -> List[str]:
        """提取列表项"""
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            return []

        text = match.group(1)
        items = [item.strip()[:200] for item in re.findall(r'^(\d+\.|\*)\s+(.+)', text, re.MULTILINE)]
        return items

    @staticmethod
    def _extract_keywords(text: str) -> List[str]:
        """提取关键词"""
        # 简单关键词提取：长度>2的单词
        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        return list(set(words))[:20]

    def retrieve_knowledge(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
        top_k: int = 3
) -> Dict[str, Any]:
        """
        RAG检索主接口

        Args:
            query: 用户查询（如"SQL注入如何绕过"）
            context: 题目上下文
                {
                    "current_vuln_type": "sqli",
                    "target_url": "http://target.com",
                    "tech_stack": ["PHP", "MySQL"],
                    "attempted_methods": ["union注入"],
                    "problem_description": "登录页面"
                }
            top_k: 返回Top-K条

        Returns:
            {
                "query": "...",
                "context": {...},
                "retrieved_knowledge": [
                    {
                        "source": "knowledge/sql-injection.md",
                        "type": "payload",
                        "content": "...",
                        "relevance_score": 0.93
                    }
                ],
                "suggested_approach": "..."
            }
        """
        if not self.loaded:
            self.build_index()

        if not self.index:
            return {"error": "索引未加载", "retrieved_knowledge": []}

        results = {
            "query": query,
            "context": context,
            "retrieved_knowledge": [],
            "suggested_approach": ""
        }

        # 从context获取当前漏洞类型
        vuln_type = context.get("current_vuln_type", "") if context else ""

        # 步骤1: 检索候选
        candidates = self._search_candidates(query, vuln_type)

        # 步骤2: 评分排序（BM25 + 上下文增强）
        scored = []
        for candidate in candidates:
            score = self.bm25.score(query, str(candidate.get("content", "")))
            # 如果context匹配，加分
            if self._context_match(candidate, context):
                score += 0.3

            scored.append((candidate, score))

        # 排序
        scored.sort(key=lambda x: x[1], reverse=True)

        # 步骤3: 返回Top-K
        for candidate, score in scored[:top_k]:
            candidate["relevance_score"] = round(score, 3)
            results["retrieved_knowledge"].append(candidate)

        # 步骤4: 生成建议
        results["suggested_approach"] = self._generate_suggestion(results["retrieved_knowledge"])

        return results

    def _search_candidates(self, query: str, vuln_type: str = "") -> List[Dict[str, Any]]:
        """搜索候选项"""
        candidates = []

        # 1. 从knowledge中搜索
        if vuln_type and vuln_type in self.index.get("knowledge", {}):
            knowledge_entry = self.index["knowledge"][vuln_type]

            # 添加payload
            for payload in knowledge_entry.get("payload_patterns", [])[:20]:
                candidates.append({
                    "source": f"knowledge/{vuln_type}.md",
                    "type": "payload",
                    "content": payload[:500]
                })

            # 添加攻击策略
            for strategy in knowledge_entry.get("attack_strategies", []):
                candidates.append({
                    "source": f"knowledge/{vuln_type}.md",
                    "type": "technique",
                    "content": strategy[:500]
                })

            # 添加高频参数
            for param in knowledge_entry.get("high_freq_params", [])[:10]:
                candidates.append({
                    "source": f"knowledge/{vuln_type}.md",
                    "type": "parameter",
                    "content": f"参数: {param.get('参数名', 'unknown')}, 场景: {param.get('典型场景', 'unknown')}"
                })

        # 2. 从cases中搜索相关案例
        if vuln_type in self.index.get("cases", {}):
            cases_entry = self.index["cases"][vuln_type]
            for case in cases_entry.get("sample_cases", [])[:10]:
                if any(keyword in query.lower() for keyword in case.get("keywords", [])):
                    candidates.append({
                        "source": f"cases/{vuln_type}.md",
                        "type": "case",
                        "content": f"案例: {case.get('title', '')}, 严重程度: {case.get('severity', '未知')}"
                    })

        # 3. 如果没指定具体类型，搜索所有类型
        if not vuln_type:
            for type_name in self.index.get("knowledge", {}).keys():
                if type_name in query.lower():
                    type_entry = self.index["knowledge"][type_name]
                    for payload in type_entry.get("payload_patterns", [])[:5]:
                        candidates.append({
                            "source": f"knowledge/{type_name}.md",
                            "type": "payload",
                            "content": payload[:300]
                        })

        return candidates

    @staticmethod
    def _context_match(candidate: Dict[str, Any], context: Optional[Dict[str, Any]]) -> bool:
        """检查上下文匹配"""
        if not context:
            return False

        content = candidate.get("content", "").lower()

        # 技术栈匹配
        tech_stack = context.get("tech_stack", [])
        for tech in tech_stack:
            if tech.lower() in content:
                return True

        # 已尝试方法匹配
        attempted = context.get("attempted_methods", [])
        for method in attempted:
            if method.lower() in content:
                return True

        return False

    @staticmethod
    def _generate_suggestion(retrieved: List[Dict[str, Any]]) -> str:
        """基于检索结果生成建议"""
        if not retrieved:
            return "暂无具体建议，请尝试基础Payload"

        suggestion = []

        # 按类型统计
        type_count = {}
        for item in retrieved:
            item_type = item.get("type", "unknown")
            type_count[item_type] = type_count.get(item_type, 0) + 1

        # 生成建议文本
        if "payload" in type_count:
            suggestion.append("建议使用检索到的Payload进行测试")
        if "technique" in type_count:
            suggestion.append("参考WooYun案例的攻击技术")
        if "case" in type_count:
            suggestion.append("参考类似真实案例的利用思路")
        if "parameter" in type_count:
            suggestion.append("重点测试高频漏洞参数")

        return ", ".join(suggestion[:2]) if suggestion else "请结合上下文调整Payload"


# 全局引擎实例
_wooyun_engine = WooyunRAGEngine()


def build_wooyun_index():
    """构建WooYun索引（提供给外部调用）"""
    return _wooyun_engine.build_index()


def retrieve_knowledge(
        query: str,
        context: Optional[Dict[str, Any]] = None,
        top_k: int = 3
) -> Dict[str, Any]:
    """
    RAG检索主接口（统一入口）

    Args:
        query: 查询语句
        context: 题目上下文
        top_k: 返回Top-K条

    Returns:
        RAG检索结果
    """
    return _wooyun_engine.retrieve_knowledge(query, context, top_k)


