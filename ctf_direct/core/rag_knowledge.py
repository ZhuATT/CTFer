"""
RAG 知识检索 - 直接模式组件
基于关键词的简单 RAG，从 wooyun knowledge 目录检索相似题目知识
从 H-Pentest `tools/knowledge.py` 简化迁移
"""
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


class RAGKnowledge:
    """
    简单的关键词 + 相似度 RAG 实现

    检索流程：
    1. 关键词匹配 → 2. 句子级相似度 → 3. 返回 top_k 结果
    """

    def __init__(self, knowledge_dir: Optional[str] = None):
        """
        Args:
            knowledge_dir: 知识库目录，默认使用 wooyun/knowledge/
        """
        if knowledge_dir is None:
            # 默认使用主项目的 wooyun 知识库
            project_root = Path(__file__).parent.parent.parent
            knowledge_dir = str(project_root / "wooyun" / "knowledge")

        self.knowledge_dir = Path(knowledge_dir)
        self.cache = {}  # 简单文件缓存

    def search(
        self,
        query: str,
        category: str = "",
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        检索相关知识

        Args:
            query: 查询字符串
            category: 可选，限定类别（如 "command-execution"）
            top_k: 返回前 k 条

        Returns:
            [{"title": ..., "method": ..., "content": ..., "relevance": float}]
        """
        if not self.knowledge_dir.exists():
            return []

        query_keywords = self._extract_keywords(query)

        # 确定要搜索的文件
        if category:
            files = [self.knowledge_dir / f"{category}.md"]
        else:
            files = list(self.knowledge_dir.glob("*.md"))

        results = []

        for file_path in files:
            if not file_path.exists():
                continue

            content = self._read_file(file_path)
            sections = self._split_sections(content)

            for section in sections:
                score = self._calculate_relevance(query_keywords, section["content"])
                if score > 0:
                    results.append({
                        "title": section["title"] or file_path.stem,
                        "method": section.get("method", ""),
                        "content": section["content"][:500],  # 限制长度
                        "relevance": score,
                        "category": file_path.stem,
                    })

        # 排序并返回 top_k
        results.sort(key=lambda x: x["relevance"], reverse=True)
        return results[:top_k]

    def _extract_keywords(self, text: str) -> List[str]:
        """从文本中提取关键词"""
        # 移除标点，转小写，分词
        text = re.sub(r"[^\w\s]", " ", text.lower())
        words = text.split()
        # 过滤停用词和短词
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

    def _calculate_relevance(self, query_keywords: List[str], content: str) -> float:
        """计算查询与内容的相似度"""
        content_lower = content.lower()
        content_words = set(re.findall(r"\w+", content_lower))

        if not query_keywords:
            return 0.0

        matched = sum(1 for kw in query_keywords if kw in content_words)
        return matched / len(query_keywords)


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
    return get_rag().search(query, category, top_k)
