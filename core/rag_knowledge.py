"""
RAG 知识检索 v2.0 - CTF Agent 直接模式组件
基于 BM25 + RRF (Reciprocal Rank Fusion) 的混合检索系统

检索流程：
1. 加载持久索引（rag_index/）
2. BM25 多源检索（各 source top 50）
3. RRF 融合
4. 来源加权 + 题型匹配加权
5. 去重 + 多样性保障
6. 格式化为 LLM 上下文

知识源（按优先级）：
1. memories/experiences/ - 历史成功经验（最高）
2. skills/ - 题型技能知识
3. knowledge_base/wooyun/ - WooYun 技术手册
4. knowledge_base/h-pentest/ - H-Pentest 攻击库
5. knowledge_base/PayloadsAllTheThings/ - PATT (只索引 README.md)
"""

import hashlib
import json
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ============================================================================
# 知识源配置
# ============================================================================

KNOWLEDGE_SOURCES = {
    "experiences": {
        "path": "memories/experiences/",
        "priority": 0,
        "type": "experience",
        "file_pattern": "*.md",
        "weight": 0.10,
    },
    "skills": {
        "path": "skills/",
        "priority": 1,
        "type": "skill",
        "file_pattern": "*/SKILL.md",
        "weight": 0.10,
    },
    "wooyun": {
        "path": "knowledge_base/wooyun/",
        "priority": 2,
        "type": "knowledge",
        "file_pattern": "**/*.md",
        "weight": 0.10,
    },
    "h-pentest": {
        "path": "knowledge_base/h-pentest/",
        "priority": 3,
        "type": "payload",
        "file_pattern": "*-攻击库.md",
        "weight": 0.10,
    },
    "patt": {
        "path": "knowledge_base/PayloadsAllTheThings/",
        "priority": 4,
        "type": "payload",
        "file_pattern": "**/README.md",
        "weight": 0.10,
    },
}

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent
RAG_INDEX_DIR = PROJECT_ROOT / "rag_index"
MANIFEST_FILE = RAG_INDEX_DIR / "manifest.json"
KB_STORE_FILE = RAG_INDEX_DIR / "kb_store.json"

# ============================================================================
# BM25 检索器
# ============================================================================

class BM25:
    """BM25 检索器 - 优于 TF-IDF 的词频饱和模型"""

    def __init__(self, k1: float = 1.2, b: float = 0.75):
        self.k1 = k1  # 词频饱和参数
        self.b = b    # 文档长度归一化参数

    def score(self, query_words: List[str], doc_words: List[str], avg_doc_len: float) -> float:
        """计算单个文档的 BM25 分数"""
        if not query_words or not doc_words:
            return 0.0

        doc_len = len(doc_words)
        doc_tf = Counter(doc_words)

        score = 0.0
        for term in query_words:
            if term not in doc_tf:
                continue
            tf = doc_tf[term]
            # BM25 公式
            numerator = tf * (self.k1 + 1)
            denominator = tf + self.k1 * (1 - self.b + self.b * doc_len / avg_doc_len)
            score += numerator / denominator

        return score

    def batch_search(
        self,
        query_words: List[str],
        documents: List[Tuple[str, List[str]]],
        top_k: int = 50
    ) -> List[Tuple[int, float]]:
        """
        批量检索

        Args:
            query_words: 查询词列表
            documents: [(doc_id, doc_words), ...]
            top_k: 返回前 k 条

        Returns:
            [(doc_index, score), ...] 按分数降序
        """
        if not documents:
            return []

        avg_doc_len = sum(len(d[1]) for d in documents) / len(documents)

        scores = []
        for i, (doc_id, doc_words) in enumerate(documents):
            s = self.score(query_words, doc_words, avg_doc_len)
            scores.append((i, s))

        # 按分数降序，返回 top_k
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]


# ============================================================================
# RRF 融合
# ============================================================================

def reciprocal_rank_fusion(
    rankings: List[List[Tuple[int, float]]],
    k: int = 60
) -> List[Tuple[int, float]]:
    """
    Reciprocal Rank Fusion - 多检索源结果融合

    Args:
        rankings: 多个检索源的排序列表，每项为 (doc_index, score) 元组
        k: 融合常数，默认 60

    Returns:
        按 RRF 综合分数排序的文档列表
    """
    rrf_scores = defaultdict(float)

    for ranking in rankings:
        for rank, (doc_idx, _) in enumerate(ranking):
            rrf_scores[doc_idx] += 1 / (k + rank + 1)  # +1 因为 rank 从 0 开始

    # 按 RRF 分数降序
    sorted_docs = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)
    return sorted_docs


# ============================================================================
# Chunk 数据类
# ============================================================================

@dataclass
class Chunk:
    """文档分块"""
    id: str           # "{doc_id}::chunk::{index}"
    content: str      # 分块内容
    doc_id: str       # 文档标识
    source: str       # experiences|skills|wooyun|h-pentest|patt
    vuln_type: str    # rce|sqli|lfi|... (从 frontmatter 或路径提取)
    chunk_type: str   # code|header|text|experience_record
    level: int        # 标题级别（0-6）
    position: int     # 位置索引
    has_code: bool   # 是否包含代码块
    has_proof: bool  # 是否有成功案例（experiences 专用）
    tags: List[str]  # 标签（experiences 从 frontmatter 提取）
    created: str      # 创建日期（experiences 专用）

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'Chunk':
        return cls(**d)


# ============================================================================
# Markdown 分块器
# ============================================================================

class MarkdownChunker:
    """Markdown 文档分块器"""

    min_chunk_size: int = 100
    max_chunk_size: int = 600    # 600 tokens (约 400 汉字)
    chunk_overlap: int = 80       # 10-20% overlap

    def chunk_file(
        self,
        file_path: Path,
        content: str,
        source: str,
        existing_metadata: Optional[dict] = None
    ) -> List[Chunk]:
        """
        将 Markdown 文件分块

        通用规则：
        1. 代码块（```...```）→ 保持完整，不拆分
        2. 标题层级（## / ###）→ 按标题分割
        3. 语义边界 → 按段落分割，保留重叠

        experiences 特殊规则：
        4. experiences 按 ## 二级标题分割，保留完整章节
        5. 每个 ## 标题下的内容作为一个 chunk
        6. chunk_type 标记为 "experience_record"
        """
        metadata = existing_metadata or {}
        doc_id = str(file_path.relative_to(PROJECT_ROOT))
        vuln_type = metadata.get('type', '') or self._extract_type_from_path(doc_id)
        tags = metadata.get('tags', [])
        created = metadata.get('created', '')

        # experiences 按 ## 二级标题分割
        if source == "experiences":
            return self._chunk_experiences(doc_id, content, source, vuln_type, tags, created)

        # skills/wooyun/h-pentest/patt 按标题和段落分割
        return self._chunk_generic(doc_id, content, source, vuln_type, tags, created)

    def _chunk_experiences(
        self,
        doc_id: str,
        content: str,
        source: str,
        vuln_type: str,
        tags: List[str],
        created: str
    ) -> List[Chunk]:
        """experiences 分块：按 ## 二级标题分割"""
        chunks = []

        # 移除 frontmatter
        content = re.sub(r'^---\n.*?\n---\n', '', content, flags=re.DOTALL)

        # 按 ## 分割大块
        major_parts = re.split(r"\n(?=##\s)", content)

        position = 0
        for major_idx, major in enumerate(major_parts):
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

            for sub_idx, sub in enumerate(sub_parts):
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
                    full_title = major_title or "未分类"

                # 提取代码块
                code_blocks = re.findall(r'```[\s\S]*?```', sub)
                has_code = len(code_blocks) > 0

                # 检查是否有成功案例（表格中有 Flag）
                has_proof = bool(re.search(r'FLAG\{[^}]+\}', sub))

                chunk_id = f"{doc_id}::chunk::{position}"
                chunk = Chunk(
                    id=chunk_id,
                    content=sub,
                    doc_id=doc_id,
                    source=source,
                    vuln_type=vuln_type,
                    chunk_type="experience_record",
                    level=3,  # ### 级别
                    position=position,
                    has_code=has_code,
                    has_proof=has_proof,
                    tags=tags,
                    created=created,
                )
                chunks.append(chunk)
                position += 1

        return chunks

    def _chunk_generic(
        self,
        doc_id: str,
        content: str,
        source: str,
        vuln_type: str,
        tags: List[str],
        created: str
    ) -> List[Chunk]:
        """通用分块：按标题和段落分割"""
        chunks = []

        # 移除 frontmatter
        content = re.sub(r'^---\n.*?\n---\n', '', content, flags=re.DOTALL)

        # 按 ## 分割
        sections = re.split(r"\n(?=##\s)", content)

        position = 0
        for sec_idx, section in enumerate(sections):
            section = section.strip()
            if not section:
                continue

            # 提取标题
            title_match = re.match(r"(#{1,6})\s+(.+)", section)
            if title_match:
                level = len(title_match.group(1))
                title = title_match.group(2).strip()
                body = re.sub(r"^#{1,6}\s+.+\n", "", section).strip()
            else:
                level = 0
                title = ""
                body = section

            if not body:
                continue

            # 提取代码块
            code_blocks = re.findall(r'```[\s\S]*?```', body)
            has_code = len(code_blocks) > 0

            # 检查是否有成功案例
            has_proof = bool(re.search(r'FLAG\{[^}]+\}', body))

            chunk_id = f"{doc_id}::chunk::{position}"
            chunk = Chunk(
                id=chunk_id,
                content=body,
                doc_id=doc_id,
                source=source,
                vuln_type=vuln_type,
                chunk_type="experience_record" if source == "experiences" else "text",
                level=level,
                position=position,
                has_code=has_code,
                has_proof=has_proof,
                tags=tags,
                created=created,
            )
            chunks.append(chunk)
            position += 1

        return chunks

    def _extract_type_from_path(self, file_path: str) -> str:
        """从文件路径中提取题型"""
        file_path = file_path.replace('\\', '/')

        patterns = [
            r'memories/experiences/([\w-]+)\.md$',
            r'skills/([\w-]+)/SKILL\.md$',
            r'knowledge/([\w-]+)\.md$',
            r'categories/([\w-]+)\.md$',
        ]

        for pattern in patterns:
            match = re.search(pattern, file_path)
            if match:
                return match.group(1).lower()

        return ""


# ============================================================================
# 持久化索引管理
# ============================================================================

class RAGIndexer:
    """RAG 持久化索引管理器"""

    def __init__(self):
        self.manifest: dict = {
            "version": "2.0",
            "last_updated": "",
            "sources": {},
            "documents": {},
        }
        self.kb_store: dict = {"chunks": []}
        self.chunker = MarkdownChunker()
        self._index_loaded = False

    def load_index(self) -> bool:
        """加载已有索引"""
        if self._index_loaded:
            return True

        if not MANIFEST_FILE.exists() or not KB_STORE_FILE.exists():
            return False

        try:
            with open(MANIFEST_FILE, 'r', encoding='utf-8') as f:
                self.manifest = json.load(f)

            with open(KB_STORE_FILE, 'r', encoding='utf-8') as f:
                self.kb_store = json.load(f)

            self._index_loaded = True
            return True
        except Exception:
            return False

    def save_manifest(self):
        """保存 manifest"""
        self.manifest["last_updated"] = datetime.now().isoformat()
        RAG_INDEX_DIR.mkdir(parents=True, exist_ok=True)
        with open(MANIFEST_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.manifest, f, ensure_ascii=False, indent=2)

    def save_kb_store(self):
        """保存 kb_store"""
        RAG_INDEX_DIR.mkdir(parents=True, exist_ok=True)
        with open(KB_STORE_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.kb_store, f, ensure_ascii=False, indent=2)

    def _compute_file_hash(self, path: Path) -> str:
        """计算文件 SHA-256 哈希"""
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return f"sha256:{sha256.hexdigest()[:16]}"

    def _parse_frontmatter(self, content: str) -> Tuple[dict, str]:
        """解析 frontmatter"""
        metadata = {}
        body = content

        if content.startswith('---'):
            parts = content.split('---', 2)
            if len(parts) >= 3:
                try:
                    import yaml
                    from datetime import date
                    metadata = yaml.safe_load(parts[1]) or {}
                    # 将 datetime.date 对象转换为字符串
                    if 'created' in metadata and isinstance(metadata['created'], date):
                        metadata['created'] = metadata['created'].strftime('%Y-%m-%d')
                except Exception:
                    pass
                body = parts[2].strip()

        return metadata, body

    def _chunk_document(
        self,
        file_path: Path,
        content: str,
        source: str
    ) -> List[Chunk]:
        """分块单个文档"""
        metadata, body = self._parse_frontmatter(content)
        return self.chunker.chunk_file(file_path, body, source, metadata)

    def build_index(self, force_rebuild: bool = False):
        """
        构建或更新 RAG 索引

        Args:
            force_rebuild: True = 完全重建, False = 增量更新
        """
        # 加载已有索引
        if not force_rebuild:
            self.load_index()

        if force_rebuild:
            self.manifest = {
                "version": "2.0",
                "last_updated": "",
                "sources": {},
                "documents": {},
            }
            self.kb_store = {"chunks": []}

        # 初始化 sources 统计（每次构建都重置）
        for source_name, config in KNOWLEDGE_SOURCES.items():
            self.manifest["sources"][source_name] = {
                "path": config["path"],
                "file_count": 0,
                "total_chunks": 0,
            }

        # 遍历所有知识源
        all_chunks = []
        for source_name, config in KNOWLEDGE_SOURCES.items():
            source_path = PROJECT_ROOT / config["path"]
            if not source_path.exists():
                continue

            source_file_count = 0
            source_chunks = []

            # 确定文件匹配模式
            pattern = config.get("file_pattern", "*.md")

            for file_path in source_path.glob(pattern):
                if not file_path.is_file():
                    continue

                # 计算文件哈希
                file_hash = self._compute_file_hash(file_path)
                file_key = str(file_path.relative_to(PROJECT_ROOT))

                # 增量更新：检查文件是否变化
                if not force_rebuild:
                    existing = self.manifest["documents"].get(file_key, {})
                    if existing.get("hash") == file_hash:
                        # 文件未变化，从旧索引中恢复 chunks
                        existing_chunks = existing.get("chunks", [])
                        for chunk_id in existing_chunks:
                            chunk = self._get_chunk_by_id(chunk_id)
                            if chunk:
                                source_chunks.append(chunk)
                        source_file_count += 1
                        continue

                # 读取并分块文件
                try:
                    content = file_path.read_text(encoding='utf-8')
                except Exception:
                    continue

                chunks = self._chunk_document(file_path, content, source_name)
                chunk_ids = [c.id for c in chunks]
                source_chunks.extend(chunks)

                # 更新文档记录
                self.manifest["documents"][file_key] = {
                    "hash": file_hash,
                    "mtime": int(file_path.stat().st_mtime),
                    "chunks": chunk_ids,
                }
                source_file_count += 1

            # 更新 source 统计
            self.manifest["sources"][source_name]["file_count"] = source_file_count
            self.manifest["sources"][source_name]["total_chunks"] = len(source_chunks)

            all_chunks.extend(source_chunks)

        # 保存索引（使用新 chunks 替换旧 kb_store）
        self.kb_store = {"chunks": [c.to_dict() for c in all_chunks]}
        self.save_manifest()
        self.save_kb_store()

        total_files = sum(s["file_count"] for s in self.manifest["sources"].values())
        print(f"索引构建完成: {len(all_chunks)} chunks, {total_files} 文件")

    def _get_chunk_by_id(self, chunk_id: str) -> Optional[Chunk]:
        """根据 ID 获取 chunk"""
        for chunk_dict in self.kb_store.get("chunks", []):
            if chunk_dict.get("id") == chunk_id:
                return Chunk.from_dict(chunk_dict)
        return None

    def get_all_chunks(self) -> List[Chunk]:
        """获取所有 chunks"""
        return [Chunk.from_dict(c) for c in self.kb_store.get("chunks", [])]

    def get_chunks_by_source(self, source: str) -> List[Chunk]:
        """获取指定源的 chunks"""
        return [
            Chunk.from_dict(c)
            for c in self.kb_store.get("chunks", [])
            if c.get("source") == source
        ]


# ============================================================================
# RAG 检索器
# ============================================================================

class RAGKnowledge:
    """
    v2.0 RAG 知识检索实现

    检索流程：
    1. BM25 多源检索 (各 source top 50)
    2. RRF 融合
    3. 来源 + 题型加权
    """

    def __init__(self):
        self.indexer = RAGIndexer()
        self.bm25 = BM25()
        self._jieba_available = self._check_jieba()

        # 尝试加载索引
        self.indexer.load_index()

    def _check_jieba(self) -> bool:
        """检查 jieba 是否可用"""
        try:
            import jieba
            jieba.initialize()
            return True
        except ImportError:
            return False

    def _tokenize(self, text: str) -> List[str]:
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
            "的", "了", "在", "是", "我", "有", "和", "就", "不", "人", "都", "一",
            "上", "也", "很", "到", "说", "要", "去", "你", "会", "着", "没有",
            "看", "好", "自己", "这", "那", "但", "却", "而", "与", "或", "之", "于",
        }
        return [w for w in words if w not in stopwords and len(w) > 1]

    def _calculate_final_score(
        self,
        doc: Chunk,
        query_type: str,
        rrf_score: float
    ) -> float:
        """
        计算综合评分：RRF分数 + 来源加权 + 题型匹配 + 特殊标记
        """
        # 1. 来源加权
        source_weights = {name: cfg["weight"] for name, cfg in KNOWLEDGE_SOURCES.items()}
        source_bonus = source_weights.get(doc.source, 0)

        # 2. 题型匹配加权
        type_bonus = 0.15 if doc.vuln_type == query_type else 0.0

        # 3. 特殊标记加权
        special_bonus = 0.0
        if doc.chunk_type == "experience_record":
            special_bonus += 0.05
        if doc.has_code:
            special_bonus += 0.03
        if doc.has_proof:
            special_bonus += 0.05

        return rrf_score + source_bonus + type_bonus + special_bonus

    def _bm25_search(
        self,
        source: str,
        query_words: List[str],
        top_k: int = 50
    ) -> List[Tuple[int, float]]:
        """对指定源进行 BM25 检索

        Returns:
            [(chunk_index, score), ...] - chunk_index 是 chunks 列表中的索引
        """
        chunks = self.indexer.get_chunks_by_source(source)

        if not chunks:
            return []

        # 准备文档：[(chunk_id, doc_words), ...]
        documents: List[Tuple[str, List[str]]] = []
        for chunk in chunks:
            doc_words = self._tokenize(chunk.content)
            documents.append((chunk.id, doc_words))

        # BM25 检索，返回 [(doc_index, score), ...]
        # doc_index 是 documents 列表中的索引（也是 chunks 列表中的对应索引）
        results = self.bm25.batch_search(query_words, documents, top_k=top_k)

        # batch_search 的 doc_index 直接对应 chunks 列表索引
        return results  # [(chunk_index, score), ...]

    def hybrid_search(
        self,
        query: str,
        query_type: str,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        v2.0 混合检索流程：
        1. BM25 多源检索 (各 source top 50)
        2. RRF 融合
        3. 应用来源 + 题型加权
        """
        query_words = self._tokenize(query)

        if not query_words:
            return []

        # Step 1: BM25 多源检索
        all_rankings = []
        source_chunks_map = {}  # source -> chunks list

        for source_name in KNOWLEDGE_SOURCES.keys():
            chunks = self.indexer.get_chunks_by_source(source_name)
            if chunks:
                source_chunks_map[source_name] = chunks
                rankings = self._bm25_search(source_name, query_words, top_k=50)
                all_rankings.append(rankings)

        # Step 2: RRF 融合
        if not all_rankings:
            return []

        fused = reciprocal_rank_fusion(all_rankings, k=60)

        # Step 3: 应用来源 + 题型加权
        scored = []
        for fused_rank, (global_idx, rrf_score) in enumerate(fused):
            # 找到对应的 chunk
            chunk = self._get_chunk_by_global_index(global_idx, source_chunks_map)
            if chunk is None:
                continue

            final_score = self._calculate_final_score(chunk, query_type, rrf_score)
            scored.append((chunk, final_score, fused_rank))

        # Step 4: 排序并返回 top_k
        scored.sort(key=lambda x: (x[1], x[2]), reverse=True)

        results = []
        for chunk, score, rank in scored[:top_k]:
            results.append({
                "id": chunk.id,
                "content": chunk.content,
                "doc_id": chunk.doc_id,
                "source": chunk.source,
                "vuln_type": chunk.vuln_type,
                "chunk_type": chunk.chunk_type,
                "has_code": chunk.has_code,
                "has_proof": chunk.has_proof,
                "tags": chunk.tags,
                "created": chunk.created,
                "score": round(score, 4),
                "rank": rank,
            })

        return results

    def _get_chunk_by_global_index(
        self,
        global_idx: int,
        source_chunks_map: Dict[str, List[Chunk]]
    ) -> Optional[Chunk]:
        """根据全局索引获取 chunk"""
        count = 0
        for source, chunks in source_chunks_map.items():
            for chunk in chunks:
                if count == global_idx:
                    return chunk
                count += 1
        return None

    def search(
        self,
        query: str,
        category: str = "",
        top_k: int = 5,
        challenge_type: str = "",
    ) -> List[Dict[str, Any]]:
        """
        检索知识库（兼容旧接口）

        Args:
            query: 查询字符串
            category: 映射后的类别
            top_k: 返回前 k 条
            challenge_type: 原始题型

        Returns:
            [{"title": ..., "content": ..., "relevance": float, "source": ...}]
        """
        # 使用 challenge_type 作为查询类型
        query_type = challenge_type or category

        # 混合检索
        results = self.hybrid_search(query, query_type, top_k)

        # 转换为旧接口格式
        formatted = []
        for r in results:
            # 从 content 中提取标题
            title = self._extract_title_from_content(r["content"])
            formatted.append({
                "title": title,
                "method": "",  # 旧接口不使用
                "content": r["content"],
                "relevance": r["score"],
                "source": r["source"],
                "file": r["doc_id"],
                "tags": r.get("tags", []),
                "has_proof": r.get("has_proof", False),
            })

        return formatted

    def _extract_title_from_content(self, content: str) -> str:
        """从内容中提取标题"""
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('#'):
                continue
            if line and len(line) > 5:
                return line[:100]
        return "未分类"


# ============================================================================
# 题型相似性
# ============================================================================

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


def is_similar_type(t1: str, t2: str) -> bool:
    """判断两个题型是否相似"""
    t1_lower = t1.lower()
    t2_lower = t2.lower()

    if t1_lower == t2_lower:
        return True

    for base, aliases in SIMILAR_TYPES.items():
        all_types = [base] + aliases
        if t1_lower in all_types and t2_lower in all_types:
            return True

    return False


# ============================================================================
# 输出格式化
# ============================================================================

def sort_by_type_priority(results: List[Dict], challenge_type: str) -> List[Dict]:
    """按题型优先级排序"""

    def get_priority(item: Dict) -> tuple:
        source = item.get("source", "")
        file_path = item.get("file", "")
        item_type = _extract_type_from_path(file_path)

        is_same = is_similar_type(item_type, challenge_type)

        source_priority_map = {"experiences": 0, "skills": 1, "wooyun": 2, "h-pentest": 2, "patt": 2}
        source_priority = source_priority_map.get(source, 3)

        type_priority = 0 if is_same else 1

        return (type_priority, source_priority)

    return sorted(results, key=get_priority)


def _extract_type_from_path(file_path: str) -> str:
    """从文件路径中提取题型"""
    file_path = file_path.replace('\\', '/')

    patterns = [
        r'memories/experiences/([\w-]+)\.md$',
        r'skills/([\w-]+)/SKILL\.md$',
        r'knowledge/([\w-]+)\.md$',
        r'categories/([\w-]+)\.md$',
    ]

    for pattern in patterns:
        match = re.search(pattern, file_path)
        if match:
            return match.group(1).lower()

    return ""


def format_structured_output(results: List[Dict], challenge_type: str) -> str:
    """生成结构化输出，直接喂给 LLM"""
    def to_str(val):
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
        item_type = _extract_type_from_path(file_path)
        is_same = is_similar_type(item_type, challenge_type)

        key = None
        if is_same:
            if source == "experiences":
                key = "experiences_same"
            elif source == "skills":
                key = "skills_same"
            elif source in ("wooyun", "h-pentest", "patt"):
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
            if item.get('has_proof'):
                lines.append(f"**成功案例**: 有 FLAG 记录")
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
        lines.append("\n## 【KNOWLEDGE - 同题型】")
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


# ============================================================================
# 全局实例和接口函数
# ============================================================================

_rag_instance: Optional[RAGKnowledge] = None
_indexer_instance: Optional[RAGIndexer] = None


def get_rag() -> RAGKnowledge:
    """获取 RAG 实例（单例）"""
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = RAGKnowledge()
    return _rag_instance


def get_indexer() -> RAGIndexer:
    """获取 Indexer 实例（单例）"""
    global _indexer_instance
    if _indexer_instance is None:
        _indexer_instance = RAGIndexer()
    return _indexer_instance


def build_rag_index(force_rebuild: bool = False):
    """构建或更新 RAG 索引"""
    indexer = get_indexer()
    indexer.build_index(force_rebuild=force_rebuild)


def get_rag_stats() -> dict:
    """获取知识库统计"""
    indexer = get_indexer()
    indexer.load_index()

    return {
        "total_chunks": len(indexer.kb_store.get("chunks", [])),
        "sources": indexer.manifest.get("sources", {}),
        "last_updated": indexer.manifest.get("last_updated", ""),
        "version": indexer.manifest.get("version", "unknown"),
    }


def register_knowledge_source(name: str, path: str, priority: int = 5):
    """注册新的知识目录，自动构建索引"""
    global KNOWLEDGE_SOURCES

    KNOWLEDGE_SOURCES[name] = {
        "path": path,
        "priority": priority,
        "type": "custom",
        "file_pattern": "*.md",
        "weight": 0.05,
    }

    # 重建索引
    build_rag_index(force_rebuild=True)


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
            marker_file = PROJECT_ROOT / "workspace" / ".knowledge_checked"
            marker_file.parent.mkdir(parents=True, exist_ok=True)
            marker_file.touch()
        except Exception:
            pass

    return results


def get_all_type_knowledge(challenge_type: str) -> str:
    """
    获取指定题型的全部知识（供 LLM 使用）

    同时检索：
    1. memories/experiences/<type>.md - 历史成功经验
    2. skills/<type>/SKILL.md - 题型技能知识
    3. knowledge_base/wooyun/ - WooYun 技术手册
    4. knowledge_base/h-pentest/ - H-Pentest 攻击库
    5. knowledge_base/PayloadsAllTheThings/ - PATT

    Args:
        challenge_type: 题型（如 "rce", "sqli"）

    Returns:
        格式化好的知识文本
    """
    # 记录知识调用日志（供 Hook 验证）
    try:
        log_file = PROJECT_ROOT / "workspace" / ".knowledge_log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"{time.time()}|get_all_type_knowledge|{challenge_type}\n")
    except Exception:
        pass

    # 检索所有来源
    results = get_rag().search(
        query=challenge_type,
        category="",
        top_k=15,
        challenge_type=challenge_type
    )

    # 同题型优先排序
    sorted_results = sort_by_type_priority(results, challenge_type)

    # 结构化输出
    return format_structured_output(sorted_results, challenge_type)


def get_knowledge_for_llm(query: str, category: str = "", top_k: int = 10) -> str:
    """获取格式化好的知识文本，直接供 LLM 使用"""
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
        "h-pentest": "【攻击库】",
        "patt": "【PATT】",
    }

    for source_name, items in sources.items():
        name = source_names.get(source_name, f"【{source_name}】")
        lines.append(f"\n{name}\n")
        lines.append("-" * 40)

        for i, item in enumerate(items, 1):
            title = item.get("title", "")
            content = item.get("content", "")
            relevance = item.get("relevance", 0)

            lines.append(f"\n[{i}] {title}")
            lines.append(f"    相关度: {relevance:.2f}")
            lines.append(f"    内容: {content[:300]}..." if len(content) > 300 else f"    内容: {content}")

    lines.append("\n=== 知识检索结束 ===")
    return "\n".join(lines)


def format_knowledge_results(results: List[Dict[str, Any]]) -> str:
    """将检索结果格式化为易读文本"""
    if not results:
        return ""

    lines = ["=== 相关知识 ===\n"]

    for i, item in enumerate(results, 1):
        title = item.get("title", "")
        content = item.get("content", "")
        source = item.get("source", "")
        file_path = item.get("file", "")

        lines.append(f"\n【{i}】{title}")
        lines.append(f"    来源: {source} -> {file_path}")
        if len(content) > 400:
            content = content[:400] + "..."
        lines.append(f"    {content}")

    lines.append("\n=== 知识结束 ===")
    return "\n".join(lines)
