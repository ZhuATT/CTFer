"""
Markdown分块器 - 支持结构化和语义分块

功能:
- 按Markdown结构分层分块（标题、段落、代码块、列表）
- 支持语义分块（句子边界、语义完整性）
- 生成统一的chunk ID机制
"""

import re
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass


@dataclass
class Chunk:
    """分块数据结构。"""

    id: str  # 统一格式: {doc_id}::chunk::{chunk_index}
    content: str
    metadata: Dict[str, Any]
    doc_id: str
    chunk_index: int
    chunk_type: str = "text"  # 分块类型: text, code, header, etc.
    level: int = 0  # 层级（用于标题级别）
    position: int = 0  # 位置索引


class MarkdownChunker:
    """文档分块器 - 通用Markdown分块处理。"""

    def __init__(self, min_chunk_size: int = 60, max_chunk_size: int = 512, chunk_overlap: int = 64):
        self.min_chunk_size = min_chunk_size
        self.max_chunk_size = max_chunk_size
        self.chunk_overlap = chunk_overlap
        if self.chunk_overlap >= self.max_chunk_size:
            raise ValueError("chunk_overlap must be smaller than max_chunk_size.")

    def _split_by_headers(self, content: str) -> List[Tuple[str, str]]:
        """按Markdown标题分割。"""
        # 匹配各级标题
        header_pattern = r"^(#{1,6})\s+(.+)$"
        parts = []
        current_header = ""
        current_content = []

        lines = content.split("\n")
        for line in lines:
            if re.match(header_pattern, line.strip()):
                # 如果已经有内容，保存当前部分
                if current_content or current_header:
                    parts.append((current_header, "\n".join(current_content)))
                current_header = line.strip()
                current_content = []
            else:
                current_content.append(line)

        # 保存最后一部分
        if current_content or current_header:
            parts.append((current_header, "\n".join(current_content)))

        return parts

    def _split_by_code_blocks(self, content: str) -> List[str]:
        """
        按代码块分割并保留代码块本身。
        返回的列表包含普通文本段和代码段，顺序一致。
        """
        # 使用捕获组，使得re.split保留分隔符（即代码块本身）
        # [\s\S]*? 允许跨行非贪婪匹配，确保捕获完整的``` ... ```代码段
        code_block_pattern = r"(```[\s\S]*?```)"  # 捕获所有代码块，包括内部换行
        parts = re.split(code_block_pattern, content)
        # 去除空字符串，保持原始顺序
        return [p for p in parts if p]

    def _split_by_semantic_boundaries(self, content: str) -> List[str]:
        """按语义边界分割（句子、段落），并支持重叠。"""
        # 使用更通用的文本分割器，例如按句子或段落
        # 这里为了简化，我们仍然以段落为基础，但逻辑会改变
        
        # 简单的按字符分割，更可靠的实现需要考虑句子边界
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.max_chunk_size,
            chunk_overlap=self.chunk_overlap,
            length_function=len,
        )
        return text_splitter.split_text(content)

    def chunk(self, doc_id: str, content: str) -> List[Chunk]:
        """
        将Markdown文档内容分块。
        这个实现是一个简化的例子，可以根据需要扩展。
        """
        # 这是一个简化的chunk逻辑，实际应用中可能需要更复杂的结构化解析
        # 例如，先按标题分割，再在每个部分内按代码和语义分割
        
        # 示例：直接使用语义边界分割
        text_chunks = self._split_by_semantic_boundaries(content)
        
        chunks = []
        for i, text_chunk in enumerate(text_chunks):
            if not text_chunk.strip():
                continue
            
            chunk_id = f"{doc_id}::chunk::{i}"
            chunks.append(
                Chunk(
                    id=chunk_id,
                    content=text_chunk,
                    metadata={"source": doc_id},
                    doc_id=doc_id,
                    chunk_index=i,
                    chunk_type="text",
                    position=i, # 简化处理
                )
            )
            
        return chunks


# 为了实现重叠分块，我们需要一个文本分割器
# 这里我们引入一个简化的 RecursiveCharacterTextSplitter 概念
# 在实际项目中，可以考虑使用成熟的库如 langchain.text_splitter
class RecursiveCharacterTextSplitter:
    def __init__(self, chunk_size: int = 512, chunk_overlap: int = 64, length_function=len):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self._length_function = length_function

    def split_text(self, text: str) -> List[str]:
        if len(text) <= self.chunk_size:
            return [text]

        chunks = []
        start_index = 0
        while start_index < len(text):
            end_index = start_index + self.chunk_size
            chunk = text[start_index:end_index]
            chunks.append(chunk)
            
            # 如果已经是最后一块，则退出
            if end_index >= len(text):
                break
                
            # 移动到下一个块的起始位置
            start_index += self.chunk_size - self.chunk_overlap
            
        return chunks

        if current_chunk:
            chunks.append("\n\n".join(current_chunk))

        return chunks

    def _generate_chunk_id(self, doc_id: str, chunk_index: int) -> str:
        """生成统一的chunk ID。"""
        return f"{doc_id}::chunk::{chunk_index:04d}"

    def chunk_document(self, doc_id: str, content: str) -> List[Chunk]:
        """
        主分块方法 - 优化分块策略。
        1. 首先按代码块分割，保护代码完整性
        2. 然后按语义边界分割，优先保持内容连贯性
        3. 最后合并标题信息，避免过度分割
        """
        all_chunks = []
        chunk_index = 0

        # 第一层：按代码块分割（保护代码完整性，保留代码块本身）
        code_parts = self._split_by_code_blocks(content)

        for part in code_parts:
            part_stripped = part.strip()
            is_code_block = part_stripped.startswith("```") and part_stripped.endswith("```")

            # 如果是代码块，直接作为一个整体chunk，不再做语义拆分
            if is_code_block:
                header = self._extract_relevant_header(part, content)
                merged_content = part  # 代码块保持原样
                if header and header.strip() and not merged_content.strip().startswith(header.strip()):
                    merged_content = f"{header.strip()}\n\n{merged_content}"

                if len(merged_content.strip()) < self.min_chunk_size:
                    # 对于代码块，即使很短也保留，保持代码完整性
                    pass

                chunk_id = self._generate_chunk_id(doc_id, chunk_index)
                metadata = {
                    "header": header or "",
                    "has_code": True,
                    "length": len(merged_content),
                    "word_count": len(merged_content.split()),
                }
                chunk = Chunk(
                    id=chunk_id,
                    content=merged_content,
                    metadata=metadata,
                    doc_id=doc_id,
                    chunk_index=chunk_index,
                    chunk_type="code",
                    level=header.count("#") if header and header.startswith("#") else 0,
                    position=chunk_index,
                )
                all_chunks.append(chunk)
                chunk_index += 1
                continue  # 处理下一个part

            # 非代码文本，继续按语义边界分块
            semantic_chunks = self._split_by_semantic_boundaries(part)

            for chunk_content in semantic_chunks:
                # 提取当前块的标题信息（如果有）
                header = self._extract_relevant_header(chunk_content, content)

                # 合并标题信息
                merged_content = chunk_content
                if header and header.strip():
                    h = header.strip()
                    # 避免重复：若标题已包含在内容开头，不再合并
                    if not merged_content.strip().startswith(h):
                        merged_content = f"{h}\n\n{merged_content}"

                # 跳过太小的块
                mc = merged_content.strip()
                if len(mc) < self.min_chunk_size:
                    continue

                # 创建chunk
                chunk_id = self._generate_chunk_id(doc_id, chunk_index)

                metadata = {
                    "header": header or "",
                    "has_code": "```" in merged_content,
                    "length": len(merged_content),
                    "word_count": len(merged_content.split()),
                }

                # 确定分块类型
                chunk_type = "text"
                if "```" in merged_content:
                    chunk_type = "code"
                elif header and header.startswith("#"):
                    chunk_type = "header"

                # 确定层级（标题级别）
                level = 0
                if header and header.startswith("#"):
                    level = header.count("#")

                chunk = Chunk(
                    id=chunk_id,
                    content=merged_content,
                    metadata=metadata,
                    doc_id=doc_id,
                    chunk_index=chunk_index,
                    chunk_type=chunk_type,
                    level=level,
                    position=chunk_index,
                )

                all_chunks.append(chunk)
                chunk_index += 1

        return all_chunks

    def _extract_relevant_header(self, chunk_content: str, full_content: str) -> str:
        """
        提取与当前分块内容最相关的标题。
        """
        # 查找当前分块在完整内容中的位置
        chunk_start = full_content.find(chunk_content)
        if chunk_start == -1:
            return ""

        # 向前搜索最近的标题
        lines = full_content[:chunk_start].split("\n")
        header_pattern = r"^(#{1,6})\s+(.+)$"

        # 从后向前搜索，找到最近的标题
        for i in range(len(lines) - 1, -1, -1):
            line = lines[i].strip()
            if re.match(header_pattern, line):
                return line

        return ""


def test_chunker():
    """测试分块器 - 基本功能验证。"""
    chunker = MarkdownChunker()

    # 测试文档 - 通用Markdown结构
    test_content = """
# 标题一

This is a section about general content.

## 子标题 1

Some paragraph content here.

```python
# 代码示例
def example_function():
    return "Hello, World!"
```

## 子标题 2

More content with various formatting.

# 标题二

Another section with different content.

```javascript
console.log('Example');
```

Final paragraph content.
"""

    chunks = chunker.chunk_document("test.md", test_content)

    print(f"Generated {len(chunks)} chunks:")
    for i, chunk in enumerate(chunks):
        print(f"\n--- Chunk {i} ---")
        print(f"ID: {chunk.id}")
        print(f"Type: {chunk.chunk_type}, Level: {chunk.level}")
        print(f"Content preview: {chunk.content[:100]}...")


if __name__ == "__main__":
    test_chunker()
