"""
成功路径记忆 - P5 组件
解题成功后自动保存经验到 memories/experiences/<type>.md
"""
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class ExperienceManager:
    """
    经验管理器

    经验文件格式：
    ```markdown
    # RCE 经验积累

    ## 2026-03-28 | http://target.com
    ### 靶机环境
    - PHP 7.4.1
    - Apache/2.4.41
    - disable_functions=exec,system,shell_exec

    ### 成功方法
    - copy() 文件写入 webshell
    - assert() 代码执行

    ### 关键 Payload
    ```php
    <?php eval($_POST['cmd']); ?>
    ```

    ### Flag 位置
    /flag

    ---
    ```

    ### 经验分类索引（自动维护）
    ```markdown
    ## 经验索引

    | 日期 | 靶机 | 关键方法 | 行号 |
    |------|------|----------|------|
    | 2026-03-28 | target.com | copy+assert | [#2026-03-28] |
    ```
    """

    EXPERIENCES_DIR = "memories/experiences"
    INDEX_FILE = "memories/experiences/_index.md"

    def __init__(self, experiences_dir: Optional[str] = None):
        if experiences_dir is None:
            project_root = Path(__file__).parent.parent
            experiences_dir = str(project_root / self.EXPERIENCES_DIR)
        self.experiences_dir = Path(experiences_dir)
        self.index_file = self.experiences_dir.parent / "_index.md"

    def _ensure_dir(self) -> None:
        """确保目录存在"""
        self.experiences_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_filename(self, challenge_type: str) -> str:
        """生成安全的文件名"""
        # 映射到已知类型
        type_mapping = {
            "rce": "rce",
            "command": "rce",
            "exec": "rce",
            "sqli": "sqli",
            "sql": "sqli",
            "injection": "sqli",
            "auth": "auth",
            "bypass": "auth",
            "login": "auth",
            "lfi": "lfi",
            "file inclusion": "lfi",
            "rfi": "lfi",
            "upload": "upload",
            "file upload": "upload",
            "xss": "xss",
            "ssrf": "ssrf",
            "ssti": "ssti",
            "sst": "ssti",
            "template": "ssti",
            "deserialization": "deserialization",
            "unserialize": "deserialization",
            "反序列化": "deserialization",
            "info": "info",
            "recon": "info",
            "info disclosure": "info",
        }
        return type_mapping.get(challenge_type.lower(), challenge_type.lower())

    def _build_experience_content(
        self,
        target: str,
        challenge_type: str,
        findings: List[str],
        methods_tried: List[str],
        method_succeeded: str,
        flag: str,
        payload_context: str = "",
    ) -> str:
        """构建经验内容"""
        date_str = datetime.now().strftime("%Y-%m-%d")
        time_str = datetime.now().strftime("%H:%M:%S")

        # 提取域名作为标题
        domain = re.sub(r"https?://", "", target.split("/")[0])

        content = f"""## {date_str} | {domain}
### 靶机环境
"""

        # 添加发现的信息
        if findings:
            for finding in findings:
                content += f"- {finding}\n"
        else:
            content += "- (无详细记录)\n"

        content += f"""
### 成功方法
- **{method_succeeded}**

"""

        # 添加关键 Payload（如果有）
        if payload_context:
            content += f"### 关键 Payload\n```\n{payload_context}\n```\n\n"

        content += """### 已尝试方法（失败）
"""
        for method in methods_tried:
            if method != method_succeeded:
                content += f"- {method}\n"

        content += f"""
### Flag
`{flag}`

"""
        content += "---\n\n"

        return content

    def _update_index(self, challenge_type: str, target: str, method_succeeded: str) -> None:
        """更新经验索引"""
        date_str = datetime.now().strftime("%Y-%m-%d")
        domain = re.sub(r"https?://", "", target.split("/")[0])

        # 锚标记（用于链接到具体经验）
        anchor = f"# {date_str}-{domain.replace('.', '-')}"

        # 读取现有索引
        existing_content = ""
        if self.index_file.exists():
            existing_content = self.index_file.read_text(encoding="utf-8")

        # 检查是否已存在该条目（基于日期+域名）
        entry_pattern = rf"{date_str}.*?{re.escape(domain)}"
        if re.search(entry_pattern, existing_content):
            # 更新已有条目
            pass  # 暂不实现更新逻辑
        else:
            # 添加新条目到索引开头
            new_entry = f"| {date_str} | {domain} | {method_succeeded} | [{anchor}](#) |\n"

            # 找到表格末尾并插入
            if "| 日期 | " in existing_content:
                lines = existing_content.split("\n")
                insert_idx = 0
                for i, line in enumerate(lines):
                    if line.startswith("| ---"):
                        insert_idx = i
                        break
                lines.insert(insert_idx, new_entry)
                existing_content = "\n".join(lines)
            else:
                # 创建新索引结构
                header = """# 经验索引

自动维护的成功经验索引，方便快速查找同类题目的解法。

## 经验索引表

| 日期 | 靶机 | 成功方法 | 链接 |
|------|------|----------|------|
"""
                existing_content = header + new_entry + "\n" + existing_content

        self.index_file.parent.mkdir(parents=True, exist_ok=True)
        self.index_file.write_text(existing_content, encoding="utf-8")

    def save_experience(
        self,
        target: str,
        challenge_type: str,
        findings: List[str],
        methods_tried: List[str],
        method_succeeded: str,
        flag: str,
        payload_context: str = "",
    ) -> str:
        """
        保存解题经验

        Args:
            target: 目标 URL
            challenge_type: 题型 (rce/sqli/auth/lfi/xss/upload)
            findings: 发现列表
            methods_tried: 已尝试的方法列表
            method_succeeded: 成功的方法
            flag: 找到的 flag
            payload_context: 关键 payload 或技术细节

        Returns:
            保存的文件路径
        """
        self._ensure_dir()

        # 确定文件名
        safe_type = self._sanitize_filename(challenge_type)
        experience_file = self.experiences_dir / f"{safe_type}.md"

        # 读取现有内容，检查是否需要添加标题
        existing_content = ""
        if experience_file.exists():
            existing_content = experience_file.read_text(encoding="utf-8")

        # 如果文件为空或没有标题，添加标题
        if not existing_content.strip():
            title_mapping = {
                "rce": "RCE 远程命令执行",
                "sqli": "SQL 注入",
                "auth": "认证绕过",
                "lfi": "文件包含",
                "upload": "文件上传",
                "xss": "XSS 跨站脚本",
                "ssrf": "SSRF 服务端请求伪造",
                "ssti": "模板注入",
                "deserialization": "反序列化",
                "info": "信息泄露",
            }
            title = title_mapping.get(safe_type, safe_type.upper())
            existing_content = f"# {title} 经验积累\n\n"

        # 构建新经验内容
        new_content = self._build_experience_content(
            target=target,
            challenge_type=challenge_type,
            findings=findings,
            methods_tried=methods_tried,
            method_succeeded=method_succeeded,
            flag=flag,
            payload_context=payload_context,
        )

        # 在 "---" 分隔符之后插入，或在文件末尾插入
        separator_idx = existing_content.find("---\n\n")
        if separator_idx != -1:
            insert_pos = separator_idx + 5
            existing_content = existing_content[:insert_pos] + new_content + existing_content[insert_pos:]
        else:
            existing_content += new_content

        # 写入文件
        experience_file.write_text(existing_content, encoding="utf-8")

        # 更新索引
        self._update_index(challenge_type, target, method_succeeded)

        return str(experience_file)

    def get_experiences(self, challenge_type: str) -> str:
        """
        获取指定题型的经验

        Args:
            challenge_type: 题型

        Returns:
            经验文件内容
        """
        safe_type = self._sanitize_filename(challenge_type)
        experience_file = self.experiences_dir / f"{safe_type}.md"

        if experience_file.exists():
            return experience_file.read_text(encoding="utf-8")
        return ""

    def list_experience_types(self) -> List[str]:
        """列出所有有经验文件的题型"""
        if not self.experiences_dir.exists():
            return []
        return [f.stem for f in self.experiences_dir.glob("*.md") if f.stem != "_index"]


# 全局实例
_experience_manager: Optional[ExperienceManager] = None


def get_experience_manager() -> ExperienceManager:
    """获取 ExperienceManager 单例"""
    global _experience_manager
    if _experience_manager is None:
        _experience_manager = ExperienceManager()
    return _experience_manager


# 快捷函数
def save_experience(
    target: str,
    challenge_type: str,
    findings: List[str],
    methods_tried: List[str],
    method_succeeded: str,
    flag: str,
    payload_context: str = "",
) -> str:
    """保存解题经验"""
    return get_experience_manager().save_experience(
        target=target,
        challenge_type=challenge_type,
        findings=findings,
        methods_tried=methods_tried,
        method_succeeded=method_succeeded,
        flag=flag,
        payload_context=payload_context,
    )


def get_experiences(challenge_type: str) -> str:
    """获取经验"""
    return get_experience_manager().get_experiences(challenge_type)


def list_experience_types() -> List[str]:
    """列出所有经验类型"""
    return get_experience_manager().list_experience_types()
