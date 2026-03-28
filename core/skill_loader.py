"""
Skill 加载器 - 根据题型加载针对性攻击知识
"""
import os
from pathlib import Path
from typing import Dict, Optional


# 题型与 skill 目录映射
TAXONOMY_SKILL_MAP = {
    "rce": "rce",
    "command_injection": "rce",
    "code_execution": "rce",
    "command_execution": "rce",
    "sqli": "sqli",
    "sql_injection": "sqli",
    "sql injection": "sqli",
    "xss": "xss",
    "cross_site_scripting": "xss",
    "auth": "auth-bypass",
    "auth_bypass": "auth-bypass",
    "authentication": "auth-bypass",
    "lfi": "file-inclusion",
    "file_inclusion": "file-inclusion",
    "local_file_inclusion": "file-inclusion",
    "file_upload": "upload",
    "upload": "upload",
    "ssrf": "ssrf",
    "ssti": "ssti",
    "template_injection": "ssti",
    "deserialization": "deserialization",
    "unserialize": "deserialization",
    "deserialize": "deserialization",
    "info_disclosure": "recon",
    "information_disclosure": "recon",
}


def resolve_skill_dir(skill_name: str, skills_base: Optional[str] = None) -> Path:
    """解析 skill 目录路径"""
    if skills_base is None:
        project_root = Path(__file__).parent.parent
        # skills 在项目根目录下
        skills_base = str(project_root / "skills")

    skill_path = Path(skills_base) / skill_name / "SKILL.md"
    if skill_path.exists():
        return skill_path

    # 尝试不区分大小写
    skills_dir = Path(skills_base)
    for d in skills_dir.iterdir():
        if d.is_dir() and d.name.lower() == skill_name.lower():
            skill_md = d / "SKILL.md"
            if skill_md.exists():
                return skill_md

    return skill_path  # 返回原路径（文件可能不存在）


def load_skill(problem_type: str, skills_base: Optional[str] = None) -> str:
    """
    根据题型加载 skill 内容

    Args:
        problem_type: 题型（如 "rce", "sqli"）
        skills_base: skills 目录路径

    Returns:
        SKILL.md 内容，文件不存在返回空字符串
    """
    skill_name = TAXONOMY_SKILL_MAP.get(problem_type.lower(), problem_type.lower())
    skill_path = resolve_skill_dir(skill_name, skills_base)

    if skill_path.exists():
        try:
            return skill_path.read_text(encoding="utf-8")
        except Exception:
            return ""
    return ""


def get_skill_type(problem_type: str) -> str:
    """获取 problem_type 对应的 skill 目录名"""
    return TAXONOMY_SKILL_MAP.get(problem_type.lower(), problem_type.lower())
