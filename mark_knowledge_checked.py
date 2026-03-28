#!/usr/bin/env python3
"""
mark_knowledge_checked.py - 标记知识已查询
在成功查询技能知识、RAG 检索、历史经验后调用此脚本
创建 workspace/.knowledge_checked 文件，触发 Hook 放行后续攻击命令
"""
import os
from pathlib import Path

def main():
    project_root = Path(__file__).parent.parent
    marker_file = project_root / "workspace" / ".knowledge_checked"
    marker_file.parent.mkdir(parents=True, exist_ok=True)
    marker_file.touch()
    print(f"[+] Knowledge check marker created at {marker_file}")

if __name__ == "__main__":
    main()
