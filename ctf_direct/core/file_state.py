"""
文件状态管理器 - 直接模式的核心组件
通过文件系统实现状态持久化，多轮推理之间共享上下文
"""
import json
import time
import uuid
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional


class FileState:
    """基于文件的共享状态管理器，支持多进程安全"""

    def __init__(self, workspace_dir: str):
        self.dir = Path(workspace_dir)
        self.dir.mkdir(exist_ok=True, parents=True)
        self.lock = Lock()

    # ─────────────────────────────────────────────────────────────
    # 基础读写
    # ─────────────────────────────────────────────────────────────

    def read(self, filename: str) -> Optional[Any]:
        """读取 JSON 文件，不存在返回 None"""
        with self.lock:
            path = self.dir / filename
            if path.exists():
                try:
                    return json.loads(path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, IOError):
                    return None
            return None

    def write(self, filename: str, data: Any) -> None:
        """写入 JSON 文件"""
        with self.lock:
            path = self.dir / filename
            path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )

    def append(self, filename: str, new_data: Dict) -> None:
        """追加到列表型 JSON 文件"""
        with self.lock:
            existing = self.read(filename) or []
            if isinstance(existing, list):
                existing.append(new_data)
                self.write(filename, existing)

    def delete(self, filename: str) -> None:
        """删除文件"""
        with self.lock:
            path = self.dir / filename
            if path.exists():
                path.unlink()

    # ─────────────────────────────────────────────────────────────
    # Target 接口
    # ─────────────────────────────────────────────────────────────

    def init_target(self, url: str, hint: str = "", problem_type: str = "", tags: List[str] = None) -> None:
        """初始化 target.json"""
        self.write("target.json", {
            "url": url,
            "hint": hint,
            "problem_type": problem_type,
            "taxonomy_tags": tags or [],
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "status": "in_progress",
            "version": uuid.uuid4().hex[:8],
        })

    def get_target(self) -> Optional[Dict]:
        """获取当前题目信息"""
        return self.read("target.json")

    def update_target_status(self, status: str) -> None:
        """更新题目状态"""
        target = self.get_target()
        if target:
            target["status"] = status
            target["version"] = uuid.uuid4().hex[:8]
            self.write("target.json", target)

    # ─────────────────────────────────────────────────────────────
    # Tool State 接口
    # ─────────────────────────────────────────────────────────────

    def append_tool_result(self, tool: str, args: Dict, output: str, success: bool = True) -> None:
        """追加工具执行结果到 tool_state.json"""
        state = self.read("tool_state.json") or {"last_results": [], "findings": []}
        entry = {
            "tool": tool,
            "args": args,
            "output": output[:5000],  # 截断过长的输出
            "success": success,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "step": len(state.get("last_results", [])) + 1,
        }
        state.setdefault("last_results", []).append(entry)
        state["version"] = uuid.uuid4().hex[:8]
        self.write("tool_state.json", state)

    def get_tool_state(self) -> Dict:
        """获取工具状态"""
        return self.read("tool_state.json") or {"last_results": [], "findings": [], "version": "0"}

    def get_last_results(self, n: int = 5) -> List[Dict]:
        """获取最近 N 条工具结果"""
        state = self.get_tool_state()
        results = state.get("last_results", [])
        return results[-n:] if results else []

    def clear_tool_state(self) -> None:
        """清空工具状态"""
        self.write("tool_state.json", {"last_results": [], "findings": [], "version": "0"})

    # ─────────────────────────────────────────────────────────────
    # Findings 接口
    # ─────────────────────────────────────────────────────────────

    def add_finding(self, kind: str, value: str, step: int = None, confirmed: bool = False) -> None:
        """添加发现到 findings.json"""
        findings = self.read("findings.json") or {"findings": []}
        entry = {
            "kind": kind,
            "value": value,
            "step": step or len(findings.get("findings", [])) + 1,
            "confirmed": confirmed,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        # 去重：相同 kind+value 不重复添加
        existing = findings.get("findings", [])
        for f in existing:
            if f.get("kind") == kind and f.get("value") == value:
                return
        findings.setdefault("findings", []).append(entry)
        findings["version"] = uuid.uuid4().hex[:8]
        self.write("findings.json", findings)

    def add_findings(self, findings_list: List[Dict]) -> None:
        """批量添加发现"""
        for f in findings_list:
            if isinstance(f, dict):
                self.add_finding(f.get("kind", ""), f.get("value", ""),
                                 f.get("step"), f.get("confirmed", False))
            elif isinstance(f, str):
                # 支持 "kind:value" 格式
                if ":" in f:
                    kind, value = f.split(":", 1)
                    self.add_finding(kind.strip(), value.strip())

    def get_findings(self) -> List[Dict]:
        """获取所有发现"""
        findings = self.read("findings.json")
        return findings.get("findings", []) if findings else []

    def confirm_finding(self, kind: str, value: str) -> None:
        """确认一个发现"""
        findings = self.read("findings.json")
        if not findings:
            return
        for f in findings.get("findings", []):
            if f.get("kind") == kind and f.get("value") == value:
                f["confirmed"] = True
                f["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        findings["version"] = uuid.uuid4().hex[:8]
        self.write("findings.json", findings)

    # ─────────────────────────────────────────────────────────────
    # RAG 知识接口
    # ─────────────────────────────────────────────────────────────

    def write_rag_knowledge(self, query: str, retrieved_knowledge: List[Dict],
                            suggested_approach: str = "") -> None:
        """写入 RAG 检索结果"""
        self.write("rag_knowledge.json", {
            "query": query,
            "retrieved_knowledge": retrieved_knowledge,
            "suggested_approach": suggested_approach,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "version": uuid.uuid4().hex[:8],
        })

    def get_rag_knowledge(self) -> Optional[Dict]:
        """获取当前 RAG 知识"""
        return self.read("rag_knowledge.json")

    # ─────────────────────────────────────────────────────────────
    # Skill 内容接口
    # ─────────────────────────────────────────────────────────────

    def write_skill_content(self, content: str, skill_type: str = "") -> None:
        """写入当前 skill 内容"""
        self.write("skill_content.json", {
            "content": content,
            "skill_type": skill_type,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })

    def get_skill_content(self) -> str:
        """获取当前 skill 内容"""
        skill = self.read("skill_content.json")
        return skill.get("content", "") if skill else ""

    # ─────────────────────────────────────────────────────────────
    # 推理历史接口
    # ─────────────────────────────────────────────────────────────

    def append_reasoning(self, role: str, content: str) -> None:
        """追加推理消息到历史"""
        history = self.read("reasoning_history.json") or {"messages": []}
        entry = {
            "role": role,
            "content": content,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        history.setdefault("messages", []).append(entry)
        # 限制历史长度（最近 50 条）
        if len(history["messages"]) > 50:
            history["messages"] = history["messages"][-50:]
        self.write("reasoning_history.json", history)

    def get_reasoning_history(self) -> List[Dict]:
        """获取推理历史"""
        history = self.read("reasoning_history.json")
        return history.get("messages", []) if history else []

    def clear_reasoning_history(self) -> None:
        """清空推理历史"""
        self.write("reasoning_history.json", {"messages": []})

    # ─────────────────────────────────────────────────────────────
    # 工具
    # ─────────────────────────────────────────────────────────────

    def get_state_version(self) -> str:
        """获取当前状态版本号（用于检测变化）"""
        target = self.get_target()
        return target.get("version", "0") if target else "0"

    def is_changed_since(self, version: str) -> bool:
        """检查状态是否自指定版本后发生变化"""
        return self.get_state_version() != version

    def snapshot(self) -> Dict[str, Any]:
        """获取完整状态快照"""
        return {
            "target": self.get_target(),
            "tool_state": self.get_tool_state(),
            "findings": self.get_findings(),
            "rag_knowledge": self.get_rag_knowledge(),
            "skill_content": self.get_skill_content(),
            "reasoning_history": self.get_reasoning_history(),
        }
