from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class GraphNode:
    id: str
    kind: str
    label: str
    status: str = "planned"
    step: int = 0
    updated_step: int = 0
    action_id: str = ""
    action_type: str = ""
    target: str = ""
    expected_tool: str = ""
    canonical_tool: str = ""
    attempt_count: int = 0
    evidence_steps: List[int] = field(default_factory=list)
    result_preview: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    id: str
    from_id: str
    to_id: str
    kind: str
    condition: str = ""
    step: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SharedFinding:
    id: str
    kind: str
    value: str
    source_node_id: str = ""
    source_action_id: str = ""
    first_seen_step: int = 0
    last_seen_step: int = 0
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphOp:
    op: str
    node_id: str = ""
    action_id: str = ""
    planned_status: str = "planned"
    success_status: str = "succeeded"
    failure_status: str = "failed"
    checkpoint_label: str = ""
    checkpoint_status: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class GraphManager:
    """Shadow graph layer with a minimal GraphOp contract."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._shared_findings: Dict[Tuple[str, str], SharedFinding] = {}
        self.active_node_id: str = ""
        self._checkpoint_counter = 0

    def build_action_graph_op(self, action: Dict[str, Any]) -> Dict[str, Any]:
        action = dict(action or {})
        return asdict(
            GraphOp(
                op="sync_action",
                node_id=self._action_node_id(action),
                action_id=str(action.get("id") or ""),
                metadata={
                    "action_type": str(action.get("type") or ""),
                    "target": str(action.get("target") or ""),
                    "expected_tool": str(action.get("expected_tool") or ""),
                },
            )
        )

    def build_checkpoint_graph_op(
        self,
        label: str,
        action: Optional[Dict[str, Any]] = None,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        action = dict(action or {})
        op_metadata = dict(metadata or {})
        if reason:
            op_metadata["reason"] = reason
        if action:
            op_metadata.setdefault("action_type", str(action.get("type") or ""))
            op_metadata.setdefault("target", str(action.get("target") or ""))
            op_metadata.setdefault("expected_tool", str(action.get("expected_tool") or ""))
        checkpoint_status = "paused" if label == "help" else "observed"
        return asdict(
            GraphOp(
                op="checkpoint",
                action_id=str(action.get("id") or ""),
                checkpoint_label=label,
                checkpoint_status=checkpoint_status,
                metadata=op_metadata,
            )
        )

    def apply_graph_op(
        self,
        graph_op: Optional[Dict[str, Any]],
        *,
        action: Optional[Dict[str, Any]] = None,
        step: int = 0,
        result: str = "",
        success: Optional[bool] = None,
        memory_step: Optional[Any] = None,
        message: str = "",
        reason: str = "",
        guidance: str = "",
        resume_count: int = 0,
    ) -> str:
        op = dict(graph_op or {})
        op_type = str(op.get("op") or "")

        if op_type == "checkpoint":
            label = str(op.get("checkpoint_label") or "")
            resolved_reason = reason or str(op.get("metadata", {}).get("reason") or "")
            if label == "help":
                return self.record_help(
                    step=step,
                    message=message or result,
                    reason=resolved_reason,
                    action=action,
                    graph_op=op,
                )
            if label == "resume":
                resolved_resume_count = resume_count or int(op.get("metadata", {}).get("resume_count") or 0)
                return self.record_resume(
                    step=step,
                    guidance=guidance or message or result,
                    resume_count=resolved_resume_count,
                    graph_op=op,
                )
            if label == "replan":
                return self.record_replan(
                    step=step,
                    action=action,
                    reason=resolved_reason,
                    graph_op=op,
                )
            raise ValueError(f"unsupported checkpoint graph op: {label}")

        if action is None:
            raise ValueError("action graph op requires action")

        if not op:
            op = self.build_action_graph_op(action)

        if success is None:
            return self.record_planned_action(action, step, graph_op=op)

        return self.record_action_result(
            action,
            step=step,
            success=success,
            result=result,
            memory_step=memory_step,
            graph_op=op,
        )

    def record_planned_action(
        self,
        action: Dict[str, Any],
        step: int,
        graph_op: Optional[Dict[str, Any]] = None,
    ) -> str:
        action = dict(action or {})
        op = dict(graph_op or {})
        action_id = str(action.get("id") or op.get("action_id") or "")
        node_id = str(op.get("node_id") or self._action_node_id(action, step))
        planned_status = str(op.get("planned_status") or "planned")
        relationship_metadata = self._action_relationship_metadata(action)
        existing = self._nodes.get(node_id)
        if existing is None:
            metadata = {
                "intent": str(action.get("intent") or ""),
                "params": dict(action.get("params") or {}),
                **relationship_metadata,
            }
            if op:
                metadata["graph_op"] = dict(op)
            node = GraphNode(
                id=node_id,
                kind="action",
                label=str(action.get("description") or action.get("type") or "action"),
                status=planned_status,
                step=step,
                updated_step=step,
                action_id=action_id,
                action_type=str(action.get("type") or ""),
                target=str(action.get("target") or ""),
                expected_tool=str(action.get("expected_tool") or ""),
                canonical_tool=str(action.get("expected_tool") or action.get("type") or ""),
                metadata=metadata,
            )
            self._nodes[node_id] = node
        else:
            existing.label = str(action.get("description") or action.get("type") or existing.label)
            existing.updated_step = step
            existing.action_id = action_id or existing.action_id
            existing.action_type = str(action.get("type") or existing.action_type)
            existing.target = str(action.get("target") or existing.target)
            existing.expected_tool = str(action.get("expected_tool") or existing.expected_tool)
            existing.canonical_tool = str(action.get("expected_tool") or action.get("type") or existing.canonical_tool)
            if existing.status in {"observed", "paused"}:
                existing.status = planned_status
            existing.metadata["intent"] = str(action.get("intent") or existing.metadata.get("intent", ""))
            existing.metadata["params"] = dict(action.get("params") or existing.metadata.get("params") or {})
            if relationship_metadata:
                existing.metadata.update(relationship_metadata)
            if op:
                existing.metadata["graph_op"] = dict(op)

        if self.active_node_id and self.active_node_id != node_id:
            self._add_edge(self.active_node_id, node_id, kind="next", step=step)
        self._link_action_relationships(node_id, action, step)
        self.active_node_id = node_id
        return node_id

    def record_action_result(
        self,
        action: Dict[str, Any],
        step: int,
        success: bool,
        result: str,
        memory_step: Optional[Any] = None,
        graph_op: Optional[Dict[str, Any]] = None,
    ) -> str:
        op = dict(graph_op or {})
        node_id = self.record_planned_action(action, step, graph_op=op)
        node = self._nodes[node_id]
        node.status = str(op.get("success_status") or "succeeded") if success else str(op.get("failure_status") or "failed")
        node.updated_step = step
        node.attempt_count += 1
        if step not in node.evidence_steps:
            node.evidence_steps.append(step)
        node.result_preview = self._preview(result)
        if memory_step is not None:
            node.expected_tool = str(getattr(memory_step, "expected_tool", "") or node.expected_tool)
            node.canonical_tool = str(
                getattr(memory_step, "canonical_tool", "")
                or getattr(memory_step, "expected_tool", "")
                or node.canonical_tool
            )
            node.metadata["tool"] = str(getattr(memory_step, "tool", "") or node.metadata.get("tool", ""))
        self.active_node_id = node_id
        return node_id

    def record_help(
        self,
        step: int,
        message: str,
        reason: str = "",
        action: Optional[Dict[str, Any]] = None,
        graph_op: Optional[Dict[str, Any]] = None,
    ) -> str:
        op = dict(graph_op or {})
        label = str(op.get("checkpoint_label") or "help")
        status = str(op.get("checkpoint_status") or "paused")
        node_id = self._new_checkpoint_id(label)
        metadata = {"reason": reason}
        if op:
            metadata["graph_op"] = dict(op)
        node = GraphNode(
            id=node_id,
            kind="checkpoint",
            label=label,
            status=status,
            step=step,
            updated_step=step,
            action_id=str((action or {}).get("id") or op.get("action_id") or ""),
            action_type=str((action or {}).get("type") or op.get("metadata", {}).get("action_type") or ""),
            target=str((action or {}).get("target") or op.get("metadata", {}).get("target") or ""),
            expected_tool=str((action or {}).get("expected_tool") or op.get("metadata", {}).get("expected_tool") or ""),
            canonical_tool=str((action or {}).get("expected_tool") or (action or {}).get("type") or ""),
            result_preview=self._preview(message),
            metadata=metadata,
        )
        self._nodes[node_id] = node
        if self.active_node_id and self.active_node_id != node_id:
            self._add_edge(self.active_node_id, node_id, kind="paused_on", step=step, condition=reason)
        self.active_node_id = node_id
        return node_id

    def record_resume(
        self,
        step: int,
        guidance: str,
        resume_count: int = 0,
        graph_op: Optional[Dict[str, Any]] = None,
    ) -> str:
        op = dict(graph_op or {})
        previous_active = self.active_node_id
        label = str(op.get("checkpoint_label") or "resume")
        status = str(op.get("checkpoint_status") or "observed")
        node_id = self._new_checkpoint_id(label)
        metadata = {"resume_count": resume_count}
        if op:
            metadata["graph_op"] = dict(op)
        node = GraphNode(
            id=node_id,
            kind="checkpoint",
            label=label,
            status=status,
            step=step,
            updated_step=step,
            result_preview=self._preview(guidance),
            metadata=metadata,
        )
        self._nodes[node_id] = node
        if previous_active and previous_active != node_id:
            self._add_edge(previous_active, node_id, kind="resumed_from", step=step)
        self.active_node_id = node_id
        if guidance:
            self.upsert_shared_finding(
                kind="guidance",
                value=guidance,
                step=step,
                source_node_id=node_id,
                metadata={"resume_count": resume_count},
            )
        return node_id

    def record_replan(
        self,
        step: int,
        action: Optional[Dict[str, Any]] = None,
        reason: str = "",
        graph_op: Optional[Dict[str, Any]] = None,
    ) -> str:
        op = dict(graph_op or {})
        previous_active = self.active_node_id
        label = str(op.get("checkpoint_label") or "replan")
        status = str(op.get("checkpoint_status") or "observed")
        payload = self._normalize_replan_metadata(op.get("metadata") or {})
        if reason and not payload.get("reason"):
            payload["reason"] = reason
        if not payload.get("reason_detail") and payload.get("reason"):
            payload["reason_detail"] = str(payload.get("reason") or "")

        action = dict(action or {})
        if action:
            payload.setdefault("source_action_id", str(action.get("id") or ""))
            payload.setdefault("source_action_type", str(action.get("type") or ""))
            payload.setdefault("blocked_action_ids", self._normalize_list(payload.get("blocked_action_ids") or [action.get("id")]))
            payload.setdefault(
                "blocked_tools",
                self._normalize_list(payload.get("blocked_tools") or [action.get("expected_tool") or action.get("type")]),
            )

        payload["avoid_action_ids"] = self._normalize_list(
            payload.get("avoid_action_ids") or payload.get("blocked_action_ids") or []
        )
        payload["avoid_tools"] = self._normalize_list(payload.get("avoid_tools") or payload.get("blocked_tools") or [])
        if not payload.get("selected_alternative") and payload.get("alternative_candidates"):
            payload["selected_alternative"] = dict(payload["alternative_candidates"][0])

        node_id = self._new_checkpoint_id(label)
        metadata = dict(payload)
        if op:
            metadata["graph_op"] = dict(op)
        node = GraphNode(
            id=node_id,
            kind="checkpoint",
            label=label,
            status=status,
            step=step,
            updated_step=step,
            action_id=str(payload.get("source_action_id") or (action or {}).get("id") or op.get("action_id") or ""),
            action_type=str(payload.get("source_action_type") or (action or {}).get("type") or op.get("metadata", {}).get("action_type") or ""),
            target=str((action or {}).get("target") or op.get("metadata", {}).get("target") or ""),
            expected_tool=str((action or {}).get("expected_tool") or op.get("metadata", {}).get("expected_tool") or ""),
            canonical_tool=str((action or {}).get("expected_tool") or (action or {}).get("type") or ""),
            result_preview=self._preview(payload.get("reason_detail") or payload.get("reason") or reason),
            metadata=metadata,
        )
        self._nodes[node_id] = node

        reason_code = str(payload.get("reason_code") or payload.get("reason") or "")
        if previous_active and previous_active != node_id:
            self._add_edge(previous_active, node_id, kind="next", step=step, condition=reason_code)

        blocked_action_ids = self._normalize_list(payload.get("blocked_action_ids"))
        blocked_tools = self._normalize_list(payload.get("blocked_tools"))
        for blocked_action_id in blocked_action_ids:
            related_node_id = self._lookup_node_id(action_id=blocked_action_id)
            if related_node_id:
                self._add_edge(
                    node_id,
                    related_node_id,
                    kind="blocked_by",
                    step=step,
                    condition=reason_code,
                    metadata={"reason_detail": str(payload.get("reason_detail") or "")},
                )
        for blocked_tool in blocked_tools:
            related_node_id = self._latest_action_node_by_tool(blocked_tool, statuses={"failed"})
            if related_node_id:
                self._add_edge(
                    node_id,
                    related_node_id,
                    kind="blocked_by",
                    step=step,
                    condition=blocked_tool,
                    metadata={"reason_code": reason_code},
                )

        source_node_id = str(payload.get("source_node_id") or "")
        if not source_node_id:
            source_action_id = str(payload.get("source_action_id") or "")
            if source_action_id:
                source_node_id = self._lookup_node_id(action_id=source_action_id)
        if not source_node_id:
            source_finding_kind = str(payload.get("source_finding_kind") or "")
            source_finding_value = str(payload.get("source_finding_value") or "")
            if source_finding_kind and source_finding_value:
                finding = self._shared_findings.get((source_finding_kind, source_finding_value))
                if finding and finding.source_node_id:
                    source_node_id = finding.source_node_id

        if source_node_id:
            self._add_edge(
                node_id,
                source_node_id,
                kind="guided_by",
                step=step,
                condition=str(payload.get("source_finding_kind") or ""),
                metadata={"value": str(payload.get("source_finding_value") or "")},
            )

        source_action_id = str(payload.get("source_action_id") or "")
        if source_action_id:
            derived_from_id = self._lookup_node_id(action_id=source_action_id)
            if derived_from_id:
                self._add_edge(node_id, derived_from_id, kind="derived_from", step=step, condition=reason_code)

        if payload.get("source_finding_kind") and payload.get("source_finding_value"):
            try:
                self.upsert_shared_finding(
                    kind=str(payload.get("source_finding_kind") or "note"),
                    value=str(payload.get("source_finding_value") or ""),
                    step=step,
                    source_node_id=source_node_id,
                    source_action_id=source_action_id,
                    metadata={"reason_code": reason_code},
                )
            except ValueError:
                pass

        self.active_node_id = node_id
        return node_id

    def upsert_shared_finding(
        self,
        kind: str,
        value: Any,
        step: int,
        source_node_id: str = "",
        source_action_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SharedFinding:
        normalized_value = self._normalize_finding_value(value)
        if not normalized_value:
            raise ValueError("finding value must not be empty")
        key = (kind, normalized_value)
        finding = self._shared_findings.get(key)
        if finding is None:
            finding = SharedFinding(
                id=f"finding:{self._stable_id(kind, normalized_value)}",
                kind=kind,
                value=normalized_value,
                source_node_id=source_node_id,
                source_action_id=source_action_id,
                first_seen_step=step,
                last_seen_step=step,
                metadata=dict(metadata or {}),
            )
            self._shared_findings[key] = finding
            return finding

        finding.last_seen_step = max(finding.last_seen_step, step)
        if source_node_id and not finding.source_node_id:
            finding.source_node_id = source_node_id
        if source_action_id and not finding.source_action_id:
            finding.source_action_id = source_action_id
        if metadata:
            finding.metadata.update(metadata)
        return finding

    def refresh_shared_findings(self, memory: Any) -> List[Dict[str, Any]]:
        target = getattr(memory, "target", None)
        context = getattr(memory, "context", None)
        steps = list(getattr(memory, "steps", []) or [])
        current_step = len(steps)

        if target is not None:
            for endpoint in getattr(target, "endpoints", []) or []:
                self.upsert_shared_finding("endpoint", endpoint, step=current_step)
                for kind, value in self._derive_findings_from_value(endpoint):
                    self.upsert_shared_finding(kind, value, step=current_step, metadata={"derived_from": "endpoint"})
            for parameter in getattr(target, "parameters", []) or []:
                self.upsert_shared_finding("parameter", parameter, step=current_step)
            for vuln in getattr(target, "vulnerabilities", []) or []:
                value = vuln.get("type") if isinstance(vuln, dict) else str(vuln)
                self.upsert_shared_finding(
                    "vulnerability",
                    value,
                    step=current_step,
                    metadata=vuln if isinstance(vuln, dict) else {},
                )
            for flag in getattr(target, "flags", []) or []:
                self.upsert_shared_finding("flag", flag, step=current_step)

        for node in self._nodes.values():
            metadata = dict(node.metadata or {})
            for raw_value in [node.target, node.result_preview, metadata.get("result"), metadata.get("label")]:
                text_value = str(raw_value or "").strip()
                if not text_value:
                    continue
                if text_value.startswith("/"):
                    self.upsert_shared_finding(
                        "endpoint",
                        text_value,
                        step=node.updated_step or node.step or current_step,
                        source_node_id=node.id,
                        source_action_id=node.action_id,
                        metadata={"derived_from": "graph.node"},
                    )
                for kind, value in self._derive_findings_from_value(text_value):
                    self.upsert_shared_finding(
                        kind,
                        value,
                        step=node.updated_step or node.step or current_step,
                        source_node_id=node.id,
                        source_action_id=node.action_id,
                        metadata={"derived_from": "graph.node"},
                    )

        for index, step_item in enumerate(steps, start=1):
            source_action_id = str(getattr(step_item, "action_id", "") or "")
            source_node_id = f"action:{source_action_id}" if source_action_id else ""
            result_text = str(getattr(step_item, "result", "") or "")
            key_findings = list(getattr(step_item, "key_findings", []) or [])

            for value in key_findings:
                finding_value = str(value or "").strip()
                if not finding_value:
                    continue
                metadata = {"derived_from": "step.key_findings"}
                if ":" in finding_value:
                    kind, raw_value = finding_value.split(":", 1)
                    kind = kind.strip()
                    raw_value = raw_value.strip()
                    if kind and raw_value:
                        self.upsert_shared_finding(
                            kind,
                            raw_value,
                            step=index,
                            source_node_id=source_node_id,
                            source_action_id=source_action_id,
                            metadata=metadata,
                        )
                        continue
                if finding_value.startswith("/"):
                    self.upsert_shared_finding(
                        "endpoint",
                        finding_value,
                        step=index,
                        source_node_id=source_node_id,
                        source_action_id=source_action_id,
                        metadata=metadata,
                    )
                    for kind, value in self._derive_findings_from_value(finding_value):
                        self.upsert_shared_finding(
                            kind,
                            value,
                            step=index,
                            source_node_id=source_node_id,
                            source_action_id=source_action_id,
                            metadata={"derived_from": "step.endpoint"},
                        )
                    continue
                for kind, value in self._derive_findings_from_value(finding_value):
                    self.upsert_shared_finding(
                        kind,
                        value,
                        step=index,
                        source_node_id=source_node_id,
                        source_action_id=source_action_id,
                        metadata=metadata,
                    )

            for kind, value in self._derive_findings_from_value(result_text):
                self.upsert_shared_finding(
                    kind,
                    value,
                    step=index,
                    source_node_id=source_node_id,
                    source_action_id=source_action_id,
                    metadata={"derived_from": "step.result"},
                )

        if context is not None:
            shared_findings = getattr(context, "shared_findings", []) or []
            for finding in shared_findings:
                if not isinstance(finding, dict):
                    continue
                try:
                    self.upsert_shared_finding(
                        kind=str(finding.get("kind") or "note"),
                        value=finding.get("value") or "",
                        step=int(finding.get("last_seen_step") or finding.get("first_seen_step") or current_step),
                        source_node_id=str(finding.get("source_node_id") or ""),
                        source_action_id=str(finding.get("source_action_id") or ""),
                        metadata=dict(finding.get("metadata") or {}),
                    )
                except ValueError:
                    continue

            if getattr(context, "human_guidance", ""):
                self.upsert_shared_finding("guidance", context.human_guidance, step=current_step)
            for entry in getattr(context, "help_history", []) or []:
                if not isinstance(entry, dict):
                    continue
                guidance = str(entry.get("guidance") or "")
                if guidance:
                    self.upsert_shared_finding(
                        "guidance",
                        guidance,
                        step=int(entry.get("resume_step") or entry.get("step") or current_step),
                        metadata={"reason": entry.get("reason", "")},
                    )

        return self.get_shared_findings()

    def get_shared_findings(self) -> List[Dict[str, Any]]:
        findings = sorted(
            self._shared_findings.values(),
            key=lambda item: (item.first_seen_step, item.kind, item.value),
        )
        return [asdict(finding) for finding in findings]

    def get_findings_by_kind(self, kind: str) -> List[Dict[str, Any]]:
        return [
            finding
            for finding in self.get_shared_findings()
            if str(finding.get("kind") or "") == kind
        ]

    def latest_finding(self, kind: str) -> Optional[Dict[str, Any]]:
        findings = self.get_findings_by_kind(kind)
        if not findings:
            return None
        return max(
            findings,
            key=lambda item: (
                int(item.get("last_seen_step") or 0),
                int(item.get("first_seen_step") or 0),
                str(item.get("id") or ""),
            ),
        )

    def _derive_findings_from_value(self, value: Any) -> List[Tuple[str, str]]:
        text = str(value or "").strip()
        if not text:
            return []

        lower_text = text.lower()
        derived: List[Tuple[str, str]] = []

        def add(kind: str, finding_value: str) -> None:
            item = (kind, str(finding_value or "").strip())
            if not item[1] or item in derived:
                return
            derived.append(item)

        if any(token in lower_text for token in [".git/head", ".git/config", "/.git", ".svn/entries", ".hg"]):
            add("repo_exposure", text)
        if any(token in lower_text for token in [".env", "config.php", "flag.txt", "/etc/passwd"]):
            add("sensitive_file", text)
        if any(token in lower_text for token in ["backup", ".zip", ".tar", ".gz", ".bak", ".old", ".swp"]):
            add("backup_file", text)
        if any(token in lower_text for token in ["phpinfo", "debug", "test.php", "info.php"]):
            add("debug_page", text)
        if any(token in lower_text for token in ["backdoor.php", "webshell", "letmein"]):
            add("shell_artifact", text)
        if any(token in lower_text for token in ["source leak", "highlight_file", "view-source", "源码泄露"]):
            add("source_leak", text)
        if any(token in lower_text for token in ["php version", "x-powered-by", "server:", "content-type:"]):
            add("info_leak", text)

        for match in re.findall(r"[?&]([^=&#]+)=", text):
            add("parameter", match)

        return derived

    def _finding_lineage_key(self, kind: str = "", value: str = "", family: str = "") -> str:
        parts = [str(kind or "").strip(), str(value or "").strip(), str(family or "").strip()]
        normalized = [part for part in parts if part]
        return "::".join(normalized)

    def _finding_lineage_summary(self, finding: Dict[str, Any], recent_replans: List[Dict[str, Any]]) -> Dict[str, Any]:
        item = dict(finding or {})
        kind = str(item.get("kind") or "").strip()
        value = str(item.get("value") or "").strip()
        family = str(item.get("verification_family") or kind or "").strip()
        lineage_key = self._finding_lineage_key(kind, value, family)

        failed_attempts = 0
        total_attempts = 0
        last_attempt_step = 0
        last_status = ""
        for node in self._nodes.values():
            if node.kind != "action":
                continue
            metadata = dict(node.metadata or {})
            node_kind = str(metadata.get("source_finding_kind") or "").strip()
            node_value = str(metadata.get("source_finding_value") or "").strip()
            node_family = str(metadata.get("verification_family") or node_kind or "").strip()
            if self._finding_lineage_key(node_kind, node_value, node_family) != lineage_key:
                continue
            attempts = max(int(node.attempt_count or 0), 1)
            total_attempts += attempts
            if node.status == "failed":
                failed_attempts += attempts
            step = int(node.updated_step or node.step or 0)
            if step >= last_attempt_step:
                last_attempt_step = step
                last_status = str(node.status or "")

        blocked = False
        blocked_by_replans: List[str] = []
        for replan in recent_replans[:3]:
            blocked_findings = list(replan.get("blocked_findings") or [])
            avoid_lineages = self._normalize_list(replan.get("avoid_lineages") or [])
            replan_lineage_key = self._finding_lineage_key(
                replan.get("source_finding_kind") or "",
                replan.get("source_finding_value") or "",
                replan.get("verification_family") or replan.get("source_finding_kind") or "",
            )
            if replan_lineage_key == lineage_key or lineage_key in avoid_lineages:
                blocked = True
                blocked_by_replans.append(str(replan.get("node_id") or ""))
                continue
            for blocked_item in blocked_findings:
                blocked_kind = str(blocked_item.get("kind") or "").strip()
                blocked_value = str(blocked_item.get("value") or "").strip()
                blocked_family = str(blocked_item.get("verification_family") or blocked_kind or "").strip()
                if self._finding_lineage_key(blocked_kind, blocked_value, blocked_family) == lineage_key:
                    blocked = True
                    blocked_by_replans.append(str(replan.get("node_id") or ""))
                    break

        summary = {
            "lineage_key": lineage_key,
            "kind": kind,
            "value": value,
            "verification_family": family,
            "source_action_id": str(item.get("source_action_id") or ""),
            "source_node_id": str(item.get("source_node_id") or ""),
            "failed_attempts": failed_attempts,
            "attempts": total_attempts,
            "blocked": blocked,
            "last_attempt_step": last_attempt_step,
            "last_status": last_status,
        }
        if blocked_by_replans:
            summary["blocked_by_replans"] = self._unique_values(blocked_by_replans)
        return summary

    def _finding_priority(self, finding: Dict[str, Any]) -> int:
        priority_map = {
            "repo_exposure": 100,
            "shell_artifact": 95,
            "source_leak": 90,
            "backup_file": 85,
            "sensitive_file": 80,
            "debug_page": 75,
            "info_leak": 70,
            "vulnerability": 65,
            "parameter": 60,
            "auth_hint": 58,
            "form_field": 57,
            "form_method": 56,
            "endpoint": 50,
            "guidance": 40,
            "flag": 120,
        }
        return priority_map.get(str(finding.get("kind") or ""), 10)

    def planner_signals(self) -> Dict[str, Any]:
        findings = self.get_shared_findings()
        if not findings:
            latest_step = 0
            for node in self._nodes.values():
                latest_step = max(latest_step, int(node.updated_step or node.step or 0))
            fallback_target = type("GraphTargetView", (), {"endpoints": [], "parameters": [], "vulnerabilities": [], "flags": []})()
            fallback_context = type("GraphContextView", (), {"shared_findings": [], "human_guidance": "", "help_history": []})()
            fallback_steps = []
            for node in self._nodes.values():
                result_text = str(node.metadata.get("result") or node.result_preview or "")
                key_findings = list(node.metadata.get("key_findings") or [])
                fallback_steps.append(
                    type(
                        "GraphStepView",
                        (),
                        {
                            "action_id": node.action_id,
                            "result": result_text,
                            "key_findings": key_findings,
                        },
                    )()
                )
                target_value = str(node.target or "").strip()
                if target_value.startswith("/") and target_value not in fallback_target.endpoints:
                    fallback_target.endpoints.append(target_value)
            fallback_memory = type(
                "GraphMemoryView",
                (),
                {"target": fallback_target, "context": fallback_context, "steps": fallback_steps},
            )()
            self.refresh_shared_findings(fallback_memory)
            findings = self.get_shared_findings()
        action_nodes = [node for node in self._nodes.values() if node.kind == "action"]
        failed_nodes = sorted(
            (node for node in action_nodes if node.status == "failed"),
            key=lambda node: (node.updated_step, node.step, node.id),
            reverse=True,
        )
        succeeded_nodes = sorted(
            (node for node in action_nodes if node.status == "succeeded"),
            key=lambda node: (node.updated_step, node.step, node.id),
            reverse=True,
        )
        replan_nodes = sorted(
            (
                node for node in self._nodes.values()
                if node.kind == "checkpoint" and node.label == "replan"
            ),
            key=lambda node: (node.updated_step, node.step, node.id),
            reverse=True,
        )

        failed_action_counts: Dict[str, int] = {}
        failed_tool_counts: Dict[str, int] = {}
        for node in failed_nodes:
            attempts = max(int(node.attempt_count or 0), 1)
            if node.action_id:
                failed_action_counts[node.action_id] = max(
                    failed_action_counts.get(node.action_id, 0),
                    attempts,
                )
            tool_name = node.canonical_tool or node.expected_tool
            if tool_name:
                failed_tool_counts[tool_name] = failed_tool_counts.get(tool_name, 0) + attempts

        def finding_values(kind: str) -> List[str]:
            return self._unique_values(
                [
                    str(finding.get("value") or "")
                    for finding in findings
                    if str(finding.get("kind") or "") == kind and str(finding.get("value") or "")
                ]
            )

        recent_replans = [self._serialize_replan_node(node) for node in replan_nodes[:5]]
        latest_replan = recent_replans[0] if recent_replans else {}
        avoid_action_ids = self._unique_values(
            [
                value
                for item in recent_replans[:3]
                for value in self._normalize_list(item.get("avoid_action_ids"))
            ]
        )
        avoid_tools = self._unique_values(
            [
                value
                for item in recent_replans[:3]
                for value in self._normalize_list(item.get("avoid_tools"))
            ]
        )

        latest_guidance = self.latest_finding("guidance")
        latest_endpoint = self.latest_finding("endpoint")
        latest_parameter = self.latest_finding("parameter")
        priority_findings = sorted(
            [
                finding for finding in findings
                if str(finding.get("kind") or "") in {
                    "repo_exposure",
                    "backup_file",
                    "sensitive_file",
                    "debug_page",
                    "source_leak",
                    "shell_artifact",
                    "info_leak",
                    "parameter",
                    "endpoint",
                    "vulnerability",
                    "auth_hint",
                    "form_field",
                    "form_method",
                }
            ],
            key=lambda item: (
                -self._finding_priority(item),
                -int(item.get("last_seen_step") or 0),
                str(item.get("kind") or ""),
                str(item.get("value") or ""),
            ),
        )
        verification_hints = [
            {
                "kind": str(item.get("kind") or ""),
                "value": str(item.get("value") or ""),
                "confidence": float(item.get("confidence") or 1.0),
                "metadata": dict(item.get("metadata") or {}),
                "source_action_id": str(item.get("source_action_id") or ""),
                "source_node_id": str(item.get("source_node_id") or ""),
                "verification_family": str(item.get("verification_family") or item.get("kind") or ""),
            }
            for item in priority_findings[:8]
        ]
        finding_lineages = [
            self._finding_lineage_summary(item, recent_replans)
            for item in priority_findings[:8]
        ]
        blocked_findings = [
            dict(item)
            for lineage in finding_lineages
            if lineage.get("blocked")
            for item in [
                {
                    "kind": str(lineage.get("kind") or ""),
                    "value": str(lineage.get("value") or ""),
                    "verification_family": str(lineage.get("verification_family") or ""),
                    "lineage_key": str(lineage.get("lineage_key") or ""),
                }
            ]
            if item.get("kind") and item.get("value")
        ]
        finding_failure_counts = {
            str(lineage.get("lineage_key") or ""): int(lineage.get("failed_attempts") or 0)
            for lineage in finding_lineages
            if str(lineage.get("lineage_key") or "")
        }
        finding_attempt_counts = {
            str(lineage.get("lineage_key") or ""): int(lineage.get("attempts") or 0)
            for lineage in finding_lineages
            if str(lineage.get("lineage_key") or "")
        }
        return {
            "latest_guidance": str((latest_guidance or {}).get("value") or ""),
            "guidance_history": finding_values("guidance")[-3:],
            "latest_endpoint": str((latest_endpoint or {}).get("value") or ""),
            "latest_parameter": str((latest_parameter or {}).get("value") or ""),
            "known_endpoints": finding_values("endpoint"),
            "known_parameters": finding_values("parameter"),
            "known_vulnerabilities": finding_values("vulnerability"),
            "known_flags": finding_values("flag"),
            "failed_action_ids": self._unique_values([node.action_id for node in failed_nodes if node.action_id]),
            "failed_action_types": self._unique_values([node.action_type for node in failed_nodes if node.action_type]),
            "failed_tools": self._unique_values(
                [node.canonical_tool or node.expected_tool for node in failed_nodes if node.canonical_tool or node.expected_tool]
            ),
            "failed_action_counts": failed_action_counts,
            "failed_tool_counts": failed_tool_counts,
            "recent_failed_cluster": [
                {
                    "node_id": node.id,
                    "action_id": node.action_id,
                    "action_type": node.action_type,
                    "tool": node.canonical_tool or node.expected_tool,
                    "step": node.updated_step or node.step,
                    "result_preview": node.result_preview,
                }
                for node in failed_nodes[:4]
            ],
            "succeeded_action_ids": self._unique_values([node.action_id for node in succeeded_nodes if node.action_id]),
            "active_node_id": self.active_node_id,
            "active_chain": self._active_chain(),
            "latest_replan": latest_replan,
            "recent_replans": recent_replans,
            "avoid_action_ids": avoid_action_ids,
            "avoid_tools": avoid_tools,
            "alternative_candidates": list(latest_replan.get("alternative_candidates") or []),
            "priority_findings": priority_findings[:8],
            "verification_hints": verification_hints,
            "finding_lineages": finding_lineages,
            "blocked_findings": blocked_findings,
            "finding_failure_counts": finding_failure_counts,
            "finding_attempt_counts": finding_attempt_counts,
        }

    def summary(self) -> str:
        if not self._nodes:
            return "graph=empty"
        counts: Dict[str, int] = {}
        for node in self._nodes.values():
            counts[node.status] = counts.get(node.status, 0) + 1
        parts = [f"nodes={len(self._nodes)}", f"edges={len(self._edges)}", f"findings={len(self._shared_findings)}"]
        for status in sorted(counts):
            parts.append(f"{status}={counts[status]}")
        replan_count = sum(
            1 for node in self._nodes.values() if node.kind == "checkpoint" and node.label == "replan"
        )
        if replan_count:
            parts.append(f"replans={replan_count}")
        if self.active_node_id:
            parts.append(f"active={self.active_node_id}")
        return ", ".join(parts)

    def snapshot(self) -> Dict[str, Any]:
        nodes = sorted(self._nodes.values(), key=lambda node: (node.step, node.id))
        replan_history = [
            self._serialize_replan_node(node)
            for node in sorted(
                (
                    node for node in self._nodes.values()
                    if node.kind == "checkpoint" and node.label == "replan"
                ),
                key=lambda node: (node.updated_step, node.step, node.id),
                reverse=True,
            )[:10]
        ]
        return {
            "version": 1,
            "active_node_id": self.active_node_id,
            "nodes": [asdict(node) for node in nodes],
            "edges": [asdict(edge) for edge in self._edges],
            "shared_findings": self.get_shared_findings(),
            "latest_replan": replan_history[0] if replan_history else {},
            "replan_history": replan_history,
            "active_chain": self._active_chain(),
            "stats": {
                "node_count": len(self._nodes),
                "edge_count": len(self._edges),
                "finding_count": len(self._shared_findings),
                "replan_count": len(replan_history),
            },
        }

    def _add_edge(
        self,
        from_id: str,
        to_id: str,
        kind: str,
        step: int,
        condition: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        edge_key = (from_id, to_id, kind, step, condition)
        for edge in self._edges:
            if (edge.from_id, edge.to_id, edge.kind, edge.step, edge.condition) == edge_key:
                if metadata:
                    edge.metadata.update(metadata)
                return
        edge = GraphEdge(
            id=f"edge:{self._stable_id(from_id, to_id, kind, str(step), condition)}",
            from_id=from_id,
            to_id=to_id,
            kind=kind,
            condition=condition,
            step=step,
            metadata=dict(metadata or {}),
        )
        self._edges.append(edge)

    def _new_checkpoint_id(self, label: str) -> str:
        self._checkpoint_counter += 1
        return f"checkpoint:{label}:{self._checkpoint_counter}"

    def _action_node_id(self, action: Dict[str, Any], step: int = 0) -> str:
        action_id = str((action or {}).get("id") or "")
        return f"action:{action_id or self._stable_id('action', str(step), str(action))}"

    def _node_id_for_action_id(self, action_id: str) -> str:
        normalized = str(action_id or "").strip()
        if not normalized:
            return ""
        return normalized if normalized.startswith(("action:", "checkpoint:")) else f"action:{normalized}"

    def _lookup_node_id(
        self,
        *,
        action_id: str = "",
        tool: str = "",
        action_type: str = "",
        statuses: Optional[set[str]] = None,
    ) -> str:
        if action_id:
            node_id = self._node_id_for_action_id(action_id)
            if node_id in self._nodes:
                return node_id
        if tool:
            return self._latest_action_node_by_tool(tool, statuses=statuses)
        if action_type:
            return self._latest_action_node_by_type(action_type, statuses=statuses)
        return ""

    def _action_relationship_metadata(self, action: Dict[str, Any]) -> Dict[str, Any]:
        action = dict(action or {})
        replan = self._normalize_replan_metadata(action.get("replan") or {})

        metadata: Dict[str, Any] = {}
        if action.get("graph_driven"):
            metadata["graph_driven"] = True
        if action.get("alternative"):
            metadata["alternative"] = True

        source_finding_kind = str(action.get("source_finding_kind") or replan.get("source_finding_kind") or "")
        source_finding_value = str(action.get("source_finding_value") or replan.get("source_finding_value") or "")
        source_node_id = str(action.get("source_node_id") or replan.get("source_node_id") or "")
        source_action_id = str(action.get("source_action_id") or replan.get("source_action_id") or "")
        alternative_to = str(
            action.get("alternative_to")
            or action.get("alternative_to_action_id")
            or replan.get("source_action_id")
            or ""
        )
        derived_from = str(
            action.get("derived_from")
            or action.get("derived_from_action_id")
            or source_action_id
            or ""
        )
        blocked_action_ids = self._normalize_list(
            action.get("blocked_action_ids")
            or replan.get("blocked_action_ids")
            or [action.get("avoids_action_id")]
        )
        blocked_tools = self._normalize_list(action.get("blocked_tools") or replan.get("blocked_tools"))
        avoid_action_ids = self._normalize_list(
            action.get("avoid_action_ids")
            or replan.get("avoid_action_ids")
            or [action.get("avoids_action_id")]
        )
        avoid_tools = self._normalize_list(action.get("avoid_tools") or replan.get("avoid_tools"))

        if source_finding_kind:
            metadata["source_finding_kind"] = source_finding_kind
        if source_finding_value:
            metadata["source_finding_value"] = source_finding_value
        if source_node_id:
            metadata["source_node_id"] = source_node_id
        if source_action_id:
            metadata["source_action_id"] = source_action_id
        if alternative_to:
            metadata["alternative_to"] = alternative_to
        if derived_from:
            metadata["derived_from"] = derived_from
        if blocked_action_ids:
            metadata["blocked_action_ids"] = blocked_action_ids
        if blocked_tools:
            metadata["blocked_tools"] = blocked_tools
        if avoid_action_ids:
            metadata["avoid_action_ids"] = avoid_action_ids
        if avoid_tools:
            metadata["avoid_tools"] = avoid_tools
        if replan:
            metadata["replan"] = replan
        return metadata

    def _link_action_relationships(self, node_id: str, action: Dict[str, Any], step: int) -> None:
        metadata = self._action_relationship_metadata(action)
        replan = dict(metadata.get("replan") or {})
        reason_code = str(replan.get("reason_code") or replan.get("reason") or "")

        blocked_action_ids = self._normalize_list(metadata.get("blocked_action_ids"))
        blocked_tools = self._normalize_list(metadata.get("blocked_tools"))
        for blocked_action_id in blocked_action_ids:
            related_node_id = self._lookup_node_id(action_id=blocked_action_id)
            if related_node_id and related_node_id != node_id:
                self._add_edge(node_id, related_node_id, kind="blocked_by", step=step, condition=reason_code)
        for blocked_tool in blocked_tools:
            related_node_id = self._latest_action_node_by_tool(blocked_tool, statuses={"failed"})
            if related_node_id and related_node_id != node_id:
                self._add_edge(node_id, related_node_id, kind="blocked_by", step=step, condition=blocked_tool)

        alternative_to = str(metadata.get("alternative_to") or "")
        if alternative_to:
            related_node_id = self._lookup_node_id(action_id=alternative_to)
            if related_node_id and related_node_id != node_id:
                self._add_edge(node_id, related_node_id, kind="alternative_to", step=step, condition=reason_code)

        derived_from = str(metadata.get("derived_from") or "")
        if derived_from:
            related_node_id = self._lookup_node_id(action_id=derived_from)
            if related_node_id and related_node_id != node_id:
                self._add_edge(node_id, related_node_id, kind="derived_from", step=step, condition=reason_code)

        source_node_id = str(metadata.get("source_node_id") or "")
        if not source_node_id:
            source_action_id = str(metadata.get("source_action_id") or "")
            if source_action_id:
                source_node_id = self._lookup_node_id(action_id=source_action_id)
        if not source_node_id:
            source_finding_kind = str(metadata.get("source_finding_kind") or "")
            source_finding_value = str(metadata.get("source_finding_value") or "")
            if source_finding_kind and source_finding_value:
                finding = self._shared_findings.get((source_finding_kind, source_finding_value))
                if finding and finding.source_node_id:
                    source_node_id = finding.source_node_id
        if source_node_id and source_node_id != node_id:
            self._add_edge(
                node_id,
                source_node_id,
                kind="guided_by",
                step=step,
                condition=str(metadata.get("source_finding_kind") or ""),
                metadata={"value": str(metadata.get("source_finding_value") or "")},
            )

    def _latest_action_node_by_tool(self, tool: str, statuses: Optional[set[str]] = None) -> str:
        normalized_tool = str(tool or "").strip()
        if not normalized_tool:
            return ""
        candidates = [
            node
            for node in self._nodes.values()
            if node.kind == "action"
            and (node.canonical_tool == normalized_tool or node.expected_tool == normalized_tool)
            and (not statuses or node.status in statuses)
        ]
        if not candidates:
            return ""
        latest = max(candidates, key=lambda node: (node.updated_step, node.step, node.id))
        return latest.id

    def _latest_action_node_by_type(self, action_type: str, statuses: Optional[set[str]] = None) -> str:
        normalized_type = str(action_type or "").strip()
        if not normalized_type:
            return ""
        candidates = [
            node
            for node in self._nodes.values()
            if node.kind == "action"
            and node.action_type == normalized_type
            and (not statuses or node.status in statuses)
        ]
        if not candidates:
            return ""
        latest = max(candidates, key=lambda node: (node.updated_step, node.step, node.id))
        return latest.id

    def _serialize_replan_node(self, node: GraphNode) -> Dict[str, Any]:
        metadata = self._normalize_replan_metadata(node.metadata)
        payload = {
            "node_id": node.id,
            "step": node.updated_step or node.step,
            "reason": str(metadata.get("reason") or node.result_preview or ""),
            "reason_code": str(metadata.get("reason_code") or ""),
            "reason_detail": str(metadata.get("reason_detail") or metadata.get("reason") or node.result_preview or ""),
            "blocked_action_ids": self._normalize_list(metadata.get("blocked_action_ids")),
            "blocked_tools": self._normalize_list(metadata.get("blocked_tools")),
            "avoid_action_ids": self._normalize_list(metadata.get("avoid_action_ids")),
            "avoid_tools": self._normalize_list(metadata.get("avoid_tools")),
            "avoid_lineages": self._normalize_list(metadata.get("avoid_lineages")),
            "blocked_findings": list(metadata.get("blocked_findings") or []),
            "alternative_candidates": list(metadata.get("alternative_candidates") or []),
            "selected_alternative": dict(metadata.get("selected_alternative") or {}),
            "source_finding_kind": str(metadata.get("source_finding_kind") or ""),
            "source_finding_value": str(metadata.get("source_finding_value") or ""),
            "verification_family": str(metadata.get("verification_family") or metadata.get("source_finding_kind") or ""),
            "source_action_id": str(metadata.get("source_action_id") or node.action_id or ""),
            "source_action_type": str(metadata.get("source_action_type") or node.action_type or ""),
            "source_node_id": str(metadata.get("source_node_id") or ""),
        }
        return payload

    def _active_chain(self, limit: int = 6) -> List[Dict[str, Any]]:
        nodes = sorted(
            self._nodes.values(),
            key=lambda node: (node.updated_step, node.step, node.id),
            reverse=True,
        )
        return [
            {
                "node_id": node.id,
                "kind": node.kind,
                "label": node.label,
                "status": node.status,
                "step": node.updated_step or node.step,
                "action_id": node.action_id,
                "action_type": node.action_type,
            }
            for node in nodes[:limit]
        ]

    @staticmethod
    def _normalize_list(values: Any) -> List[str]:
        if values is None:
            return []
        if isinstance(values, (list, tuple, set)):
            raw_values = values
        else:
            raw_values = [values]
        normalized: List[str] = []
        seen = set()
        for value in raw_values:
            text = str(value or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized.append(text)
        return normalized

    def _normalize_candidate(self, candidate: Any) -> Dict[str, Any]:
        if isinstance(candidate, dict):
            normalized = {
                "action_type": str(candidate.get("action_type") or candidate.get("type") or ""),
                "action_id": str(candidate.get("action_id") or candidate.get("id") or ""),
                "target": str(candidate.get("target") or ""),
                "description": str(candidate.get("description") or ""),
                "intent": str(candidate.get("intent") or ""),
                "expected_tool": str(candidate.get("expected_tool") or ""),
                "source_finding_kind": str(candidate.get("source_finding_kind") or ""),
                "source_finding_value": str(candidate.get("source_finding_value") or ""),
                "alternative_to": str(candidate.get("alternative_to") or ""),
                "derived_from": str(candidate.get("derived_from") or ""),
            }
            params = dict(candidate.get("params") or {})
            if params:
                normalized["params"] = params
            return {key: value for key, value in normalized.items() if value not in ("", [], {}, None)}
        text = str(candidate or "").strip()
        return {"action_type": text} if text else {}

    def _normalize_replan_metadata(self, metadata: Any) -> Dict[str, Any]:
        raw = dict(metadata or {})
        normalized: Dict[str, Any] = {}
        for key in (
            "reason",
            "reason_code",
            "reason_detail",
            "source_finding_kind",
            "source_finding_value",
            "source_action_id",
            "source_action_type",
            "source_node_id",
            "verification_family",
        ):
            value = str(raw.get(key) or "").strip()
            if value:
                normalized[key] = value

        blocked_action_ids = self._normalize_list(raw.get("blocked_action_ids") or raw.get("blocked_action_id"))
        blocked_tools = self._normalize_list(raw.get("blocked_tools") or raw.get("blocked_tool"))
        avoid_action_ids = self._normalize_list(raw.get("avoid_action_ids") or raw.get("avoid_action_id"))
        avoid_tools = self._normalize_list(raw.get("avoid_tools") or raw.get("avoid_tool"))
        avoid_lineages = self._normalize_list(raw.get("avoid_lineages") or raw.get("avoid_lineage"))
        blocked_findings = [
            item for item in (self._normalize_blocked_finding(finding) for finding in raw.get("blocked_findings") or []) if item
        ]
        alternative_candidates = [
            item for item in (self._normalize_candidate(candidate) for candidate in raw.get("alternative_candidates") or []) if item
        ]
        selected_alternative = self._normalize_candidate(raw.get("selected_alternative") or {})

        if blocked_action_ids:
            normalized["blocked_action_ids"] = blocked_action_ids
        if blocked_tools:
            normalized["blocked_tools"] = blocked_tools
        if avoid_action_ids:
            normalized["avoid_action_ids"] = avoid_action_ids
        if avoid_tools:
            normalized["avoid_tools"] = avoid_tools
        if avoid_lineages:
            normalized["avoid_lineages"] = avoid_lineages
        if blocked_findings:
            normalized["blocked_findings"] = blocked_findings
        if alternative_candidates:
            normalized["alternative_candidates"] = alternative_candidates
        if selected_alternative:
            normalized["selected_alternative"] = selected_alternative
        return normalized

    def _normalize_blocked_finding(self, finding: Any) -> Dict[str, Any]:
        if not isinstance(finding, dict):
            return {}
        normalized = {
            "kind": str(finding.get("kind") or "").strip(),
            "value": str(finding.get("value") or "").strip(),
            "verification_family": str(
                finding.get("verification_family") or finding.get("kind") or ""
            ).strip(),
        }
        return {key: value for key, value in normalized.items() if value}

    @staticmethod
    def _preview(result: Any, limit: int = 160) -> str:
        text = str(result or "").strip()
        if len(text) <= limit:
            return text
        return text[:limit] + "..."

    @staticmethod
    def _unique_values(values: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for value in values:
            normalized = str(value or "").strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(normalized)
        return ordered

    @staticmethod
    def _normalize_finding_value(value: Any) -> str:
        if isinstance(value, dict):
            raw = str(value.get("type") or value.get("value") or "")
        else:
            raw = str(value or "")
        return raw.strip()

    @staticmethod
    def _stable_id(*parts: str) -> str:
        payload = "::".join(parts)
        return hashlib.md5(payload.encode("utf-8")).hexdigest()[:12]
