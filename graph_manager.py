from __future__ import annotations

import hashlib
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
        existing = self._nodes.get(node_id)
        if existing is None:
            metadata = {
                "intent": str(action.get("intent") or ""),
                "params": dict(action.get("params") or {}),
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
            if op:
                existing.metadata["graph_op"] = dict(op)

        if self.active_node_id and self.active_node_id != node_id:
            self._add_edge(self.active_node_id, node_id, kind="next", step=step)
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
        current_step = len(getattr(memory, "steps", []) or [])

        if target is not None:
            for endpoint in getattr(target, "endpoints", []) or []:
                self.upsert_shared_finding("endpoint", endpoint, step=current_step)
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

    def planner_signals(self) -> Dict[str, Any]:
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

        latest_guidance = self.latest_finding("guidance")
        latest_endpoint = self.latest_finding("endpoint")
        latest_parameter = self.latest_finding("parameter")
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
            "succeeded_action_ids": self._unique_values([node.action_id for node in succeeded_nodes if node.action_id]),
            "active_node_id": self.active_node_id,
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
        if self.active_node_id:
            parts.append(f"active={self.active_node_id}")
        return ", ".join(parts)

    def snapshot(self) -> Dict[str, Any]:
        nodes = sorted(self._nodes.values(), key=lambda node: (node.step, node.id))
        return {
            "version": 1,
            "active_node_id": self.active_node_id,
            "nodes": [asdict(node) for node in nodes],
            "edges": [asdict(edge) for edge in self._edges],
            "shared_findings": self.get_shared_findings(),
            "stats": {
                "node_count": len(self._nodes),
                "edge_count": len(self._edges),
                "finding_count": len(self._shared_findings),
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
