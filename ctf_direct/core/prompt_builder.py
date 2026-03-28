"""
Prompt 构建器 - 直接模式的核心组件
将 target + skill + findings + tool_results 整合为 LLM prompt
"""
import json
from typing import Any, Dict, List


class PromptBuilder:
    """构建 LLM 推理 prompt"""

    def __init__(self):
        pass

    def build(self, context: Dict[str, Any]) -> str:
        """
        构建完整的推理 prompt

        Args:
            context: 包含 target、skill、rag、findings、tool_results 的字典

        Returns:
            格式化的 prompt 字符串
        """
        target = context.get("target", {})
        findings = context.get("findings", [])
        tool_results = context.get("tool_results", [])
        skill = context.get("skill", "")
        rag = context.get("rag", {})
        reasoning_history = context.get("reasoning_history", [])
        attack_plan = context.get("attack_plan")

        prompt_parts = []

        # === 题目信息 ===
        prompt_parts.append(self._build_target_section(target))

        # === 攻击计划（Phase 3.1: Strategic Supervisor）===
        if attack_plan and attack_plan.get("suggested_steps"):
            prompt_parts.append(self._build_attack_plan_section(attack_plan))

        # === Skill 知识 ===
        if skill:
            prompt_parts.append(f"\n## 针对性技能知识（最高优先级）\n{skill}\n")

        # === RAG 知识 ===
        if rag and rag.get("retrieved_knowledge"):
            prompt_parts.append(self._build_rag_section(rag))

        # === 已发现的线索 ===
        if findings:
            prompt_parts.append(self._build_findings_section(findings))

        # === 最近工具执行结果 ===
        if tool_results:
            prompt_parts.append(self._build_tool_results_section(tool_results))

        # === 最近推理历史 ===
        if reasoning_history:
            prompt_parts.append(self._build_history_section(reasoning_history))

        # === 可用工具 ===
        prompt_parts.append(self._build_tools_section(context.get("tools", [])))

        # === 决策要求 ===
        prompt_parts.append(self._build_instruction_section())

        return "\n".join(prompt_parts)

    def _build_target_section(self, target: Dict) -> str:
        url = target.get("url", "")
        hint = target.get("hint", "")
        problem_type = target.get("problem_type", "")
        tags = target.get("taxonomy_tags", [])

        section = ["## 当前题目"]
        section.append(f"- **URL**: {url}")
        if hint:
            section.append(f"- **Hint**: {hint}")
        if problem_type:
            section.append(f"- **题型**: {problem_type}")
        if tags:
            section.append(f"- **标签**: {', '.join(tags)}")

        return "\n".join(section)

    def _build_attack_plan_section(self, attack_plan: Dict) -> str:
        """Phase 3.1: Strategic Supervisor - 构建攻击计划部分"""
        lines = ["\n## 攻击计划（Strategic Supervisor 建议）"]
        lines.append("以下是基于题型的建议攻击路径，**非强制**，LLM 可根据实际情况调整：\n")

        suggested = attack_plan.get("suggested_steps", [])
        if suggested:
            lines.append("### 建议攻击步骤")
            for i, step in enumerate(suggested[:4], 1):
                lines.append(f"{i}. {step}")

        poc_hints = attack_plan.get("poc_hints", [])
        if poc_hints:
            lines.append("\n### 可用 POC 候选")
            for poc in poc_hints[:5]:
                lines.append(f"- `{poc}`")

        rag_insights = attack_plan.get("rag_insights", [])
        if rag_insights:
            lines.append("\n### RAG 知识补充")
            for insight in rag_insights[:2]:
                title = insight.get("title", "未知")
                method = insight.get("method", "")
                lines.append(f"- **{title}**: {method}")

        lines.append("\n*提示：如有已验证的发现，请优先跟进，不必严格遵循以上计划。*")
        return "\n".join(lines)

    def _build_findings_section(self, findings: List[Dict]) -> str:
        lines = ["\n## 已发现的线索（Findings）"]
        if not findings:
            lines.append("- 暂无")
            return "\n".join(lines)

        for f in findings[-10:]:  # 最近10条
            kind = f.get("kind", "")
            value = f.get("value", "")
            confirmed = "✓" if f.get("confirmed") else "?"
            lines.append(f"- [{confirmed}] {kind}: {value}")

        return "\n".join(lines)

    def _build_tool_results_section(self, tool_results: List[Dict]) -> str:
        lines = ["\n## 最近工具执行结果"]
        if not tool_results:
            lines.append("- 暂无")
            return "\n".join(lines)

        for r in tool_results[-5:]:  # 最近5条
            tool = r.get("tool", "?")
            args = r.get("args", {})
            output = r.get("output", "")
            success = r.get("success", True)
            step = r.get("step", "?")

            status = "✅" if success else "❌"
            args_str = json.dumps(args, ensure_ascii=False)[:100]

            lines.append(f"\n### Step {step} {status}: {tool}")
            lines.append(f"参数: {args_str}")
            # 只显示前500字符
            display_output = output[:500] + ("..." if len(output) > 500 else "")
            lines.append(f"输出:\n{display_output}")

        return "\n".join(lines)

    def _build_rag_section(self, rag: Dict) -> str:
        lines = ["\n## 相似题目参考（RAG）"]
        query = rag.get("query", "")
        if query:
            lines.append(f"查询: {query}")

        knowledge = rag.get("retrieved_knowledge", [])
        if not knowledge:
            return "\n".join(lines)

        for k in knowledge[:3]:  # 最多3条
            title = k.get("title", "未知")
            method = k.get("method", "")
            content = k.get("content", "")[:300]
            relevance = k.get("relevance", 0)
            lines.append(f"\n### [{relevance:.2f}] {title}")
            if method:
                lines.append(f"方法: {method}")
            lines.append(f"内容: {content}...")

        suggested = rag.get("suggested_approach", "")
        if suggested:
            lines.append(f"\n**建议方向**: {suggested}")

        return "\n".join(lines)

    def _build_history_section(self, history: List[Dict]) -> str:
        lines = ["\n## 最近推理历史"]
        if not history:
            return "\n".join(lines)

        for msg in history[-5:]:  # 最近5条
            role = msg.get("role", "?")
            content = msg.get("content", "")[:200]
            lines.append(f"\n**{role}**: {content}...")

        return "\n".join(lines)

    def _build_tools_section(self, tools: List[Dict]) -> str:
        lines = ["\n## 可用工具"]

        if not tools:
            lines.append("无外部工具可用，只能通过对话与用户交流")
            return "\n".join(lines)

        lines.append("你可以通过以下工具与环境交互：")
        for t in tools:
            name = t.get("name", "?")
            desc = t.get("description", "")
            params = t.get("parameters", {})
            props = params.get("properties", {})
            required = params.get("required", [])

            lines.append(f"\n### {name}")
            lines.append(f"说明: {desc}")
            if props:
                lines.append("参数:")
                for pname, pdesc in props.items():
                    req_mark = "（必填）" if pname in required else "（可选）"
                    lines.append(f"  - {pname} {req_mark}: {pdesc.get('description', '')}")

        return "\n".join(lines)

    def _build_instruction_section(self) -> str:
        return """
## 推理要求

1. **基于以上信息做出决策**，不要重复已失败的尝试
2. **如果连续 3 次无新发现**，考虑换方向或请求 RAG 知识
3. **发现 flag 时**，输出 `FLAG{...}` 格式并停止
4. **优先利用针对性 skill 和 RAG 知识**，不要硬试

## 输出格式

**动作决策**（选一个）:
- 工具调用: `TOOL: tool_name | args: {...}`
- 推理: `THINK: 你的推理过程`
- 完成: `FINISHED: 最终结论`
- Flag: `FLAG{ctf_flag_here}`
"""
