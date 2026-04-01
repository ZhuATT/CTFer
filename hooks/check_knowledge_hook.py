#!/usr/bin/env python3
"""
check_knowledge_hook.py - 解题状态上下文提供者

Phase 1 增强版：
- PreToolUse Hook 增强检查：
  1. 假设声明检查
  2. 方法失败检查
  3. 预算检查
  4. 阶段工具白名单检查
- PostToolUse 自动记录：在执行攻击命令前，自动记录上一次命令的结果

Hook 返回的 additionalContext 包含：
- 当前题目和已尝试的方法
- 失败记录和建议
- 可用的解题知识位置
- 循环检测警告
- 失败阈值触发时的强制重查消息
"""
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta

# 工作目录
WORKSPACE = Path(__file__).parent.parent.parent / "workspace"
STATE_FILE = WORKSPACE / "state.json"
LAST_COMMAND_FILE = WORKSPACE / ".last_command"
POST_RECORD_MARKER = WORKSPACE / ".post_record_pending"
KNOWLEDGE_LOG = WORKSPACE / ".knowledge_log"
ADVISOR_DIR = WORKSPACE / "advisor"
ADVISOR_LATEST = ADVISOR_DIR / "latest.json"

# 导入核心模块
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.loop_detector import (
    check_loop, LOOP_WARNING_MESSAGE, LOOP_BREAK_FORCE_MESSAGE
)
from core.state_manager import (
    get_state_manager, Phase, PHASE_CONFIG,
    is_tool_allowed, check_budget as check_budget_func,
    get_phase as get_phase_func, get_hypothesis as get_hypothesis_func
)
from core.phase_gate import (
    get_gate, check_phase_transition, get_transition_suggestion,
    Phase as PhaseEnum
)


def load_json(path: Path) -> Optional[Dict]:
    """加载 JSON 文件"""
    if not path.exists():
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def get_state_summary() -> str:
    """获取解题状态摘要"""
    state = load_json(STATE_FILE)
    if not state:
        return ""

    lines = []
    target = state.get("target", "未知")
    ctype = state.get("type", "未知")
    flag = state.get("flag", "")

    lines.append(f"【当前状态】")
    lines.append(f"- 靶机: {target}")
    lines.append(f"- 题型: {ctype}")
    lines.append(f"- Flag: {'已找到 ' + flag if flag else '未找到'}")

    findings = state.get("findings", [])
    if findings:
        lines.append(f"\n【已有发现】({len(findings)} 条)")
        for f in findings[-3:]:  # 只显示最近 3 条
            lines.append(f"  - {f}")

    methods = state.get("methods_tried", [])
    if methods:
        lines.append(f"\n【已尝试方法】({len(methods)} 条)")
        for m in methods[-3:]:
            lines.append(f"  - {m}")

    return "\n".join(lines)




def get_knowledge_info() -> str:
    """获取知识库信息"""
    knowledge_files = []

    # 技能知识
    skills_dir = Path(__file__).parent.parent.parent / "skills"
    if skills_dir.exists():
        for skill_file in skills_dir.glob("*/SKILL.md"):
            knowledge_files.append(f"skills/{skill_file.parent.name}/SKILL.md")

    # 经验知识
    experiences_dir = Path(__file__).parent.parent.parent / "memories" / "experiences"
    if experiences_dir.exists():
        for exp_file in experiences_dir.glob("*.md"):
            knowledge_files.append(f"memories/experiences/{exp_file.name}")

    if not knowledge_files:
        return ""

    lines = []
    lines.append(f"\n【可用知识库】({len(knowledge_files)} 个文件)")
    for kf in knowledge_files[:10]:  # 只显示前 10 个
        lines.append(f"  - {kf}")

    return "\n".join(lines)




def parse_command_signature(command: str) -> Tuple[Optional[str], Optional[str]]:
    """
    从完整命令字符串解析出工具名和参数字符串

    Args:
        command: 完整命令，如 "curl -s -k http://target.com" 或 "python -c \"import os\""

    Returns:
        (tool_name, args_str) 如 ("curl", "-s -k http://target.com")
    """
    if not command:
        return None, None

    command = command.strip()
    command_lower = command.lower()

    # 处理 python 路径（Windows 完整路径或普通 python 命令）
    # 例如: C:/Users/.../python.exe, python -c 等
    if ".exe" in command_lower:
        # 找到 .exe 的位置
        exe_pos = command_lower.find(".exe")
        # 检查 .exe 前面是否有 python
        before_exe = command_lower[:exe_pos]
        if "python" in before_exe:
            # 这是 python.exe，提取参数
            # 参数是从 .exe 之后开始的
            after_exe = command[exe_pos + 4:].strip()
            return "python", after_exe
        # 不是 python.exe，用原始的第一个单词作为工具名
        parts = command.split(" ", 1)
        return parts[0], parts[1] if len(parts) > 1 else ""
    elif command.startswith("python"):
        parts = command.split(" ", 1)
        if len(parts) > 1:
            return "python", parts[1]
        return "python", ""

    # 处理各种工具调用
    simple_tools = [
        "curl", "sqlmap", "dirsearch", "python3", "php", "node", "ruby", "perl",
        "bash", "sh", "grep", "cat", "ls", "cd", "pwd", "mkdir", "rm", "cp",
        "mv", "tar", "gzip", "gunzip", "unzip", "wget", "nc", "netcat", "nmap",
        "git", "docker", "pip", "uv", "docker", "docker-compose"
    ]

    for tool in simple_tools:
        if command.startswith(tool + " "):
            args = command[len(tool) + 1:].strip()
            return tool, args

    # 如果没有空格，整个命令就是工具名
    parts = command.split()
    if parts:
        return parts[0], " ".join(parts[1:]) if len(parts) > 1 else ""

    return None, None


def check_loop_detection(command: str) -> Optional[Tuple[str, str]]:
    """
    检测循环并返回状态和消息

    Returns:
        (status, message) 或 None
    """
    if not command:
        return None

    tool_name, args_str = parse_command_signature(command)
    if not tool_name:
        return None

    result = check_loop(tool_name, args_str if args_str else None)

    if result == "break":
        return "break", LOOP_BREAK_FORCE_MESSAGE
    elif result == "warn":
        return "warn", LOOP_WARNING_MESSAGE

    return None


def get_current_target() -> str:
    """获取当前靶机 URL"""
    state = load_json(STATE_FILE)
    return state.get("target", "") if state else ""


# ==================== 新增：上一次命令结果读写 ====================

def save_last_command(command: str, output: str, return_code: int = 0):
    """保存上一次命令结果，供下次 Hook 调用时分析"""
    LAST_COMMAND_FILE.write_text(
        json.dumps({
            "command": command,
            "output": output[:2000],  # 截断避免过大
            "return_code": return_code,
            "timestamp": datetime.now().isoformat()
        }, ensure_ascii=False),
        encoding="utf-8"
    )


def get_last_command_result() -> Optional[Dict[str, Any]]:
    """获取上一次命令结果"""
    if not LAST_COMMAND_FILE.exists():
        return None
    try:
        return json.loads(LAST_COMMAND_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, IOError):
        return None




# ==================== Phase 1 增强：假设声明检查 ====================

def check_hypothesis_declared() -> Tuple[bool, str]:
    """
    检查是否已声明当前假设

    Returns:
        (needs_declaration, message) - needs_declaration=True 表示需要声明
    """
    state = load_json(STATE_FILE)
    if not state:
        return False, ""  # 没有状态，不拦截

    hypothesis = state.get("current_hypothesis", "")
    phase = state.get("phase", Phase.RECON)

    # Identify 和 Exploit 阶段必须声明假设
    if phase in [Phase.IDENTIFY, Phase.EXPLOIT] and not hypothesis:
        return True, HYPOTHESIS_REQUIRED_MESSAGE

    return False, ""


HYPOTHESIS_REQUIRED_MESSAGE = """
═══════════════════════════════════════════════════════════════════════
🛑 【Phase Gate】请先声明当前假设

在继续攻击之前，必须明确回答：

1. 目标漏洞类型：______
2. 攻击向量：______
3. 预期结果：______

格式示例：
假设：LFI漏洞，通过日志文件包含执行代码
向量：注入PHP到UA头，包含access.log
预期：日志包含后执行id命令

请在回答前不要执行任何攻击工具。
═══════════════════════════════════════════════════════════════════════
"""

# ==================== P0: 攻击命令拦截 ====================

ATTACK_COMMANDS = ["sqlmap", "dirsearch", "nikto", "gobuster", "wfuzz", "hydra", "nmap", "wpscan", "ffuf", "dirb", "dirbuster", "medusa", "ncrack"]

def is_attack_command(command: str) -> bool:
    """判断是否为攻击性命令"""
    cmd_lower = command.lower()
    return any(x in cmd_lower for x in ATTACK_COMMANDS)

def check_findings_required(command: str) -> Tuple[bool, str]:
    """攻击命令需要先记录发现"""
    if not is_attack_command(command):
        return False, ""

    state = load_json(STATE_FILE)
    if not state:
        return False, ""

    findings = state.get("findings", [])
    if not findings:
        return True, """
═══════════════════════════════════════════════════════════════════════
🛑 【拦截】攻击命令需要先记录发现

你没有记录任何发现（findings=[]），攻击前请先：
  add_finding('你的发现')

例如：add_finding('发现登录表单，密码在JS中硬编码')
═══════════════════════════════════════════════════════════════════════
"""
    return False, ""




# ==================== Phase 1 增强：预算检查 ====================

def check_phase_budget() -> Tuple[bool, str]:
    """
    检查当前阶段预算是否耗尽

    Returns:
        (budget_exceeded, message)
    """
    state = load_json(STATE_FILE)
    if not state:
        return False, ""

    phase = state.get("phase", Phase.RECON)
    step_count = state.get("step_count", 0)
    budget = PHASE_CONFIG.get(phase, {}).get("budget", 8)
    hypothesis = state.get("current_hypothesis", "未声明")
    hypothesis_status = state.get("hypothesis_status", "unverified")

    if step_count >= budget:
        msg = BUDGET_EXCEEDED_MESSAGE.format(
            phase=phase,
            step_count=step_count,
            budget=budget,
            hypothesis=hypothesis,
            hypothesis_status=hypothesis_status
        )
        return True, msg

    return False, ""


BUDGET_EXCEEDED_MESSAGE = """
═══════════════════════════════════════════════════════════════════════
🛑 【预算耗尽】{phase} 阶段预算已用完（{step_count}/{budget}）

当前进度：
- 假设：{hypothesis}
- 假设状态：{hypothesis_status}

请评估：
- 是否已确定攻击向量？
- 是否需要返回 Recon 重新收集？
- 还是切换到 Exploit 尝试新方法？
═══════════════════════════════════════════════════════════════════════
"""


# ==================== Phase 1 增强：阶段工具白名单检查 ====================

def check_tool_whitelist(tool_name: str) -> Tuple[bool, str]:
    """
    检查工具是否在当前阶段白名单中

    Returns:
        (not_allowed, message)
    """
    state = load_json(STATE_FILE)
    if not state:
        return False, ""

    phase = state.get("phase", Phase.RECON)
    allowed_tools = PHASE_CONFIG.get(phase, {}).get("allowed_tools", [])

    # Flag 阶段没有工具限制
    if phase == Phase.FLAG or not allowed_tools:
        return False, ""

    if tool_name not in allowed_tools:
        msg = TOOL_NOT_ALLOWED_MESSAGE.format(
            tool=tool_name,
            phase=phase,
            allowed=", ".join(allowed_tools)
        )
        return True, msg

    return False, ""


TOOL_NOT_ALLOWED_MESSAGE = """
═══════════════════════════════════════════════════════════════════════
🛑 【阶段工具检查】{tool} 不在当前阶段白名单中

当前阶段：{phase}
允许的工具：{allowed}

请：
1. 使用该阶段允许的工具继续攻击
2. 或者切换到正确的阶段
═══════════════════════════════════════════════════════════════════════
"""

# ==================== Phase 4: 顾问审查通知 ====================

def get_advisor_notice() -> str:
    """
    检查是否有未读的顾问建议

    Returns:
        格式化的顾问通知文本，如果有新建议的话
    """
    if not ADVISOR_LATEST.exists():
        return ""

    try:
        advice = json.loads(ADVISOR_LATEST.read_text(encoding="utf-8"))
        state = load_json(STATE_FILE)
        if not state:
            return ""

        last_advisor_read = state.get("last_advisor_read", "")

        # 检查是否有新的顾问建议
        if advice.get("timestamp") != last_advisor_read:
            # 更新 last_advisor_read
            state["last_advisor_read"] = advice.get("timestamp")
            STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

            return format_advisor_notice(advice)
    except (json.JSONDecodeError, IOError, TypeError):
        pass
    return ""


def format_advisor_notice(advice: dict) -> str:
    """格式化顾问通知"""
    verdict = advice.get("verdict", "proceed")
    reasoning = advice.get("reasoning", "")
    suggestions = advice.get("suggestions", [])
    review_type = advice.get("review_type", "review")
    priority = advice.get("priority", 2)

    # verdict 颜色标记
    verdict_icon = {"proceed": "✅", "pause": "⚠️", "pivot": "🔄"}.get(verdict, "📋")

    lines = [
        f"\n{'='*70}",
        f"{verdict_icon} 【顾问审查】{review_type} (优先级: {priority})",
        f"verdict: {verdict}",
        f"reasoning: {reasoning}"
    ]

    if suggestions:
        lines.append("suggestions:")
        for s in suggestions:
            lines.append(f"  - {s}")

    lines.append(f"{'='*70}")
    return "\n".join(lines)


# ==================== 重写：Hook 主函数 ====================

def get_context_for_llm(command: str) -> Dict[str, Any]:
    """
    Phase 2 增强版 Hook 上下文生成器

    流程：
    0. 自动记录上一次命令结果（PostToolUse 模拟）
    1. 解析命令获取工具名和参数
    2. Phase 1 增强检查：
       - 假设声明检查
       - 方法失败检查
       - 预算检查
       - 阶段工具白名单检查
       - 语义级循环检测
    3. Phase 2 新增：
       - 阶段转换建议检查
    4. 原有检查：
       - 循环检测（签名级）
       - 失败阈值检查
    5. 注入所有警告和建议到 additionalContext
    """
    context_parts = []
    target = ""

    # ========== 0. PostToolUse: 自动记录上一次命令 ==========
    try:
        record_result = auto_record_last_command()
    except Exception as e:
        # 单个检查出错不影响其他检查
        pass

    # ========== 获取目标 ==========
    try:
        target = get_current_target()
    except Exception:
        pass

    # ========== 解析命令 ==========
    tool_name, args_str = None, None
    try:
        tool_name, args_str = parse_command_signature(command)
    except Exception:
        pass

    # ========== Phase 1 增强：PreToolUse 检查 ==========

    # 0. 第一次攻击时自动触发初始顾问审查
    try:
        state = load_json(STATE_FILE)
        if state and state.get("step_count", 0) == 0 and state.get("target"):
            try:
                from core.advisor import review_initial
                advice = review_initial()
                if advice:
                    context_parts.append(format_advisor_notice(advice))
            except Exception:
                pass
    except Exception:
        pass

    # 1. 检查假设声明（Identify/Exploit 阶段必须声明假设）
    try:
        needs_hypothesis, hypothesis_msg = check_hypothesis_declared()
        if needs_hypothesis:
            context_parts.append(hypothesis_msg)
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "Hypothesis not declared - please declare your hypothesis before attacking",
                    "additionalContext": "\n".join(context_parts)
                }
            }
    except Exception:
        pass

    # P0: 攻击命令需要先有发现
    try:
        needs_findings, findings_msg = check_findings_required(command)
        if needs_findings:
            context_parts.append(findings_msg)
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "No findings recorded - please call add_finding() first",
                    "additionalContext": "\n".join(context_parts)
                }
            }
    except Exception:
        pass

    # 3. 检查预算（硬限制）
    try:
        budget_exceeded, budget_msg = check_phase_budget()
        if budget_exceeded:
            context_parts.append(budget_msg)
            # 调用顾问获取预算耗尽时的建议
            try:
                from core.advisor import review
                state = load_json(STATE_FILE)
                phase = state.get("phase", "recon") if state else "recon"
                advice = review("budget_exceeded",
                    question=f"{phase}阶段预算耗尽，应该继续还是换方向？",
                    state_override=state
                )
                if advice and advice.get("suggestions"):
                    context_parts.append("\n顾问建议:")
                    for s in advice["suggestions"][:3]:
                        context_parts.append(f"  - {s}")
                if advice and advice.get("verdict"):
                    context_parts.append(f"顾问 verdict: {advice['verdict']}")
            except Exception:
                pass
            # 硬限制：拦截
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "Budget exceeded",
                    "additionalContext": "\n".join(context_parts)
                }
            }
    except Exception:
        pass

    # ========== Phase 2 新增：阶段转换建议 ==========
    try:
        transition_suggestion = get_transition_suggestion()
        if transition_suggestion:
            context_parts.append(f"\n{'='*70}\n{transition_suggestion}\n{'='*70}")
    except Exception:
        pass

    # P4: Recon 阶段使用攻击命令时的提示
    try:
        state = load_json(STATE_FILE)
        if state and state.get("phase") == Phase.RECON and is_attack_command(command):
            context_parts.append("""
💡 【提示】你还在 recon 阶段，考虑切换到 identify：
  try_set_phase('identify')
""")
    except Exception:
        pass

    # 5. 基于计数的自动顾问触发（不再依赖失败检测）
    # 每 3 次尝试自动触发一次顾问审查
    try:
        state = load_json(STATE_FILE)
        if state and target:
            step_count = state.get("step_count", 0)
            # 达到 3/6/9 次时自动触发顾问
            if step_count > 0 and step_count % 3 == 0:
                try:
                    from core.advisor import review
                    advice = review("periodic",
                        question=f"已尝试 {step_count} 次，是否应该换方向或调整策略？",
                        state_override=state
                    )
                    if advice:
                        context_parts.append(format_advisor_notice(advice))
                except Exception:
                    pass
    except Exception:
        pass

    # 6. 签名级循环检测
    try:
        loop_result = check_loop_detection(command)
        if loop_result:
            loop_status, loop_msg = loop_result
            context_parts.append(loop_msg)

            # break 级别强制中断
            if loop_status == "break":
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": "Loop detection triggered - too many repeated attempts",
                        "additionalContext": "\n".join(context_parts)
                    }
                }
    except Exception:
        pass

    # ========== 9. 注入上一次命令结果 ==========
    try:
        last_result = get_last_command_result()
        if last_result:
            last_output = last_result.get("output", "")[:500]
            if last_output:
                context_parts.append(f"【上次命令输出】\n{last_output}")
    except Exception:
        pass

    # ========== 10. 状态摘要 ==========
    try:
        state_summary = get_state_summary()
        if state_summary:
            context_parts.insert(0, state_summary)
    except Exception:
        pass

    # ========== 11. 知识库信息 ==========
    try:
        if target:
            knowledge_info = get_knowledge_info()
            if knowledge_info:
                context_parts.append(knowledge_info)
    except Exception:
        pass

    # ========== 13. 知识库提示 ==========
    try:
        if not target:
            context_parts.append("\n📋 提示：这是新的解题任务，请先用 curl 访问目标识别题型。")
    except Exception:
        pass

    # ========== Phase 4: 顾问审查通知 ==========
    try:
        advisor_notice = get_advisor_notice()
        if advisor_notice:
            context_parts.append(advisor_notice)
    except Exception:
        pass

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "Auto-approved by check_knowledge_hook",
            "additionalContext": "\n".join(context_parts)
        }
    }


# ==================== 重写：main 函数 ====================

# ==================== Phase 1 PostToolUse: 自动记录上一次命令结果 ====================

def parse_tool_name_from_command(command: str) -> str:
    """从命令中解析工具名"""
    if not command:
        return ""

    command = command.strip()

    # python 路径（Windows 完整路径）
    if ".exe" in command and "python" in command.lower():
        return "python"
    if command.startswith("python"):
        return "python"

    # 简单工具名列表
    simple_tools = [
        "curl", "sqlmap", "dirsearch", "python3", "php", "node", "ruby", "perl",
        "bash", "sh", "grep", "cat", "ls", "cd", "pwd", "mkdir", "rm", "cp",
        "mv", "tar", "gzip", "gunzip", "unzip", "wget", "nc", "netcat", "nmap",
        "git", "docker", "pip", "uv", "docker-compose", "java", "ruby"
    ]

    for tool in simple_tools:
        if command.startswith(tool + " "):
            return tool
        if command == tool:
            return tool

    # 如果没有匹配，返回第一个单词
    parts = command.split()
    if parts:
        return parts[0]

    return ""




def auto_record_last_command() -> str:
    """
    自动记录上一次命令执行结果（PostToolUse Hook 模拟）

    在 PreToolUse Hook 执行前调用，检查是否需要记录上一次命令的结果。
    这样可以在下一次命令执行前自动：
    1. add_method() - 记录已使用的方法
    2. increment_step() - 更新当前阶段步数

    Returns:
        记录结果描述（用于调试）
    """
    last_result = get_last_command_result()
    if not last_result:
        return "无上一次命令结果，跳过记录"

    # 检查是否已记录（避免重复记录）
    if POST_RECORD_MARKER.exists():
        try:
            marker = json.loads(POST_RECORD_MARKER.read_text(encoding="utf-8"))
            last_recorded_time = marker.get("timestamp", "")
            last_command = marker.get("command", "")

            # 如果上次记录的命令和当前一致，跳过
            if last_recorded_time == last_result.get("timestamp", "") and last_command == last_result.get("command", ""):
                return "已记录过，跳过"
        except (json.JSONDecodeError, IOError):
            pass
    else:
        marker = {"timestamp": "", "command": "", "recorded": False}

    command = last_result.get("command", "")
    output = last_result.get("output", "")
    return_code = last_result.get("return_code", 0)

    # 解析工具名
    tool_name = parse_tool_name_from_command(command)
    if not tool_name:
        return f"无法识别工具名: {command[:50]}"

    # 1. 添加方法到状态
    state = load_json(STATE_FILE)
    if state:
        methods_tried = state.get("methods_tried", [])
        if tool_name not in methods_tried:
            methods_tried.append(tool_name)
            state["methods_tried"] = methods_tried

        # 2. 增加步数
        step_count = state.get("step_count", 0) + 1
        state["step_count"] = step_count

        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


    # 标记已记录
    marker = {
        "timestamp": last_result.get("timestamp", ""),
        "command": last_result.get("command", ""),
        "recorded": True,
        "tool": tool_name,
        "success": True
    }
    POST_RECORD_MARKER.write_text(json.dumps(marker, ensure_ascii=False), encoding="utf-8")

    return f"✓ PostRecord: {tool_name} 成功 (step: {step_count if state else '?'})"


def main():
    """
    Hook 入口

    流程：
    1. 读取当前命令
    2. 检查循环和失败阈值
    3. 将上一次命令结果注入额外上下文
    4. 返回给 LLM
    """
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        print("{}", flush=True)
        return

    # 提取命令
    command = ""
    if isinstance(input_data, dict):
        tool_input = input_data.get("tool_input", {})
        if isinstance(tool_input, dict):
            command = tool_input.get("command", "")
        elif isinstance(tool_input, str):
            command = tool_input

    # 获取上下文（包含上一次命令失败分析）
    result = get_context_for_llm(command)

    # 将上一次命令结果注入 additionalContext（让 LLM 知道上一次的输出）
    last_result = get_last_command_result()
    if last_result:
        output_snippet = last_result.get("output", "")[:500]
        if output_snippet:
            result["hookSpecificOutput"]["additionalContext"] += (
                f"\n\n【上次命令输出】\n{output_snippet}"
            )

    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
