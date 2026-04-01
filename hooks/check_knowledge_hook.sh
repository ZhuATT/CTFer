#!/bin/bash
# check_knowledge_hook.sh - 强制知识检查的 PreToolUse Hook
# 在执行 curl/sqlmap/dirsearch 前验证是否已完成知识准备

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE="$PROJECT_ROOT/workspace"
MARKER_FILE="$WORKSPACE/.knowledge_checked"

# 需要知识准备的命令模式
NEED_KNOWLEDGE_PATTERNS="curl.*-s|sqlmap_tool\.py|dirsearch_tool\.py|python.*sqlmap|python.*dirsearch"

# 从 stdin 读取 hook 输入 (JSON)
read -r INPUT

# 提取命令
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

if [[ -z "$COMMAND" ]]; then
    # 无法提取命令，放行
    echo '{}'
    exit 0
fi

# 检查命令是否需要知识准备
if echo "$COMMAND" | grep -qE "$NEED_KNOWLEDGE_PATTERNS"; then
    # 这是需要知识的工具命令
    if [[ ! -f "$MARKER_FILE" ]]; then
        # 没有检查过知识，拒绝执行并注入提醒
        echo '{"continue": true, "hookSpecificOutput": {"additionalContext": "【知识检查提醒】你即将执行攻击工具但尚未查询知识！\n\n请先完成以下步骤：\n1. python -c \"from core.rag_knowledge import search_knowledge; print(search_knowledge(...))\"\n2. Read skills/<type>/SKILL.md\n3. Read memories/experiences/<type>.md\n\n执行后再重试此命令。"}, "systemMessage": "请先查询知识！"}'
        exit 0
    fi

    # 检查 marker 是否过期（超过 30 分钟）
    if [[ -f "$MARKER_FILE" ]]; then
        FILE_TIME=$(stat -c %Y "$MARKER_FILE" 2>/dev/null || stat -f %m "$MARKER_FILE" 2>/dev/null)
        NOW=$(date +%s)
        DIFF=$((NOW - FILE_TIME))
        if [[ $DIFF -gt 1800 ]]; then
            # 超过 30 分钟，重新提醒
            echo '{"continue": true, "hookSpecificOutput": {"additionalContext": "【知识检查提醒】距离上次查询知识已超过 30 分钟，请确认当前思路是否仍然有效。\n\n建议：python -c \"from core.rag_knowledge import search_knowledge; print(search_knowledge(...))\" 重新检索。"}, "systemMessage": "知识查询可能已过期"}'
            exit 0
        fi
    fi
fi

# 放行
echo '{}'
exit 0
