"""
ctf_direct 入口 - 直接模式主程序
用法：
    python ctf_direct/main.py --url <靶机URL> --hint <hint>
"""
import argparse
import json
import os
import sys
from pathlib import Path

# 添加项目根目录到 path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ctf_direct.core.file_state import FileState
from ctf_direct.core.llm_client import LLMClient
from ctf_direct.core.tool_executor import ToolExecutor
from ctf_direct.core.reasoner import DirectReasoner


def load_config() -> dict:
    """从 config.json 加载 LLM 配置"""
    config_path = PROJECT_ROOT / "config.json"
    if config_path.exists():
        with open(config_path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def main():
    parser = argparse.ArgumentParser(description="CTF Agent 直接模式")
    parser.add_argument("--url", required=True, help="靶机 URL")
    parser.add_argument("--hint", default="", help="题目 hint")
    parser.add_argument("--type", default="", help="题型（如 rce, sqli, auth）")
    parser.add_argument("--tags", nargs="*", default=[], help="标签列表")
    parser.add_argument("--max-steps", type=int, default=30, help="最大步数")
    parser.add_argument("--workspace", default=str(PROJECT_ROOT / "ctf_direct" / "workspace"), help="工作空间目录")
    args = parser.parse_args()

    # 加载 LLM 配置
    config = load_config()
    llm_config = config.get("llm", {})
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip() or llm_config.get("api_key", "")
    api_base = os.environ.get("ANTHROPIC_BASE_URL", "").strip() or llm_config.get("api_base", "")
    model = llm_config.get("model", "MiniMax-M2.5")

    if not api_key or not api_base:
        print("[Error] 请在 config.json 中配置 LLM API Key 和 Base URL")
        sys.exit(1)

    # 初始化工作空间
    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    # 初始化文件状态
    state = FileState(str(workspace))
    state.init_target(
        url=args.url,
        hint=args.hint,
        problem_type=args.type,
        tags=args.tags,
    )
    print(f"[Init] 靶机: {args.url}")
    print(f"[Init] 工作空间: {workspace}")

    # 初始化组件
    temperature = llm_config.get("temperature", 0.3)
    max_tokens = llm_config.get("max_tokens", 2000)

    llm_client = LLMClient(
        api_key=api_key,
        base_url=api_base,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    tool_executor = ToolExecutor()
    reasoner = DirectReasoner(
        workspace_dir=str(workspace),
        llm_client=llm_client,
        tool_executor=tool_executor,
    )

    # 运行推理
    result = reasoner.run(max_steps=args.max_steps)

    print(f"\n{'='*60}")
    print(f"执行完成: {result}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
