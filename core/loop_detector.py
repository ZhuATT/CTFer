"""
LoopDetector - 签名级循环检测组件

通过追踪工具调用的签名（tool_name + args），检测是否陷入重复执行。
相比简单的失败次数计数，签名级检测能精确区分"真正的循环"和"合理的重试"。

参考 ctf-agent2/backend/loop_detect.py 实现
"""
import json
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union, List


@dataclass
class LoopDetector:
    """
    追踪最近工具调用签名，检测重复循环

    Attributes:
        window: 滑动窗口大小，默认12
        warn_threshold: 警告阈值，默认3次相同签名
        break_threshold: 强制中断阈值，默认5次相同签名
    """

    window: int = 12
    warn_threshold: int = 3
    break_threshold: int = 5
    _recent: deque = field(init=False)

    def __post_init__(self) -> None:
        self._recent = deque(maxlen=self.window)

    def check(self, tool_name: str, args: Optional[Union[dict, str]] = None) -> Optional[str]:
        """
        检查是否陷入循环

        Args:
            tool_name: 工具名称（如 curl, sqlmap, python）
            args: 工具参数，dict 或 str

        Returns:
            None: 无循环
            "warn": 接近循环阈值（3次）
            "break": 超过循环阈值（5次），应强制中断
        """
        # 生成签名
        if args:
            if isinstance(args, dict):
                raw = json.dumps(args, sort_keys=True)
            else:
                raw = str(args)
            sig = f"{tool_name}:{raw[:500]}"
        else:
            sig = tool_name

        self._recent.append(sig)

        # 统计窗口内相同签名出现次数
        count = sum(1 for s in self._recent if s == sig)
        if count >= self.break_threshold:
            return "break"
        if count >= self.warn_threshold:
            return "warn"
        return None

    @property
    def last_sig(self) -> str:
        """获取最近一次签名字符串"""
        return self._recent[-1] if self._recent else ""

    def reset(self) -> None:
        """清除所有记录"""
        self._recent.clear()

    def get_recent_sigs(self) -> List[str]:
        """获取最近的签名列表（用于调试）"""
        return list(self._recent)

    def export_state(self) -> dict:
        """导出状态用于持久化"""
        return {
            "recent": list(self._recent),
            "window": self.window,
            "warn_threshold": self.warn_threshold,
            "break_threshold": self.break_threshold,
        }

    def import_state(self, state: dict) -> None:
        """从持久化状态恢复"""
        self._recent = deque(state.get("recent", []), maxlen=self.window)


# 持久化文件路径
LOOP_STATE_FILE = Path(__file__).parent.parent / "workspace" / ".loop_state.json"

# 全局实例
_detector: Optional[LoopDetector] = None


def get_detector() -> LoopDetector:
    """获取 LoopDetector 单例（跨进程需要手动 save/load）"""
    global _detector
    if _detector is None:
        _detector = LoopDetector()
        # 尝试从文件恢复状态
        load_state()
    return _detector


def save_state() -> None:
    """保存状态到文件（跨进程持久化）"""
    detector = get_detector()
    state = detector.export_state()
    LOOP_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOOP_STATE_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def load_state() -> None:
    """从文件加载状态"""
    if LOOP_STATE_FILE.exists():
        try:
            state = json.loads(LOOP_STATE_FILE.read_text(encoding="utf-8"))
            get_detector().import_state(state)
        except (json.JSONDecodeError, IOError):
            pass


# 快捷函数
def check_loop(tool_name: str, args: Optional[Union[dict, str]] = None) -> Optional[str]:
    """快捷函数：检查是否循环（并自动保存状态）"""
    result = get_detector().check(tool_name, args)
    save_state()  # 持久化以便跨进程
    return result


def reset_loop() -> None:
    """快捷函数：重置检测器"""
    get_detector().reset()
    save_state()


def get_last_sig() -> str:
    """快捷函数：获取最近签名"""
    return get_detector().last_sig


# 警告消息模板
LOOP_WARNING_MESSAGE = (
    "⚠️ **循环检测警告** — 检测到重复执行相同命令。\n"
    "你已多次执行完全相同的命令，建议：\n"
    "1. 停止重复，step back 重新分析\n"
    "2. 尝试不同的技术路径\n"
    "3. 查看 memories/experiences/ 中的成功经验\n"
    "4. 使用 get_all_type_knowledge() 重新获取解题知识\n"
)


LOOP_BREAK_MESSAGE = (
    "🛑 **循环中断** — 检测到反复执行相同命令，已强制中断当前循环。\n"
    "请重新审视问题：\n"
    "1. 这个方向是否正确？\n"
    "2. 是否有遗漏的信息？\n"
    "3. 尝试完全不同的攻击向量\n"
)

LOOP_BREAK_FORCE_MESSAGE = """
╔══════════════════════════════════════════════════════════════════════╗
║  🛑 循环中断 — 检测到反复执行完全相同的命令                         ║
║                                                                      ║
║  你必须立即：                                                         ║
║                                                                      ║
║  1. 停止执行当前命令（立即中断）                                       ║
║  2. step back，回顾之前所有命令的输出                                  ║
║  3. 回答以下问题：                                                    ║
║     - 攻击方向是否正确？                                              ║
║     - Payload 构造是否有误？                                          ║
║     - 是否遗漏了重要信息（响应头、源码、注释）？                    ║
║  4. 尝试完全不同的攻击向量                                            ║
║  5. 如有必要，重新调用 get_all_type_knowledge() 获取新知识             ║
║                                                                      ║
║  可能的问题：                                                         ║
║  - 当前漏洞类型判断错误（如实际是 SQL 注入而非 LFI）                   ║
║  - Payload 被过滤，需要更换 bypass 手法                                ║
║  - 目标不存在此漏洞，需要更换攻击面                                    ║
╚══════════════════════════════════════════════════════════════════════╝
"""
