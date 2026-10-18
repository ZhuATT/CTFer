"""AT1 submit —— 观察者判断书受理 CLI（批4 G1-F；协议=contracts/OBSERVER-INTERFACE.md）。

观察者在会话内运行本命令提交判断书：与执行器**同一套校验代码**逐条过——
全部合法：写 `.observer/SUBMITTED` 标记 + 打印"提交成功"退出码 0；
有坏条：逐条打印错误退出码 1（观察者可就地修正后重新提交，查重幂等无害）。

注意：本命令只校验+受理（标记），**不入图**——图唯一写手=driver 侧执行器
（轮末统一入库；直接改图会被 driver 内存态落盘覆盖，见批4 计划 G1-F）。
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import observer_harvest              # noqa: E402
from src.board import Blackboard              # noqa: E402


def main(engagement_root: str) -> int:
    root = Path(engagement_root)
    jp = root / ".observer" / "OBSERVER.json"
    if not jp.is_file():
        print("[submit] 判断书不存在：.observer/OBSERVER.json")
        return 1
    try:
        doc = json.loads(jp.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[submit] 判断书 JSON 无法解析：{e}")
        return 1
    if not isinstance(doc, dict) or not isinstance(doc.get("operations"), list) \
            or not doc["operations"]:
        print("[submit] 判断书 operations 缺失或为空")
        return 1

    noreport_rejects: set[str] = set()
    tp = root / ".observer" / "task.json"
    if tp.is_file():
        try:
            task = json.loads(tp.read_text(encoding="utf-8")) or {}
            noreport_rejects = set(task.get("noreport_rejects") or ())
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    # 在临时装载的黑板上跑与执行器完全相同的校验（root=None：不落盘不写 receipts）
    bb = Blackboard(str(root / ".at1" / "blackboard.json"))
    res = observer_harvest.apply_judgment(
        bb, doc, round=int(doc.get("round", 0) or 0),
        root=None, noreport_rejects=noreport_rejects)

    if res["rejects"]:
        print(f"[submit] 校验失败（{len(res['rejects'])} 条被拒）：")
        for r in res["rejects"]:
            print(f"  - 第{r.get('index', '?')}条 {r.get('op', '?')}：{r.get('error', '')}")
        print("[submit] 请修正 .observer/OBSERVER.json 后重新运行本命令")
        return 1

    marker = root / ".observer" / "SUBMITTED"
    marker.write_text(json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "ops": len(doc["operations"]),
        "applied": res["applied"],
    }, ensure_ascii=False), encoding="utf-8")
    print(f"[submit] 提交成功（{len(doc['operations'])} 条已受理，"
          f"新入图 {res['applied']} 条）——可以结束会话")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
