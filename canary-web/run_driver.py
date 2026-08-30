# -*- coding: utf-8 -*-
"""canary-web × driver 全链路验收（P4.9，M4 验收 #1）。

流程：起靶 → 生成 engagement 三件套（真协议目录，非临时编排）→
driver.run_engagement（真主循环）→ grade.py 对分。
run_chain.py 冻结为对照（A4 时期）；本脚本是 M4 后唯一回归入口。

用法：source .secrets.env && python canary-web/run_driver.py [--keep] [--budget 3600]
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.driver import run_engagement          # noqa: E402

PORT = 8791
TARGET = f"http://127.0.0.1:{PORT}"

STATUS_TMPL = """# CanaryShop Engagement Status

## 漏洞表
| ID | 等级 | 标题 | 证据 |
|---|---|---|---|

## 攻击面
| 功能/端点 | 深度 | 测过什么 | 结论/免疫 |
|---|---|---|---|

## 已确认非漏洞

## 阻断项
（无）
"""

PRIOR_INTEL = """# 前置情报
- 本地授权测试靶 CanaryShop（电商），绑定 127.0.0.1，随便打
- 双账号：userA/userB，会话 cookie 形态见 /api/login（POST {\"user\":\"userA\"}）
- 侦察提示：首页链接覆盖主要功能区
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--budget", type=float, default=3600)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--timebox", type=int, default=900)
    args = ap.parse_args()

    tgt = subprocess.Popen(
        [sys.executable, str(Path(__file__).parent / "target.py")],
        env={**__import__("os").environ, "CANARY_PORT": str(PORT)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.5)
    probe = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", TARGET],
                           capture_output=True, text=True)
    if probe.stdout.strip() != "200":
        tgt.kill()
        print(f"[abort] 靶子没起来（{probe.stdout.strip()}）")
        return 2

    root = Path(tempfile.mkdtemp(prefix="at1-canary-drv-"))
    eng_dir = root / "engagement"
    (eng_dir / "state").mkdir(parents=True)
    (eng_dir / "notes").mkdir(parents=True)
    (eng_dir / "engagement.json").write_text(json.dumps({
        "target": TARGET, "mission": "结果类发现（越权/注入/未授权访问）",
        "date": "2026-08-30",
        "scope": {"allow": ["127.0.0.1"], "deny": []},
        "credentials": {},
    }, ensure_ascii=False), encoding="utf-8")
    (eng_dir / "state" / "status.md").write_text(STATUS_TMPL, encoding="utf-8")
    (eng_dir / "notes" / "prior-intel.md").write_text(PRIOR_INTEL, encoding="utf-8")

    print(f"[canary-driver] engagement={eng_dir}")
    try:
        rc = run_engagement(str(eng_dir), budget_s=args.budget, max_rounds=args.rounds)
    finally:
        tgt.kill()

    # grade 对分
    sys.path.insert(0, str(Path(__file__).parent))
    import grade
    print("\n===== grade =====")
    bb_path = eng_dir / ".at1" / "_blackboard.json"
    if bb_path.is_file():
        bb = json.loads(bb_path.read_text(encoding="utf-8"))
        print(f"[黑板 findings] {len(bb.get('findings', []))} 条")
        for f in bb.get("findings", []):
            print(f"  {f.get('id','?')} {f.get('assessment','?'):<22} "
                  f"{f.get('endpoint','?')} sev={f.get('severity','?')} "
                  f"锚={'Y' if f.get('evidence_verified') else 'N'}")
    grade_rc = grade.main(str(eng_dir))
    print(f"[result] driver 退出码 {rc}；现场：{root}"
          + ("（--keep）" if args.keep else ""))
    if not args.keep:
        shutil.rmtree(root, ignore_errors=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
