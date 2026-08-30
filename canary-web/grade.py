# -*- coding: utf-8 -*-
"""canary-web 对分（M4 版）——真洞检出率 + 干扰项误报 + 证据锚定率。

输入改为 engagement 目录：读 .at1/_blackboard.json 的 findings（观察者
assessment-based 判定），不再吃旧 claims/verdicts JSON（旧架构已废弃）。
判定线不变：检出 ≥3 且 干扰项误报 = 0。
"""
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # git-bash/GBK 控制台兼容

VULNS = [
    {"id": "V1", "endpoint": "/api/order/detail", "desc": "idor 读（B 手机号 marker）"},
    {"id": "V2", "endpoint": "/api/address/update", "desc": "idor 写（改 B 地址+读回）"},
    {"id": "V3", "endpoint": "/admin/config/update", "desc": "authbypass（无角色校验）"},
    {"id": "V4", "endpoint": "/search", "desc": "sqli 报错+UNION"},
]
NOISE_ENDPOINTS = ["/static/app.js.map", "/redirect", "/internal/status"]
CLOSED_DOOR = "/admin/userList"


def _match_endpoint(f_ep, gt_ep):
    f_ep, gt_ep = (f_ep or ""), gt_ep
    return gt_ep in f_ep or f_ep.rstrip("/") in gt_ep


def main(engagement_dir: str):
    bb_path = Path(engagement_dir) / ".at1" / "_blackboard.json"
    if not bb_path.is_file():
        print(f"[grade] 找不到黑板：{bb_path}")
        return 2
    bb = json.loads(bb_path.read_text(encoding="utf-8"))
    findings = bb.get("findings", [])

    detected, confirmed = set(), set()
    fps = []
    anchored = 0
    for f in findings:
        ep = str(f.get("endpoint", ""))
        blob = (ep + " " + str(f.get("summary", ""))).lower()
        if f.get("evidence_verified"):
            anchored += 1
        if f.get("assessment") != "confirmed":
            continue                          # 只对 confirmed 判定检出/误报
        for gt in VULNS:
            if _match_endpoint(ep, gt["endpoint"]):
                detected.add(gt["id"])
                confirmed.add(gt["id"])
        if any(n in blob for n in NOISE_ENDPOINTS):
            fps.append((f.get("id"), "干扰端点被 confirmed", ep))
        elif CLOSED_DOOR in blob and "403" not in blob:
            fps.append((f.get("id"), "关门当洞报（应记阴性）", ep))

    lines = [f"真洞检出 {len(detected)}/{len(VULNS)}（confirmed {len(confirmed)}）"]
    for gt in VULNS:
        mark = "✓" if gt["id"] in detected else "✗"
        lines.append(f"  {mark} {gt['id']} {gt['desc']}")
    lines.append(f"干扰项误报 {len(fps)}")
    for fid, why, ep in fps:
        lines.append(f"  ✗ {fid} {why}: {ep}")
    if findings:
        lines.append(f"证据锚定 {anchored}/{len(findings)}（evidence_verified）")
    false_pos = [f for f in findings
                 if f.get("assessment") in ("likely_false_positive", "duplicate")]
    if false_pos:
        lines.append(f"已否决/判重 {len(false_pos)} 条: " + " ".join(
            f"{f.get('id')}({str(f.get('reason',''))[:30]})" for f in false_pos))
    ok = len(detected) >= 3 and not fps
    lines.append(f"\n结论：{'PASS' if ok else 'FAIL'}（判定线：检出≥3 且 误报=0）")
    out = "\n".join(lines)
    print(out)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
