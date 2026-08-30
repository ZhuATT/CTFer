# -*- coding: utf-8 -*-
"""canary-web 对分（phase3 附录 D）——真洞检出率 + 干扰项误报 + 格式合规。"""
import json
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # git-bash/GBK 控制台兼容

VULNS = [
    {"id": "V1", "class": "idor_read", "endpoint": "/api/order/detail", "desc": "idor 读（B 手机号 marker）"},
    {"id": "V2", "class": "idor_write", "endpoint": "/api/address/update", "desc": "idor 写（改 B 地址+读回）"},
    {"id": "V3", "class": "authbypass", "endpoint": "/admin/config/update", "desc": "authbypass（无角色校验）"},
    {"id": "V4", "class": "sqli_error", "endpoint": "/search", "desc": "sqli 报错+UNION"},
]
NOISE_ENDPOINTS = ["/static/app.js.map", "/redirect", "/internal/status"]
NOISE_HINTS = ["access-control-allow-origin", "server\":", "x-powered-by", "instance", "i-0abc", "10.2.3.4"]
CLOSED_DOOR = "/admin/userList"


def _match_endpoint(claim_ep, gt_ep):
    return gt_ep in (claim_ep or "") or (claim_ep or "") in gt_ep


def main(path):
    data = json.load(open(path, encoding="utf-8"))
    claims = {c["id"]: c for c in data["claims"]}
    verdicts = {v["claim_id"]: v for v in data["verdicts"]}

    detected, confirmed = set(), set()
    fps = []
    for cid, c in claims.items():
        v = verdicts.get(cid, {})
        for gt in VULNS:
            if _match_endpoint(c["endpoint"], gt["endpoint"]) and (
                    c["class"] in (gt["class"], "sqli_diff") if gt["class"] == "sqli_error"
                    else c["class"] == gt["class"]):
                detected.add(gt["id"])
                if v.get("verdict") == "confirmed":
                    confirmed.add(gt["id"])
        # 干扰项误报：claim 指向干扰端点，或 marker/endpoint 明显是噪音内容
        blob = (c["endpoint"] or "").lower()
        if any(n in blob for n in NOISE_ENDPOINTS):
            fps.append((cid, "干扰端点", blob))
        elif any(h in blob for h in NOISE_HINTS):
            fps.append((cid, "噪音内容当发现", blob))
        elif CLOSED_DOOR in blob and c["class"] == "authbypass" and v.get("verdict") not in ("immune",):
            fps.append((cid, "关门当 bypass 报", blob))

    lines = []
    lines.append(f"真洞检出 {len(detected)}/{len(VULNS)}（confirmed {len(confirmed)}）")
    for gt in VULNS:
        mark = "✓" if gt["id"] in detected else "✗"
        conf = "（confirmed）" if gt["id"] in confirmed else ""
        lines.append(f"  {mark} {gt['id']} {gt['desc']}{conf}")
    lines.append(f"干扰项误报 {len(fps)}")
    for cid, why, blob in fps:
        lines.append(f"  ✗ {cid} {why}: {blob}")
    immune = [v for v in verdicts.values() if v.get("verdict") == "immune"]
    if immune:
        lines.append(f"阴性记录（关门素材，非误报）: {len(immune)} 条")
    ok = len(detected) >= 3 and not fps
    lines.append(f"\n结论：{'PASS' if ok else 'FAIL'}（判定线：检出≥3 且 误报=0）")
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
