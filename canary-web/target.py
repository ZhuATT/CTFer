# -*- coding: utf-8 -*-
"""canary-web 靶（phase3 附录 D）——127.0.0.1 本地 Flask，验证层实机测试用。

4 真洞 + 7 干扰项 + 双账号 + 一扇关着的门。数据合成，永不部署。
"""
import re
import sqlite3

from flask import Flask, Response, jsonify, request

PORT = 8790
MARKER_PHONE = "13900000002"          # userB 手机号（idor marker）
SID = {"FAKE-sess-userA": "userA", "FAKE-sess-userB": "userB"}

USERS = {
    "userA": {"uid": 100, "name": "张三", "phone": "13900000001", "addr": "上海市浦东新区A路1号",
              "nickname": "<svg/onload=at1selfxss>"},
    "userB": {"uid": 20001, "name": "李四", "phone": MARKER_PHONE, "addr": "北京市朝阳区B路2号",
              "nickname": "正常昵称"},
}
ORDERS = {
    8822: {"buyer": "userA", "receiver": "张三", "receiver_phone": "13900000001"},
    8823: {"buyer": "userC", "receiver": "李四", "receiver_phone": MARKER_PHONE,
           "receiver_addr": "北京市朝阳区B路2号", "item": "笔记本电脑", "price": 5999},
}
ADDRESSES = {501: {"uid": 20001, "addr": "北京市朝阳区B路2号"},   # 属于 userB
             502: {"uid": 100, "addr": "上海市浦东新区A路1号"}}
BANNER = {"siteBanner": "欢迎光临"}

app = Flask(__name__)
_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.executescript(
    "CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT);"
    "CREATE TABLE users(uid INTEGER PRIMARY KEY, name TEXT, phone TEXT);")
_db.executemany("INSERT INTO items VALUES(?,?)", [(1, "键盘"), (2, "鼠标")])
_db.executemany("INSERT INTO users VALUES(?,?,?)",
                [(100, "张三", "13900000001"), (20001, "李四", MARKER_PHONE)])
_db.commit()


@app.after_request
def _noise(resp):
    resp.headers["Server"] = "CanaryWeb/1.0 (nginx-front)"        # 干扰⑦：版本指纹
    resp.headers["X-Powered-By"] = "Flask"                         # （无 CSP/X-Frame 等 → 干扰⑥）
    resp.headers["Access-Control-Allow-Origin"] = "*"              # 干扰①：CORS *
    return resp


def _who():
    return SID.get(request.cookies.get("session", ""))


@app.get("/")
def index():
    resp = Response("""<html><body><h1>CanaryShop</h1>
<a href="/api/item/list">商品</a> | <a href="/static/app.js">app.js</a> |
<a href="/redirect?url=https://example.com">活动跳转</a></body></html>""",
                    mimetype="text/html")
    resp.set_cookie("session", "FAKE-sess-userA", httponly=True)   # 默认发 A 的会话
    return resp


@app.get("/static/app.js")
def app_js():
    return Response(
        'const API={orders:"/api/order/detail?id=",addr:"/api/address/update",'
        'adminCfg:"/admin/config/update",search:"/search?q="};\n'
        'fetch("/internal/status").then(r=>r.json());\n', mimetype="application/javascript")


@app.get("/static/app.js.map")                                     # 干扰②：sourcemap
def app_map():
    return jsonify({"version": 3, "sources": ["../src/app.jsx", "../src/secret-key.jsx"],
                    "mappings": "AAAA"})


@app.get("/redirect")                                             # 干扰④：开放重定向
def redirect():
    from flask import redirect as _r
    return _r(request.args.get("url", "/"))


@app.get("/internal/status")                                      # 干扰⑤：内网 IP+instance-id
def internal():
    return jsonify({"svc": "redis://10.2.3.4:6379", "instance": "i-0abc123def456789a",
                    "region": "cn-north-1"})


@app.get("/api/user/profile")
def profile():
    u = _who()
    if not u:
        return jsonify({"code": 401, "msg": "login required"}), 401
    d = dict(USERS[u])
    d["nickname"] = d["nickname"]                                  # 原样返回（self-XSS 干扰③：仅自己可见）
    return jsonify({"code": 0, "data": d})


@app.get("/api/order/detail")                                     # 真洞①：idor 读（无属主校验）
def order_detail():
    try:
        oid = int(request.args.get("id", "0"))
    except ValueError:
        oid = 0
    o = ORDERS.get(oid)
    if not o:
        return jsonify({"code": 404}), 404
    return jsonify({"code": 0, "data": o})


@app.route("/api/address/update", methods=["POST"])               # 真洞②：idor 写（无属主校验）
def addr_update():
    d = request.get_json(force=True, silent=True) or {}
    aid = int(d.get("addrId", 0))
    if aid not in ADDRESSES:
        return jsonify({"code": 404}), 404
    ADDRESSES[aid]["addr"] = str(d.get("addr", ""))[:80]
    return jsonify({"code": 0})


@app.get("/api/address/<int:aid>")                                # 读回通道（idor 写的验证面）
def addr_get(aid):
    a = ADDRESSES.get(aid)
    return (jsonify({"code": 0, "data": a}) if a else (jsonify({"code": 404}), 404))


@app.route("/admin/config/update", methods=["POST"])              # 真洞③：authbypass（无角色校验）
def admin_cfg():
    d = request.get_json(force=True, silent=True) or {}
    BANNER.update(d)
    return jsonify({"code": 0, "affected": list(d.keys())})


@app.get("/admin/config")
def admin_cfg_get():
    return jsonify({"code": 0, "data": BANNER})


@app.get("/admin/userList")                                       # 关着的门：阴性记录素材
def admin_users():
    u = _who()
    if u != "userB":                                              # 无人有 admin 角色 → 对 A 恒 403
        return jsonify({"code": 403, "msg": "admin only"}), 403
    return jsonify({"code": 0, "data": ["userA", "userB"]})


@app.get("/search")                                               # 真洞④：sqli 报错 + UNION 数据
def search():
    q = request.args.get("q", "")
    try:
        rows = _db.execute(f"SELECT * FROM items WHERE name LIKE '%{q}%'").fetchall()
        return jsonify({"code": 0, "data": [{"id": r[0], "name": r[1]} for r in rows]})
    except sqlite3.OperationalError as e:
        return Response(
            f"<h1>Debug</h1><p>You have an error in your SQL syntax; "
            f"near '%{q}%' at line 1</p><pre>SELECT * FROM items WHERE name LIKE '%{q}%'</pre>",
            status=500, mimetype="text/html")


if __name__ == "__main__":
    print(f"canary 靶就绪 http://127.0.0.1:{PORT}  marker={MARKER_PHONE}")
    app.run(host="127.0.0.1", port=PORT, threaded=True)
