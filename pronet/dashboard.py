"""Read-only web status page served by the coordinator.

Built from the overview the coordinator already keeps; rendering it sends
nothing through any tunnel and touches no server. No JavaScript (CSP: none).
"""
from __future__ import annotations

import html
import time

from .views import pct, servers, tunnels

STATUS = {"UP": ("وصل", "good"), "DOWN": ("قطع", "bad"), "UNKNOWN": ("نامشخص", "warn"),
          "SETTING UP": ("در حال راه‌اندازی", "warn")}

STYLE = """
:root{color-scheme:dark;--bg:#0b111c;--card:#131c2b;--text:#e6ebf3;--muted:#8d99ad;--line:#222d40;--good:#17b26a;--warn:#f79009;--bad:#f04438}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.7 Tahoma,Vazirmatn,system-ui,sans-serif}
main{max-width:1100px;margin:auto;padding:24px 16px}
h1{font-size:22px;margin:0}h2{font-size:15px;color:var(--muted);margin:28px 0 12px}h3{margin:0;font-size:16px}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px;min-width:0;box-shadow:0 1px 3px rgba(0,0,0,.35)}
.card.s-good{border-inline-start:5px solid var(--good)}.card.s-bad{border-inline-start:5px solid var(--bad)}.card.s-warn{border-inline-start:5px solid var(--warn)}
.summary{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.chip{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 16px;min-width:130px}
.chip b{display:block;font-size:22px;line-height:1.2;font-variant-numeric:tabular-nums}.chip span{color:var(--muted);font-size:12px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-inline-end:6px;vertical-align:middle}
.kv b,.meter b{font-variant-numeric:tabular-nums}
.wide{grid-column:1/-1}
.card header{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:12px}
.pill{font-size:12px;padding:3px 10px;border-radius:999px;color:#fff;white-space:nowrap}
.big{font-size:14px;padding:6px 16px}
.good{background:var(--good)}.warn{background:var(--warn)}.bad{background:var(--bad)}.bad-text{color:var(--bad)}
.muted{color:var(--muted)}small{display:block}
.meter{display:grid;grid-template-columns:44px 1fr 48px;align-items:center;gap:8px;margin:6px 0}
.bar{height:8px;background:var(--line);border-radius:6px;overflow:hidden}.bar i{display:block;height:100%}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:2px 24px}
.kv{display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px solid var(--line)}
.kv span{color:var(--muted)}.kv b{font-weight:600;text-align:left;overflow-wrap:anywhere}
.problems{margin:12px 0 4px;padding:10px 28px;border-radius:10px;background:rgba(247,144,9,.12);border:1px solid rgba(247,144,9,.35)}
details{margin:10px 0}summary{cursor:pointer;color:var(--muted)}.events{padding:0 18px;margin:6px 0}
footer{margin-top:28px;color:var(--muted);font-size:12px}
"""


def e(value):
    return html.escape(str(value), quote=True)


def _meter(label, value):
    width = max(0, min(100, value)) if isinstance(value, (int, float)) else 0
    tone = "bad" if width >= 90 else "warn" if width >= 75 else "good"
    return ('<div class="meter"><span>%s</span><div class="bar"><i class="%s" style="width:%d%%"></i></div>'
            '<b dir="ltr">%s</b></div>' % (label, tone, round(width), e(pct(value).strip())))


def _kv(name, value, ok=True):
    return '<div class="kv"><span>%s</span><b dir="ltr"%s>%s</b></div>' % (name, "" if ok else ' class="bad-text"', e(value))


def _server_card(row):
    state = '<span class="pill good">آنلاین</span>' if row["online"] else '<span class="pill bad">آفلاین</span>'
    role = "ایران" if row["role"] == "iran" else "خارج"
    return ('<article class="card s-%s"><header><div><h3>%s</h3><small>%s · <span dir="ltr">%s</span></small></div>%s</header>'
            '%s%s%s<small class="muted">آخرین گزارش: <span dir="ltr">%s</span></small></article>'
            % ("good" if row["online"] else "bad", e(row["name"]), role, e(row["ip"]), state, _meter("CPU", row["cpu"]), _meter("RAM", row["ram"]),
               _meter("Disk", row["disk"]), e(row["seen"])))


def _tunnel_card(row):
    label, tone = STATUS.get(row["status"], (row["status"], "warn"))
    body = []
    if row["state"] != "ACTIVE":
        progress = row.get("progress") or {}
        body.append(_kv("مرحله", row["state"]))
        if progress.get("total"):
            body.append(_kv("تست‌شده", "%s / %s (passed %s)" % (progress.get("tested", 0), progress["total"], progress.get("passed", 0))))
    else:
        rtt = (" · %d ms" % row["rtt"]) if isinstance(row["rtt"], (int, float)) else ""
        body.append(_kv("آدرس کاربران", row["endpoint"]))
        body.append(_kv("روش فعال", "%s%s" % (row["active"], rtt)))
        for item in row["standby"] or [{"name": "-", "text": "none", "ok": False}]:
            body.append(_kv("پشتیبان", "%s · %s" % (item["name"], item["text"]), item["ok"]))
        body.append(_kv("اینباند پنل (خارج)", "%s · port %s" % (row["inbound"], row["port"]), row["inbound_ok"]))
        traffic = row["traffic"]
        body.append(_kv("ترافیک کل", "↓ %s   ↑ %s" % (traffic["down_total"], traffic["up_total"])))
        body.append(_kv("سرعت لحظه‌ای", "↓ %s   ↑ %s Mbps" % (traffic["down_now"], traffic["up_now"])))
        body.append(_kv("اتصال‌های فعال", traffic["connections"] if traffic["connections"] is not None else "-"))
        body.append(_kv("آخرین جابه‌جایی به پشتیبان", row["last_switch"]))
    problems = "".join("<li>%s</li>" % e(text) for text in row["problems"])
    events = "".join('<li dir="ltr"><code>%s</code> %s <span class="muted">%s</span></li>'
                     % (e(item.get("utc", "")[5:16].replace("T", " ")), e(item.get("event", "")), e(item.get("detail", "")))
                     for item in row["events"][-5:])
    return ('<article class="card wide s-%s"><header><div><h3>%s</h3><small dir="ltr">%s → %s</small></div>'
            '<span class="pill big %s">%s</span></header><div class="grid2">%s</div>%s%s'
            '<small class="muted" dir="ltr">%s · ID %s</small></article>'
            % (tone, e(row["name"]), e(row["iran"]), e(row["foreign"]), tone, label, "".join(body),
               '<ul class="problems" dir="ltr">%s</ul>' % problems if problems else "",
               '<details><summary>رویدادهای اخیر</summary><ul class="events">%s</ul></details>' % events if events else "",
               e(row["failover"]), e(row["id"])))


def _summary(tunnel_rows, server_rows):
    up = sum(1 for row in tunnel_rows if row["status"] == "UP")
    down = sum(1 for row in tunnel_rows if row["status"] in ("DOWN", "UNKNOWN"))
    online = sum(1 for row in server_rows if row["online"])
    issues = sum(len(row["problems"]) for row in tunnel_rows)
    chips = [("تونل وصل", up, "good"), ("تونل قطع/نامشخص", down, "bad" if down else "good"),
             ("سرور آنلاین", "%d/%d" % (online, len(server_rows)), "good" if online == len(server_rows) else "bad"),
             ("هشدار", issues, "warn" if issues else "good")]
    return '<div class="summary">%s</div>' % "".join(
        '<div class="chip"><span><i class="dot %s"></i>%s</span><b dir="ltr">%s</b></div>' % (tone, label, e(value))
        for label, value, tone in chips)


def render(data):
    tunnel_rows, server_rows = tunnels(data), servers(data)
    tunnel_html = "".join(_tunnel_card(row) for row in tunnel_rows) or \
        '<p class="muted">هنوز تونلی ساخته نشده است. روی سرور ایران: <code dir="ltr">sudo pronet</code></p>'
    server_html = "".join(_server_card(row) for row in server_rows) or '<p class="muted">سروری ثبت نشده است.</p>'
    stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(data.get("server_time") or time.time()))
    return ('<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="15">'
            '<title>Pronet Fleet</title><style>%s</style></head><body><main>'
            '<div class="top"><h1>Pronet Fleet</h1><small class="muted" dir="ltr">%s · auto-refresh 15 s</small></div>%s'
            '<h2>تونل‌ها</h2><div class="cards">%s</div><h2>سرورها</h2><div class="cards">%s</div>'
            '<footer>این صفحه فقط خواندنی است و از اطلاعاتی ساخته می‌شود که مرکز از قبل دارد؛ هیچ باری روی تونل نمی‌گذارد. '
            '«آفلاین» یعنی سرور در ۴۵ ثانیهٔ اخیر گزارشی نفرستاده (خاموش، ریبوت یا اتمام ترافیک). '
            'وضعیت تونل با هر تست سلامت (پیش‌فرض هر ۶۰ ثانیه) به‌روز می‌شود.</footer></main></body></html>'
            % (STYLE, e(stamp), _summary(tunnel_rows, server_rows), tunnel_html, server_html))
