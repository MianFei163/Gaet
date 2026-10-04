#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线
============================
1. 拉 VPN Gate 原始节点 (官方 CSV, 失败回退 GitHub 镜像)
2. 只留带 TCP 入口的中继 = SSTP 可用节点 (OpenVPN 配置 proto tcp + remote 端口)
3. 按 host+port+protocol 去重
4. 并发调用 Cloudflare Worker 检测, 以返回 JSON 的 success 字段为准
5. 保留 success=true 的节点, 按国家分组, 生成 public/ 下 6 个文件
6. 网页端 (GitHub Pages) 读 data.json 展示

时间显示: 统一为北京时间 (UTC+8)
退出码: 0=正常完成; 1=硬性失败 (数据源全挂/解析不出节点/Worker 全挂/程序异常)
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import requests

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BJ_TZ = timezone(timedelta(hours=8))


def bj_now_str(fmt="%Y-%m-%d %H:%M:%S"):
    """返回当前北京时间字符串 (带 ' 北京' 后缀)。"""
    return datetime.now(BJ_TZ).strftime(fmt) + " 北京"


REPO_DIR = os.path.dirname(os.path.abspath(__file__))
VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://fco.us.ci/check?sstp=vpn:vpn@")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

CHAIN_URL = os.environ.get("CHAIN_URL", "https://MianFeiWeiRuan.github.io/Gate/chains.txt")
HOSTS_URL = os.environ.get("HOSTS_URL", "https://MianFeiWeiRuan.github.io/Gate/hosts.txt")
NODES_URL = os.environ.get("NODES_URL", "https://MianFeiWeiRuan.github.io/Gate/nodes.txt")
SUB_URL = os.environ.get("SUB_URL", "https://MianFeiWeiRuan.github.io/Gate/sub.txt")
EDT_UUID = os.environ.get("EDT_UUID", "dd1289f7-4fee-4504-8ed6-674456c48130")
EDT_DOMAIN = os.environ.get("EDT_DOMAIN", "fci.us.ci")
EDT_FINGERPRINT = os.environ.get("EDT_FINGERPRINT", "chrome")
EDGE_HOSTS = [
    h.strip() for h in os.environ.get(
        "EDGE_HOSTS",
        "ct.cloudflare.byoip.top:443,cu.cloudflare.byoip.top:443,cm.cloudflare.byoip.top:443,"
        "yg1.ygkkk.dpdns.org:443,cf.090227.xyz:443,cloudflare.182682.xyz:443,skk.moe:443,saas.sin.fan:443",
    ).split(",") if h.strip()
]

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

_section = None


def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)


def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)


def country_name(grp, fallback):
    code = str(grp.get("code") or "?").upper()
    return COUNTRY_ZH.get(code) or (code if code and code != "?" else fallback)


def iter_sorted_nodes(countries):
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])),
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = country_name(grp, cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (
                0 if n.get("residential") == "residential" else 1,
                n.get("latency_ms") is None,
                n.get("latency_ms") or 0,
                n.get("host") or "",
            ),
        )
        res = [n for n in nodes if n.get("residential") == "residential"]
        dc = [n for n in nodes if n.get("residential") != "residential"]
        yield zh, code, grp, nodes, res, dc


def fetch_vpngate():
    try:
        log("VPN GATE", f"获取官方 API: {VPNGATE_API}")
        r = requests.get(VPNGATE_API, timeout=HTTP_TIMEOUT,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; gate-checker)"})
        r.raise_for_status()
        rows = parse_csv(r.text)
        if rows:
            log("VPN GATE", f"主源(官方 API) 获取到 {len(rows)} 个原始节点")
            return rows, "vpngate.net/api/iphone"
        raise RuntimeError("官方 API 返回 0 行数据")
    except Exception as exc:
        log("VPN GATE", f"官方 API 获取失败: {exc}")

    try:
        log("VPN GATE", f"回退镜像: {VPNGATE_MIRROR}")
        r = requests.get(VPNGATE_MIRROR, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        rows = parse_mirror_json(r.json())
        if rows:
            log("VPN GATE", f"回退源(镜像) 获取到 {len(rows)} 个原始节点")
            return rows, "github-mirror"
    except Exception as exc:
        log("VPN GATE", f"回退镜像也失败: {exc}")
    die("VPN Gate 官方 API 与回退镜像均不可用, 数据源完全失败 (不生成空结果, 本次运行判定失败)")


def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = next((i for i, ln in enumerate(lines) if ln.lstrip("#").startswith("HostName")), None)
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")
    header = lines[header_idx].lstrip("#").split(",")
    pos = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        pos[col] = next((i for i, h in enumerate(header) if h.strip().lstrip("*").lower() == col), None)
    if pos["openvpn_configdata_base64"] is None:
        pos["openvpn_configdata_base64"] = next(
            (i for i, h in enumerate(header) if "base64" in h.lower()), len(header) - 1)
    for col, dflt in (("hostname", 0), ("ip", 1), ("countrylong", 5), ("countryshort", 6)):
        if pos[col] is None:
            pos[col] = dflt

    rows = []
    for ln in lines[header_idx + 1:]:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7:
            continue
        host, ip = fields[pos["hostname"]].strip(), fields[pos["ip"]].strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host, "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows


def parse_mirror_json(data):
    servers = []
    for item in (data if isinstance(data, list) else [data]):
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if host and ip:
            rows.append({
                "host": host, "ip": ip,
                "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
                "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
                "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
            })
    return rows


_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M | re.I)
_REMOTE_LINE_RE = re.compile(r"^remote\s+(\S+)\s+(\d+)", re.M | re.I)


def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        pm = _PROTO_TCP_RE.search(cfg)
        if not pm:
            continue
        remotes = list(_REMOTE_LINE_RE.finditer(cfg))
        if not remotes:
            continue
        after = [m for m in remotes if m.start() >= pm.start()]
        chosen = after[0] if after else remotes[-1]
        port = int(chosen.group(2))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({"host": host, "port": port, "ip": r["ip"],
                      "country": r["country_long"], "country_code": r["country_short"]})
    return nodes


def dedupe(nodes):
    seen, out = set(), []
    for n in nodes:
        k = (n["host"].lower(), n["port"], "sstp")
        if k not in seen:
            seen.add(k)
            out.append(n)
    return out


def classify_network(host, exit_org, is_datacenter=None):
    dc = None
    if is_datacenter is True or (isinstance(is_datacenter, str) and is_datacenter.strip().lower() in ("true", "1", "yes")):
        dc = True
    elif is_datacenter is False or (isinstance(is_datacenter, str) and is_datacenter.strip().lower() in ("false", "0", "no")):
        dc = False
    if dc is True:
        return "datacenter"
    if dc is False:
        return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"
    return "unknown"


def check_one(node, session):
    out = dict(node)
    out.update({
        "protocol": "sstp",
        "link": f"sstp://vpn:vpn@{node['host']}:{node['port']}",
        "status": "failed", "success": False, "exit": None, "residential": "unknown",
        "checked_at": bj_now_str("%Y-%m-%d %H:%M"),
    })
    try:
        r = session.get(WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe=""),
                        timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = None if ok else (j.get("error") or j.get("message") or "check failed")
        ei = j.get("exit") or {}
        if ei:
            asn = ei.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": ei.get("ip"), "country": ei.get("country"),
                "country_code": ei.get("country_code"), "city": ei.get("city"),
                "continent": ei.get("continent"), "asn": asn.get("asn"),
                "org": org, "type": asn.get("type"),
                "is_datacenter": ei.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, ei.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out


def check_all(nodes, session):
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        for fut in as_completed([pool.submit(check_one, n, session) for n in nodes]):
            results.append(fut.result())
    return results


def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)
    for grp in countries.values():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
    stats = {
        "raw_nodes": raw_count, "sstp_nodes": sstp_count, "checked": len(results),
        "success": len(available), "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }
    return {
        "generated_at": bj_now_str(),
        "source": source, "worker": WORKER_CHECK_URL,
        "stats": stats, "countries": countries, "available": available,
    }


def build_chains_text(data):
    lines = [
        "# VPN Gate SSTP 节点 -> edgetunnel 链式代理清单",
        f"# 自动更新: {data['generated_at']} (每 2 小时重新检测)",
        f"# 固定地址: {CHAIN_URL}",
        "#",
        "# 用法: 在 edgetunnel 节点备注里直接粘贴下面任意一行 (名字与指令连写)",
        "#   例: 日本-住宅-01$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        "# 名字保持不变, 只有 $sstp:// 后面的地址每 2 小时自动更换",
        "# 账号密码固定 vpn:vpn ; 端口必须保留",
        "# ========================================================",
    ]
    for zh, code, grp, _nodes, res, dc in iter_sorted_nodes(data["countries"]):
        lines.append("")
        lines.append(f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----")
        for i, n in enumerate(res, 1):
            lines.append(f"{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc, 1):
            lines.append(f"{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"


def build_hosts_text(data):
    entry = os.environ.get("HOSTS_ENTRY", "").strip()
    edge = [e.strip() for e in entry.split(",") if e.strip()] or EDGE_HOSTS or [f"{EDT_DOMAIN}:443"]
    lines = [
        "# edgetunnel「自定义优选IP」清单 (整段复制, 追加到后台现有内容后面)",
        f"# 自动更新: {data['generated_at']} (每 2 小时重新检测)",
        f"# 固定地址: {HOSTS_URL}",
        "# 每行 = 入口地址#名字$sstp://vpn:vpn@节点:端口",
        "# 入口用 7 个实测可用优选域名循环分配",
        "# 名字 = 国家-住宅/机房-编号, 直接区分住宅与机房",
        "# 名字固定; 只有 $sstp:// 后面的节点地址每 2 小时自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口必须保留",
        "# ========================================================",
    ]
    idx = 0
    for zh, code, grp, _nodes, res, dc in iter_sorted_nodes(data["countries"]):
        lines.append("")
        lines.append(f"# ---- {zh} {code} · {grp['count']} 节点 (住宅 {grp['residential']} / 机房 {grp['datacenter']}) ----")
        for i, n in enumerate(res, 1):
            lines.append(f"{edge[idx % len(edge)]}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
            idx += 1
        for i, n in enumerate(dc, 1):
            lines.append(f"{edge[idx % len(edge)]}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
            idx += 1
    return "\n".join(lines) + "\n"


def _b64_secret_encode(plaintext, secret):
    d, k = plaintext.encode(), secret.encode()
    return base64.b64encode(bytes(d[i] ^ k[i % len(k)] for i in range(len(d)))).decode("ascii")


def _socks5_account(address, default_port=80):
    address = re.sub(r"^(socks5|http|https|turn|sstp)://", "", address.strip(), flags=re.I).split("#")[0].strip()
    at = address.rfind("@")
    auth, hostpart = (address[:at], address[at + 1:]) if at != -1 else ("", address)
    hostpart = hostpart.split("/")[0]
    username = password = None
    if auth:
        if ":" not in auth:
            try:
                auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode()
            except Exception:
                pass
        parts = auth.split(":", 1)
        username = parts[0]
        password = parts[1] if len(parts) > 1 else None
    hostname, port = hostpart, default_port
    if hostpart.count(":") == 1 and not hostpart.startswith("["):
        h, p = hostpart.rsplit(":", 1)
        if p.isdigit():
            hostname, port = h, int(p)
    return {"username": username, "password": password, "hostname": hostname, "port": port}


def build_sub_text(data):
    lines = [
        "# edgetunnel 完整订阅 (vless://) —— 填进后台「订阅链接」URL",
        f"# 自动更新: {data['generated_at']} (每 2 小时重新检测)",
        f"# 固定地址: {SUB_URL}",
        f"# 节点域名: {EDT_DOMAIN} (传输 ws / TLS / fingerprint {EDT_FINGERPRINT})",
        "# 名字固定; $sstp:// 链式代理(编码在 path)每 2 小时自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口已编码进 path",
        "# ========================================================",
    ]
    for zh, code, grp, nodes, _res, _dc in iter_sorted_nodes(data["countries"]):
        for i, n in enumerate(nodes, 1):
            name = f"{zh}-{i:02d}"
            chain = {"type": "sstp", **_socks5_account(f"vpn:vpn@{n['host']}:{n['port']}", 443)}
            enc = _b64_secret_encode(json.dumps(chain, separators=(",", ":")), EDT_UUID)
            path = quote("/video/" + enc, safe="+/=:")
            lines.append(
                f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
                f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
                f"&path={path}&encryption=none&alpn=#{quote(name, safe='')}"
            )
    return "\n".join(lines) + "\n"


def write_outputs(data):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    paths = {}
    paths["data.json"] = os.path.join(PUBLIC_DIR, "data.json")
    with open(paths["data.json"], "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    paths["index.html"] = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, encoding="utf-8") as f:
            html = f.read()
    else:
        html = ("<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
                "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
                "<script>fetch('data.json').then(r=>r.json()).then(d=>"
                "document.getElementById('out').textContent=JSON.stringify(d.stats)"
                ").catch(e=>document.getElementById('out').textContent='加载失败:'+e)</script></html>")
    with open(paths["index.html"], "w", encoding="utf-8") as f:
        f.write(html)

    hosts_text = build_hosts_text(data)
    for name, content in (
        ("chains.txt", build_chains_text(data)),
        ("hosts.txt", hosts_text),
        ("sub.txt", build_sub_text(data)),
    ):
        paths[name] = os.path.join(PUBLIC_DIR, name)
        with open(paths[name], "w", encoding="utf-8") as f:
            f.write(content)

    paths["nodes.txt"] = os.path.join(PUBLIC_DIR, "nodes.txt")
    nodes_lines = [ln for ln in hosts_text.split("\n") if ln and not ln.startswith("#")]
    with open(paths["nodes.txt"], "w", encoding="utf-8") as f:
        f.write("\n".join(nodes_lines) + ("\n" if nodes_lines else ""))
    return paths


def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化")
    uniq = dedupe(sstp_nodes)
    if MAX_CHECK_NODES > 0 and len(uniq) > MAX_CHECK_NODES:
        log("VPN GATE", f"MAX_CHECK_NODES={MAX_CHECK_NODES}, 截断 {len(uniq)} -> {MAX_CHECK_NODES}")
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0
    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    if uniq and not success:
        if len(worker_errors) == len(uniq):
            die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")
        die(f"提交 {len(uniq)} 个节点, 无一通过 Worker 检测 (success 全为 false) — 判定失败")

    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len(success)}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    paths = write_outputs(data)
    for name, p in paths.items():
        log("WEBSITE", f"生成 {os.path.relpath(p, REPO_DIR)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (每 2 小时更新)")
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
