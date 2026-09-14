"""
NetGuard - Secure Network Monitor
Flask backend with:
  - Real ARP scanning via Scapy
  - Real ARP spoofing to block devices
  - bcrypt password hashing
  - Fernet-encrypted JSON storage (no pickle)
  - Input validation on every endpoint
  - RBAC (admin/viewer)
  - Rate limiting on auth endpoints
  - [NEW] Packet monitoring & capture via Scapy sniffing
  - [NEW] Per-IP traffic profiling & threat scoring (SOC)
  - [NEW] Scheduled HTML reports with recommendations
Run as root: sudo python app.py
"""
import os
import re
import sys
import json
import time
import uuid
import threading
import ipaddress
import secrets
import logging
from collections import defaultdict, deque
from datetime import datetime
from functools import wraps

import bcrypt
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify, session, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (ARP, Ether, IP, TCP, UDP, DNSQR,
                       srp, sendp, sniff, conf,
                       get_if_addr, get_if_hwaddr, get_if_list)
conf.verb = 0

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
BASE_DIR           = os.path.dirname(os.path.abspath(__file__))
STORAGE_FILE       = os.path.join(BASE_DIR, "data.enc")
KEY_FILE           = os.path.join(BASE_DIR, "storage.key")
REPORTS_DIR        = os.path.join(BASE_DIR, "reports")
SESSION_TIMEOUT    = 1800
PACKET_BUFFER_SIZE = 500

os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = secrets.token_bytes(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

limiter = Limiter(get_remote_address, app=app, default_limits=[])

# ─────────────────────────────────────────────
# Encrypted Storage
# ─────────────────────────────────────────────
def _get_fernet() -> Fernet:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(KEY_FILE, 0o600)
    return Fernet(key)

def load_data() -> dict:
    fernet = _get_fernet()
    if not os.path.exists(STORAGE_FILE):
        return _default_data()
    try:
        with open(STORAGE_FILE, "rb") as f:
            raw = fernet.decrypt(f.read())
        return json.loads(raw.decode())
    except Exception:
        return _default_data()

def save_data(data: dict):
    fernet = _get_fernet()
    encrypted = fernet.encrypt(json.dumps(data, default=str).encode())
    with open(STORAGE_FILE, "wb") as f:
        f.write(encrypted)
    os.chmod(STORAGE_FILE, 0o600)

def _default_data() -> dict:
    admin_pw = "Admin@1234"
    hashed   = bcrypt.hashpw(admin_pw.encode(), bcrypt.gensalt(rounds=12)).decode()
    return {
        "users":           {"admin": {"hash": hashed, "role": "admin"}},
        "blocked_macs":    [],
        "audit_log":       [],
        "report_schedule": {"interval_minutes": 60, "enabled": True},
    }

# ─────────────────────────────────────────────
# Input Validation
# ─────────────────────────────────────────────
IP_RE   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
MAC_RE  = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/([0-9]|[12][0-9]|3[0-2])$")
USER_RE = re.compile(r"^[a-zA-Z0-9_]{1,32}$")

def valid_ip(v):
    if not IP_RE.match(v): return False
    return all(0 <= int(o) <= 255 for o in v.split("."))

def valid_mac(v):      return bool(MAC_RE.match(v))
def valid_username(v): return bool(USER_RE.match(v))

def valid_cidr(v):
    if not CIDR_RE.match(v): return False
    try:
        ipaddress.ip_network(v, strict=False); return True
    except ValueError:
        return False

# ─────────────────────────────────────────────
# Audit Logging
# ─────────────────────────────────────────────
def audit(action: str, detail: str, user: str = "system", level: str = "info"):
    data = load_data()
    entry = {
        "id":     str(uuid.uuid4())[:8],
        "ts":     datetime.utcnow().isoformat(),
        "level":  level,
        "user":   user,
        "action": action,
        "detail": detail,
        "ip":     request.remote_addr if request else "internal",
    }
    data["audit_log"].insert(0, entry)
    data["audit_log"] = data["audit_log"][:200]
    save_data(data)
    return entry

# ─────────────────────────────────────────────
# RBAC
# ─────────────────────────────────────────────
PERMISSIONS = {
    "admin":  {"scan","block","unblock","view_devices","view_logs",
               "manage_users","view_packets","view_reports"},
    "viewer": {"view_devices","view_logs","view_packets","view_reports"},
}

def login_required(perm: str = None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            uid = session.get("user_id")
            if not uid:
                return jsonify({"error": "Unauthorized"}), 401
            if time.time() - session.get("last_active", 0) > SESSION_TIMEOUT:
                session.clear()
                return jsonify({"error": "Session expired"}), 401
            session["last_active"] = time.time()
            if perm:
                role = session.get("role", "")
                if perm not in PERMISSIONS.get(role, set()):
                    audit("ACCESS_DENIED", f"Role '{role}' attempted '{perm}'",
                          session.get("username", "?"), "warn")
                    return jsonify({"error": f"Forbidden: requires '{perm}'"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ─────────────────────────────────────────────
# Network Interface Detection
# ─────────────────────────────────────────────
def detect_interface():
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                return iface, ip
        except Exception:
            continue
    return None, None

# ─────────────────────────────────────────────
# ARP Scanner
# ─────────────────────────────────────────────
def arp_scan(subnet: str, iface: str) -> list:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(pkt, timeout=3, iface=iface, verbose=0)
    seen = {}
    for _, rcv in answered:
        seen[rcv.hwsrc.lower()] = rcv.psrc
    return [{"ip": ip, "mac": mac} for mac, ip in seen.items()]

# ─────────────────────────────────────────────
# ARP Spoof Engine
# ─────────────────────────────────────────────
_spoof_threads: dict = {}

def _spoof_loop(target_ip, target_mac, gateway_ip, iface, stop_event):
    try:    our_mac = get_if_hwaddr(iface)
    except: our_mac = "00:00:00:00:00:00"
    pkt = (Ether(dst=target_mac) /
           ARP(op=2, pdst=target_ip, hwdst=target_mac,
               psrc=gateway_ip, hwsrc=our_mac))
    while not stop_event.wait(1.5):
        try:    sendp(pkt, iface=iface, verbose=0)
        except: pass

def start_block(target_ip, target_mac, gateway_ip, iface):
    mac = target_mac.lower()
    if mac in _spoof_threads: return
    ev = threading.Event()
    t  = threading.Thread(target=_spoof_loop,
                          args=(target_ip, mac, gateway_ip, iface, ev), daemon=True)
    _spoof_threads[mac] = ev
    t.start()

def stop_block(target_mac):
    ev = _spoof_threads.pop(target_mac.lower(), None)
    if ev: ev.set()

# ═══════════════════════════════════════════════════════════════
# [NEW] ① PACKET MONITORING ENGINE
# ═══════════════════════════════════════════════════════════════
SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 5555, 6666, 7777, 8080, 8443, 1080, 9050, 9150}
MALWARE_DOMAINS  = {"tor-exit", "pastebin.com", "raw.githubusercontent.com",
                    "ngrok.io", "duckdns.org", "no-ip.com"}

_packet_buffer: deque  = deque(maxlen=PACKET_BUFFER_SIZE)
_packet_lock           = threading.Lock()
_sniffer_thread        = None
_sniffer_stop          = threading.Event()

def _classify_packet(src_ip, dst_ip, sport, dport, proto, domain=""):
    score, reason = 0, []
    for p in (sport, dport):
        if p in SUSPICIOUS_PORTS:
            score += 35; reason.append(f"suspicious port {p}"); break
    for bad in MALWARE_DOMAINS:
        if bad in domain:
            score += 40; reason.append(f"suspicious domain ({domain})"); break
    try:
        if ipaddress.ip_address(src_ip).is_private and \
           not ipaddress.ip_address(dst_ip).is_private and \
           dport in SUSPICIOUS_PORTS:
            score += 15; reason.append("private→public on risky port")
    except Exception:
        pass
    score = min(score, 100)
    label = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return score, label, "; ".join(reason) if reason else "normal traffic"

def _packet_handler(pkt):
    try:
        if not pkt.haslayer(IP): return
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto, sport, dport, domain = "OTHER", 0, 0, ""
        size = len(pkt)
        if pkt.haslayer(TCP):
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            proto = "HTTPS" if 443 in (sport, dport) else "HTTP" if 80 in (sport, dport) else "TCP"
        elif pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            if 53 in (sport, dport):
                proto = "DNS"
                if pkt.haslayer(DNSQR):
                    domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            else:
                proto = "UDP"
        risk, label, reason = _classify_packet(src_ip, dst_ip, sport, dport, proto, domain)
        entry = {
            "id": str(uuid.uuid4())[:8], "ts": datetime.utcnow().isoformat(),
            "src": src_ip, "dst": dst_ip, "sport": sport, "dport": dport,
            "proto": proto, "size": size, "domain": domain,
            "risk": risk, "label": label, "reason": reason,
        }
        with _packet_lock:
            _packet_buffer.appendleft(entry)
        _update_profile(src_ip, dst_ip, proto, domain, risk, size)
    except Exception:
        pass

def _sniffer_loop(iface, stop_evt):
    sniff(iface=iface, prn=_packet_handler, store=False,
          stop_filter=lambda _: stop_evt.is_set(), filter="ip")

def start_sniffer():
    global _sniffer_thread, _sniffer_stop
    if _sniffer_thread and _sniffer_thread.is_alive(): return
    iface, _ = detect_interface()
    if not iface: return
    _sniffer_stop.clear()
    _sniffer_thread = threading.Thread(target=_sniffer_loop,
                                       args=(iface, _sniffer_stop), daemon=True)
    _sniffer_thread.start()
    print(f"[+] Packet sniffer started on {iface}")

# ═══════════════════════════════════════════════════════════════
# [NEW] ② PER-IP TRAFFIC PROFILER (SOC)
# ═══════════════════════════════════════════════════════════════
_profiles: dict  = defaultdict(lambda: {
    "ip": "", "first_seen": None, "last_seen": None,
    "pkt_count": 0, "bytes_total": 0,
    "protocols": defaultdict(int), "domains": [], "dst_ips": [],
    "risk_scores": deque(maxlen=100), "max_risk": 0, "blocked": False,
})
_profile_lock = threading.Lock()

def _update_profile(src_ip, dst_ip, proto, domain, risk, size):
    with _profile_lock:
        p   = _profiles[src_ip]
        now = datetime.utcnow().isoformat()
        p["ip"] = src_ip
        p["last_seen"] = now
        if not p["first_seen"]: p["first_seen"] = now
        p["pkt_count"]   += 1
        p["bytes_total"] += size
        p["protocols"][proto] = p["protocols"].get(proto, 0) + 1
        p["risk_scores"].append(risk)
        p["max_risk"] = max(p["max_risk"], risk)
        if domain and domain not in p["domains"]:
            p["domains"].append(domain)
            if len(p["domains"]) > 50: p["domains"].pop(0)
        try:
            if not ipaddress.ip_address(dst_ip).is_private and dst_ip not in p["dst_ips"]:
                p["dst_ips"].append(dst_ip)
                if len(p["dst_ips"]) > 20: p["dst_ips"].pop(0)
        except Exception:
            pass

def _profile_snapshot():
    with _profile_lock:
        out = []
        for ip, p in _profiles.items():
            scores   = list(p["risk_scores"])
            avg_risk = round(sum(scores) / len(scores)) if scores else 0
            out.append({
                "ip": ip, "first_seen": p["first_seen"], "last_seen": p["last_seen"],
                "pkt_count": p["pkt_count"], "bytes_total": p["bytes_total"],
                "protocols": dict(p["protocols"]), "domains": p["domains"][-10:],
                "dst_ips": p["dst_ips"][-5:], "avg_risk": avg_risk,
                "max_risk": p["max_risk"], "blocked": p["blocked"],
                "threat_level": "high" if avg_risk >= 70 else "medium" if avg_risk >= 40 else "low",
            })
        out.sort(key=lambda x: x["avg_risk"], reverse=True)
        return out

# ═══════════════════════════════════════════════════════════════
# [NEW] ③ REPORT SCHEDULER
# ═══════════════════════════════════════════════════════════════
_report_timer = None
_report_lock  = threading.Lock()

def _threat_recommendations(profiles):
    recs      = []
    high_risk = [p for p in profiles if p["avg_risk"] >= 70]
    med_risk  = [p for p in profiles if 40 <= p["avg_risk"] < 70]
    if not profiles:
        return ["No traffic captured yet — ensure sniffer is running."]
    if high_risk:
        ips = ", ".join(p["ip"] for p in high_risk[:5])
        recs.append(f"🔴 IMMEDIATE ACTION: Block or investigate high-risk hosts: {ips}. "
                    "These IPs show suspicious traffic patterns.")
    if med_risk:
        ips = ", ".join(p["ip"] for p in med_risk[:5])
        recs.append(f"🟡 MONITOR: Medium-risk hosts: {ips}. "
                    "Review destination IPs and visited domains.")
    sus_dom = [p for p in profiles
               if any(bad in d for d in p["domains"] for bad in MALWARE_DOMAINS)]
    if sus_dom:
        ips = ", ".join(p["ip"] for p in sus_dom)
        recs.append(f"⚠️  Hosts contacting suspicious domains: {ips}. "
                    "Consider DNS-level blocking.")
    heavy = [p for p in profiles if p["bytes_total"] > 50 * 1024 * 1024]
    if heavy:
        ips = ", ".join(p["ip"] for p in heavy[:3])
        recs.append(f"📶 High-volume hosts: {ips}. Verify — possible data exfiltration.")
    if not recs:
        recs.append("✅ All traffic appears normal. No immediate action required.")
    recs.append("📋 Routine: Review audit logs weekly and keep NetGuard updated.")
    return recs

def _build_html_report(profiles, packets_sample, generated_at):
    high = sum(1 for p in profiles if p["threat_level"] == "high")
    med  = sum(1 for p in profiles if p["threat_level"] == "medium")
    low  = sum(1 for p in profiles if p["threat_level"] == "low")
    recs = _threat_recommendations(profiles)

    rows_p = ""
    for p in profiles:
        c = {"high":"#c0392b","medium":"#d68910","low":"#1e8449"}[p["threat_level"]]
        rows_p += (f"<tr><td><code>{p['ip']}</code></td><td>{p['pkt_count']:,}</td>"
                   f"<td>{round(p['bytes_total']/1024,1)} KB</td>"
                   f"<td>{', '.join(list(p['protocols'].keys())[:4])}</td>"
                   f"<td>{', '.join(p['domains'][:3]) or '—'}</td>"
                   f"<td style='color:{c};font-weight:600'>{p['avg_risk']}% ({p['threat_level']})</td>"
                   f"<td>{'🚫 Blocked' if p['blocked'] else '✅ Active'}</td></tr>")

    rows_pk = ""
    for pk in list(packets_sample)[:50]:
        c = {"high":"#c0392b","medium":"#d68910","low":"#27ae60"}[pk["label"]]
        rows_pk += (f"<tr><td>{pk['ts'][11:19]}</td><td><code>{pk['src']}</code></td>"
                    f"<td><code>{pk['dst']}</code></td><td>{pk['proto']}</td>"
                    f"<td>{pk['size']} B</td>"
                    f"<td style='color:{c}'>{pk['risk']}% — {pk['reason']}</td></tr>")

    recs_html = "".join(f"<li>{r}</li>" for r in recs)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>NetGuard Report — {generated_at}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:0;padding:24px;background:#f4f6f8;color:#222}}
h1{{color:#1a252f;margin-bottom:4px}}
.sub{{color:#666;margin-bottom:24px;font-size:14px}}
.cards{{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}}
.card{{background:#fff;border-radius:8px;padding:16px 24px;min-width:120px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.card h2{{margin:0 0 4px;font-size:28px}}.card p{{margin:0;color:#666;font-size:13px}}
.red{{color:#c0392b}}.amber{{color:#d68910}}.green{{color:#1e8449}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
       overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:24px}}
th{{background:#1a252f;color:#fff;padding:10px 12px;text-align:left;font-size:13px}}
td{{padding:9px 12px;font-size:13px;border-bottom:1px solid #eee}}
tr:last-child td{{border-bottom:none}}tr:hover td{{background:#f9fafb}}
h3{{margin:24px 0 8px;color:#1a252f}}
.recs{{background:#fff;border-radius:8px;padding:16px 24px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.recs li{{margin-bottom:8px;line-height:1.6;font-size:14px}}
.footer{{text-align:center;color:#aaa;font-size:12px;margin-top:32px}}
</style></head><body>
<h1>🛡 NetGuard — Network Security Report</h1>
<div class="sub">Generated: {generated_at} UTC | NetGuard Automated Reporter</div>
<div class="cards">
  <div class="card"><h2>{len(profiles)}</h2><p>Active Hosts</p></div>
  <div class="card"><h2 class="red">{high}</h2><p>High Risk</p></div>
  <div class="card"><h2 class="amber">{med}</h2><p>Medium Risk</p></div>
  <div class="card"><h2 class="green">{low}</h2><p>Low Risk</p></div>
</div>
<h3>Per-IP Traffic Profile</h3>
<table><thead><tr><th>IP</th><th>Packets</th><th>Volume</th>
<th>Protocols</th><th>Top Domains</th><th>Threat Risk</th><th>Status</th>
</tr></thead><tbody>{rows_p}</tbody></table>
<h3>Recent Packets (last 50)</h3>
<table><thead><tr><th>Time</th><th>Source</th><th>Destination</th>
<th>Protocol</th><th>Size</th><th>Assessment</th>
</tr></thead><tbody>{rows_pk}</tbody></table>
<h3>Recommendations</h3>
<div class="recs"><ul>{recs_html}</ul></div>
<div class="footer">NetGuard &copy; {datetime.utcnow().year} — Automated Security Report</div>
</body></html>"""

def generate_report_now():
    profiles = _profile_snapshot()
    with _packet_lock:
        packets_sample = list(_packet_buffer)
    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{ts}.html"
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(_build_html_report(profiles, packets_sample,
                                   datetime.utcnow().isoformat()[:19]))
    existing = sorted([fn for fn in os.listdir(REPORTS_DIR)
                       if fn.endswith(".html")], reverse=True)
    for old in existing[48:]:
        try: os.remove(os.path.join(REPORTS_DIR, old))
        except: pass
    print(f"[+] Report generated: {filename}")
    return filename

def _schedule_next_report(interval_minutes):
    global _report_timer
    with _report_lock:
        if _report_timer: _report_timer.cancel()
        _report_timer = threading.Timer(
            interval_minutes * 60, _scheduled_report_task, args=(interval_minutes,))
        _report_timer.daemon = True
        _report_timer.start()

def _scheduled_report_task(interval_minutes):
    try:    generate_report_now()
    finally:
        data = load_data()
        if data["report_schedule"]["enabled"]:
            _schedule_next_report(data["report_schedule"]["interval_minutes"])

def start_report_scheduler():
    data  = load_data()
    sched = data.get("report_schedule", {})
    if sched.get("enabled", True):
        interval = sched.get("interval_minutes", 60)
        _schedule_next_report(interval)
        print(f"[+] Report scheduler started — every {interval} min")

# ═══════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
@limiter.limit("10/minute")
def api_login():
    body     = request.get_json(silent=True) or {}
    username = body.get("username", "").strip()
    password = body.get("password", "")
    if not valid_username(username):
        return jsonify({"error": "Invalid username format"}), 400
    if not isinstance(password, str) or len(password) > 128:
        return jsonify({"error": "Invalid password"}), 400
    data = load_data()
    user = data["users"].get(username)
    if not user or not bcrypt.checkpw(password.encode(), user["hash"].encode()):
        audit("LOGIN_FAIL", f"Failed login for '{username}'", username, "warn")
        return jsonify({"error": "Invalid credentials"}), 401
    session.clear()
    session["user_id"]     = str(uuid.uuid4())
    session["username"]    = username
    session["role"]        = user["role"]
    session["last_active"] = time.time()
    audit("LOGIN_OK", f"User '{username}' authenticated (role={user['role']})", username)
    return jsonify({"username": username, "role": user["role"]})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    user = session.get("username", "?")
    session.clear()
    audit("LOGOUT", f"User '{user}' logged out", user)
    return jsonify({"ok": True})

@app.route("/api/me")
def api_me():
    if not session.get("user_id"):
        return jsonify({"error": "Not logged in"}), 401
    if time.time() - session.get("last_active", 0) > SESSION_TIMEOUT:
        session.clear()
        return jsonify({"error": "Session expired"}), 401
    session["last_active"] = time.time()
    return jsonify({"username": session["username"], "role": session["role"]})

# ═══════════════════════════════════════════════════════════════
# SCAN
# ═══════════════════════════════════════════════════════════════
@app.route("/api/scan", methods=["POST"])
@login_required("scan")
def api_scan():
    body   = request.get_json(silent=True) or {}
    subnet = body.get("subnet", "").strip()
    if not valid_cidr(subnet):
        return jsonify({"error": "Invalid subnet (expected CIDR e.g. 192.168.1.0/24)"}), 400
    iface, _ = detect_interface()
    if not iface:
        return jsonify({"error": "No active network interface found"}), 500
    audit("SCAN", f"ARP scan on {subnet}", session["username"])
    try:
        found = arp_scan(subnet, iface)
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500
    data    = load_data()
    blocked = set(data["blocked_macs"])
    devices = [{"ip": d["ip"], "mac": d["mac"], "blocked": d["mac"].lower() in blocked}
               for d in found]
    audit("SCAN_DONE", f"Found {len(devices)} device(s) on {subnet}", session["username"])
    return jsonify({"devices": devices, "iface": iface})

# ═══════════════════════════════════════════════════════════════
# BLOCK / UNBLOCK
# ═══════════════════════════════════════════════════════════════
@app.route("/api/block", methods=["POST"])
@login_required("block")
def api_block():
    body       = request.get_json(silent=True) or {}
    target_ip  = body.get("ip",      "").strip()
    target_mac = body.get("mac",     "").strip().lower()
    gateway_ip = body.get("gateway", "").strip()
    if not valid_ip(target_ip):   return jsonify({"error": "Invalid target IP"}), 400
    if not valid_mac(target_mac): return jsonify({"error": "Invalid target MAC"}), 400
    if not valid_ip(gateway_ip):  return jsonify({"error": "Invalid gateway IP"}), 400
    iface, _ = detect_interface()
    if not iface: return jsonify({"error": "No interface"}), 500
    data = load_data()
    if target_mac not in data["blocked_macs"]:
        data["blocked_macs"].append(target_mac)
        save_data(data)
    with _profile_lock:
        _profiles[target_ip]["blocked"] = True
    start_block(target_ip, target_mac, gateway_ip, iface)
    audit("BLOCK", f"Blocking {target_ip} ({target_mac}) via ARP spoof",
          session["username"], "warn")
    return jsonify({"ok": True, "mac": target_mac})

@app.route("/api/unblock", methods=["POST"])
@login_required("unblock")
def api_unblock():
    body       = request.get_json(silent=True) or {}
    target_mac = body.get("mac", "").strip().lower()
    if not valid_mac(target_mac): return jsonify({"error": "Invalid MAC"}), 400
    stop_block(target_mac)
    data = load_data()
    data["blocked_macs"] = [m for m in data["blocked_macs"] if m != target_mac]
    save_data(data)
    audit("UNBLOCK", f"Unblocked {target_mac}", session["username"])
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════
# USER MANAGEMENT ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/api/users", methods=["GET", "POST"])
@login_required("manage_users")
def api_users():
    data = load_data()
    if request.method == "GET":
        users = [{"username": u, "role": meta.get("role", "viewer")}
                 for u, meta in sorted(data.get("users", {}).items())]
        return jsonify({"users": users})

    body = request.get_json(silent=True) or {}
    username = body.get("username", "").strip()
    password = body.get("password", "")
    role = body.get("role", "viewer").strip().lower()

    if not valid_username(username):
        return jsonify({"error": "Invalid username format"}), 400
    if username in data.get("users", {}):
        return jsonify({"error": "User already exists"}), 409
    if role not in ("admin", "viewer"):
        return jsonify({"error": "Role must be admin or viewer"}), 400
    if not isinstance(password, str) or not (8 <= len(password) <= 128):
        return jsonify({"error": "Password must be 8-128 characters"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    data.setdefault("users", {})[username] = {"hash": hashed, "role": role}
    save_data(data)
    audit("USER_CREATE", f"Created user '{username}' role={role}", session["username"])
    return jsonify({"ok": True, "username": username, "role": role})

@app.route("/api/users/<username>", methods=["PUT", "DELETE"])
@login_required("manage_users")
def api_user_detail(username):
    username = username.strip()
    if not valid_username(username):
        return jsonify({"error": "Invalid username format"}), 400

    data = load_data()
    users = data.get("users", {})
    if username not in users:
        return jsonify({"error": "User not found"}), 404

    if request.method == "DELETE":
        if username == session.get("username"):
            return jsonify({"error": "You cannot delete the currently logged-in user"}), 400
        if len(users) <= 1:
            return jsonify({"error": "At least one user must remain"}), 400
        users.pop(username, None)
        save_data(data)
        audit("USER_DELETE", f"Deleted user '{username}'", session["username"], "warn")
        return jsonify({"ok": True})

    body = request.get_json(silent=True) or {}
    changed = []

    if "role" in body:
        role = str(body.get("role", "")).strip().lower()
        if role not in ("admin", "viewer"):
            return jsonify({"error": "Role must be admin or viewer"}), 400
        if username == session.get("username") and role != session.get("role"):
            return jsonify({"error": "You cannot change your own role while logged in"}), 400
        users[username]["role"] = role
        changed.append(f"role={role}")

    if "password" in body and body.get("password"):
        password = body.get("password", "")
        if not isinstance(password, str) or not (8 <= len(password) <= 128):
            return jsonify({"error": "Password must be 8-128 characters"}), 400
        users[username]["hash"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
        changed.append("password updated")

    if not changed:
        return jsonify({"error": "No changes provided"}), 400

    save_data(data)
    audit("USER_UPDATE", f"Updated user '{username}': {', '.join(changed)}", session["username"])
    return jsonify({"ok": True, "username": username, "role": users[username]["role"]})

# ═══════════════════════════════════════════════════════════════
# LOGS & NETINFO
# ═══════════════════════════════════════════════════════════════
@app.route("/api/logs")
@login_required("view_logs")
def api_logs():
    data = load_data()
    return jsonify({"logs": data["audit_log"][:100]})

@app.route("/api/netinfo")
@login_required("view_devices")
def api_netinfo():
    iface, ip = detect_interface()
    return jsonify({"iface": iface or "unknown", "ip": ip or "unknown"})

# ═══════════════════════════════════════════════════════════════
# [NEW] PACKET MONITORING ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/api/packets")
@login_required("view_packets")
def api_packets():
    try:
        limit    = min(int(request.args.get("limit", 100)), PACKET_BUFFER_SIZE)
        proto    = request.args.get("proto", "").upper()
        min_risk = int(request.args.get("min_risk", 0))
    except ValueError:
        return jsonify({"error": "Invalid query params"}), 400
    with _packet_lock:
        pkts = list(_packet_buffer)
    if proto:    pkts = [p for p in pkts if p["proto"] == proto]
    if min_risk: pkts = [p for p in pkts if p["risk"] >= min_risk]
    return jsonify({"packets": pkts[:limit], "total": len(pkts),
                    "buffer_size": PACKET_BUFFER_SIZE})

@app.route("/api/packets/stats")
@login_required("view_packets")
def api_packets_stats():
    with _packet_lock:
        pkts = list(_packet_buffer)
    proto_count  = defaultdict(int)
    risk_dist    = {"low": 0, "medium": 0, "high": 0}
    total_bytes  = 0
    for p in pkts:
        proto_count[p["proto"]] += 1
        risk_dist[p["label"]]   += 1
        total_bytes += p["size"]
    return jsonify({
        "total_captured":    len(pkts),
        "proto_breakdown":   dict(proto_count),
        "risk_distribution": risk_dist,
        "total_bytes":       total_bytes,
        "sniffer_running":   _sniffer_thread is not None and _sniffer_thread.is_alive(),
    })

@app.route("/api/packets/block", methods=["POST"])
@login_required("block")
def api_block_from_packet():
    body = request.get_json(silent=True) or {}
    pid  = body.get("packet_id", "").strip()
    if not pid: return jsonify({"error": "packet_id required"}), 400
    with _packet_lock:
        target = next((p for p in _packet_buffer if p["id"] == pid), None)
    if not target: return jsonify({"error": "Packet not found in buffer"}), 404
    audit("PKT_BLOCK_REQUEST", f"Block requested for {target['src']} from packet {pid}",
          session["username"], "warn")
    return jsonify({"ok": True, "src_ip": target["src"],
                    "note": "Use /api/block with ip+mac+gateway to apply ARP block."})

# ═══════════════════════════════════════════════════════════════
# [NEW] SOC PROFILER ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/api/soc/profiles")
@login_required("view_packets")
def api_soc_profiles():
    try:
        min_risk     = int(request.args.get("min_risk", 0))
        threat_level = request.args.get("threat_level", "").lower()
    except ValueError:
        return jsonify({"error": "Invalid params"}), 400
    profiles = _profile_snapshot()
    if min_risk:     profiles = [p for p in profiles if p["avg_risk"] >= min_risk]
    if threat_level in ("high","medium","low"):
        profiles = [p for p in profiles if p["threat_level"] == threat_level]
    return jsonify({"profiles": profiles, "total": len(profiles)})

@app.route("/api/soc/profiles/<ip>")
@login_required("view_packets")
def api_soc_profile_detail(ip):
    if not valid_ip(ip): return jsonify({"error": "Invalid IP"}), 400
    with _profile_lock:
        p = _profiles.get(ip)
    if not p: return jsonify({"error": "No profile for this IP"}), 404
    scores = list(p["risk_scores"])
    return jsonify({
        "ip": ip, "first_seen": p["first_seen"], "last_seen": p["last_seen"],
        "pkt_count": p["pkt_count"], "bytes_total": p["bytes_total"],
        "protocols": dict(p["protocols"]), "domains": p["domains"],
        "dst_ips": p["dst_ips"],
        "avg_risk": round(sum(scores)/len(scores)) if scores else 0,
        "max_risk": p["max_risk"], "blocked": p["blocked"],
    })

@app.route("/api/soc/recommendations")
@login_required("view_packets")
def api_soc_recommendations():
    profiles = _profile_snapshot()
    return jsonify({"recommendations": _threat_recommendations(profiles),
                    "generated_at": datetime.utcnow().isoformat()})

# ═══════════════════════════════════════════════════════════════
# [NEW] REPORT ROUTES
# ═══════════════════════════════════════════════════════════════
@app.route("/api/reports")
@login_required("view_reports")
def api_reports_list():
    files = sorted([fn for fn in os.listdir(REPORTS_DIR)
                    if fn.endswith(".html")], reverse=True)
    out = [{"filename": fn,
            "size_kb":  round(os.path.getsize(os.path.join(REPORTS_DIR, fn)) / 1024, 1),
            "url":      f"/reports/{fn}"}
           for fn in files[:20]]
    return jsonify({"reports": out})

@app.route("/api/reports/generate", methods=["POST"])
@login_required("view_reports")
def api_reports_generate():
    try:
        filename = generate_report_now()
        audit("REPORT_GEN", f"Manual report: {filename}", session["username"])
        return jsonify({"ok": True, "filename": filename, "url": f"/reports/{filename}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reports/schedule", methods=["GET", "POST"])
@login_required("view_reports")
def api_reports_schedule():
    data = load_data()
    if request.method == "GET":
        return jsonify(data.get("report_schedule", {}))
    body     = request.get_json(silent=True) or {}
    interval = body.get("interval_minutes")
    enabled  = body.get("enabled")
    if interval is not None:
        try:
            interval = int(interval)
            assert 5 <= interval <= 10080
        except (ValueError, AssertionError):
            return jsonify({"error": "interval_minutes must be 5–10080"}), 400
        data["report_schedule"]["interval_minutes"] = interval
    if enabled is not None:
        data["report_schedule"]["enabled"] = bool(enabled)
    save_data(data)
    if data["report_schedule"]["enabled"]:
        _schedule_next_report(data["report_schedule"]["interval_minutes"])
    else:
        with _report_lock:
            if _report_timer: _report_timer.cancel()
    audit("REPORT_SCHEDULE", f"Updated: {data['report_schedule']}", session["username"])
    return jsonify({"ok": True, "schedule": data["report_schedule"]})

@app.route("/reports/<path:filename>")
@login_required("view_reports")
def serve_report(filename):
    safe = re.sub(r"[^a-zA-Z0-9_.\-]", "", filename)
    if not safe.endswith(".html"):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(REPORTS_DIR, safe)

# ═══════════════════════════════════════════════════════════════
# FRONTEND
# ═══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

# ═══════════════════════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.name != "nt" and os.geteuid() != 0:
        print("[!] Must run as root for ARP/sniff operations: sudo python app.py")
        sys.exit(1)
    if not os.path.exists(STORAGE_FILE):
        save_data(_default_data())
        print("[+] Storage initialized (admin / Admin@1234)")
    iface, ip = detect_interface()
    print(f"[+] Interface : {iface}  IP: {ip}")
    print(f"[+] Storage   : {STORAGE_FILE} (Fernet-encrypted)")
    start_sniffer()           # [NEW] live packet capture
    start_report_scheduler()  # [NEW] periodic HTML reports
    print("[+] Running at http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
