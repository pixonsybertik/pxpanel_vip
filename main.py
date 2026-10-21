# ============================================================
# PX Panel PRO — Commercial · Railway · Matte UI
# Auth: /setup (once) · /pxpanelworking (login)
# Protocols: VLESS-WS + XHTTP (advanced)
# ============================================================
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import string
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import aiofiles
import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

# ── App ─────────────────────────────────────────────────────
APP_NAME = "PX"
APP_VERSION = "14.0.0-pro"
PORT = int(os.environ.get("PORT", "8000"))
DATA_DIR = Path(os.environ.get("RAILWAY_VOLUME_MOUNT_PATH") or os.environ.get("DATA_DIR") or "./data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE = DATA_DIR / "px_state.json"
SECRET_FILE = DATA_DIR / "px_secret.key"
SESSION_COOKIE = "px_sess"
SESSION_TTL = 60 * 60 * 12  # 12h

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(APP_NAME)

app = FastAPI(title=APP_NAME, version=APP_VERSION, docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
try:
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")
except Exception:
    pass

# ── State ───────────────────────────────────────────────────
SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
LINKS: dict = {}
FOLDERS: dict = {"0": {"id": "0", "name": "پیش‌فرض", "created_at": ""}}
SESSIONS: dict = {}  # token -> {exp, ip}
LOGIN_FAILS: dict = defaultdict(lambda: {"n": 0, "until": 0.0})
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "started_at": time.time()}
connections: dict = {}
activity_logs: deque = deque(maxlen=200)
error_logs: deque = deque(maxlen=100)
CONFIG = {"host": os.environ.get("RAILWAY_PUBLIC_DOMAIN") or "localhost"}
PASSWORD_HASH: str | None = None
SECRET_KEY: bytes = b""

PROTOCOLS = ("vless-ws", "xhttp-stream-up")
PROTOCOL_LABELS = {"vless-ws": "VLESS WS", "xhttp-stream-up": "XHTTP Fast"}
DEFAULT_PROTOCOL = "vless-ws"
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "random")
DEFAULT_FINGERPRINT = "chrome"

# ── Crypto / utils ──────────────────────────────────────────
def _load_secret() -> bytes:
    if SECRET_FILE.exists():
        return SECRET_FILE.read_bytes().strip() or secrets.token_bytes(32)
    k = secrets.token_bytes(32)
    SECRET_FILE.write_bytes(k)
    return k

def hash_password(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), SECRET_KEY, 120_000).hex()

def verify_password(pw: str, h: str) -> bool:
    try:
        return hmac.compare_digest(hash_password(pw), h)
    except Exception:
        return False

def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def safe_int(v, default=0, minimum=None, maximum=None):
    try:
        n = int(float(v))
    except Exception:
        n = default
    if minimum is not None:
        n = max(minimum, n)
    if maximum is not None:
        n = min(maximum, n)
    return n

def fmt_bytes(n: int) -> str:
    n = float(max(0, int(n or 0)))
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"

def parse_size_to_bytes(value, unit="GB") -> int:
    try:
        v = float(value)
    except Exception:
        return 0
    if v <= 0:
        return 0
    m = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}.get(str(unit).upper(), 1024**3)
    return int(v * m)

def parse_speed_to_bytes(value, unit="MBIT") -> int:
    try:
        v = float(value)
    except Exception:
        return 0
    if v <= 0:
        return 0
    # store as bytes/sec
    if str(unit).upper() in ("MBIT", "MBPS"):
        return int(v * 1_000_000 / 8)
    return int(v)

def random_name(n=8) -> str:
    chars = string.ascii_lowercase + string.digits
    s = "".join(secrets.choice(chars) for _ in range(n))
    if s[0].isdigit():
        s = "a" + s[1:]
    return s

def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"

def get_host(request: Request | None = None) -> str:
    if request is not None:
        h = request.headers.get("x-forwarded-host") or request.headers.get("host")
        if h:
            h = h.split(":")[0].strip()
            CONFIG["host"] = h
            return h
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN") or CONFIG.get("host") or "localhost"

def log_activity(kind: str, msg: str, level: str = "info"):
    activity_logs.appendleft({"kind": kind, "msg": msg, "level": level, "time": now_iso()})

# ── Persistence ─────────────────────────────────────────────
async def save_state():
    async with SAVE_LOCK:
        data = {
            "password_hash": PASSWORD_HASH,
            "links": LINKS,
            "folders": FOLDERS,
            "stats": stats,
            "config": CONFIG,
        }
        tmp = DATA_FILE.with_suffix(".tmp")
        async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
            await f.write(json.dumps(data, ensure_ascii=False))
        tmp.replace(DATA_FILE)

async def load_state():
    global PASSWORD_HASH, LINKS, FOLDERS, stats, CONFIG
    if not DATA_FILE.exists():
        return
    try:
        async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.loads(await f.read())
        PASSWORD_HASH = data.get("password_hash")
        LINKS = data.get("links") or {}
        FOLDERS = data.get("folders") or FOLDERS
        if "0" not in FOLDERS:
            FOLDERS["0"] = {"id": "0", "name": "پیش‌فرض", "created_at": now_iso()}
        st = data.get("stats") or {}
        stats.update({k: st.get(k, stats[k]) for k in stats if k != "started_at"})
        CONFIG.update(data.get("config") or {})
    except Exception as e:
        logger.warning("load_state: %s", e)

# ── Auth ────────────────────────────────────────────────────
def needs_setup() -> bool:
    return not PASSWORD_HASH

def create_session(ip: str) -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {"exp": time.time() + SESSION_TTL, "ip": ip}
    return token

def destroy_session(token: str | None):
    if token:
        SESSIONS.pop(token, None)

def session_ok(token: str | None, ip: str | None = None) -> bool:
    if not token or token not in SESSIONS:
        return False
    s = SESSIONS[token]
    if s["exp"] < time.time():
        SESSIONS.pop(token, None)
        return False
    return True

async def require_auth(request: Request):
    if needs_setup():
        raise HTTPException(503, detail="setup required")
    token = request.cookies.get(SESSION_COOKIE)
    if not session_ok(token):
        raise HTTPException(401, detail="unauthorized")
    return token

def login_locked(ip: str) -> bool:
    row = LOGIN_FAILS[ip]
    return row["until"] > time.time()

def register_fail(ip: str):
    row = LOGIN_FAILS[ip]
    row["n"] += 1
    if row["n"] >= 5:
        row["until"] = time.time() + 30 * 60
        row["n"] = 0

def clear_fails(ip: str):
    LOGIN_FAILS.pop(ip, None)

# ── Links ───────────────────────────────────────────────────
def is_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.fromisoformat(str(exp).replace("Z", "")) < datetime.utcnow()
    except Exception:
        return False

def is_allowed(link: dict | None) -> bool:
    if not link:
        return False
    if link.get("active") is False:
        return False
    if is_expired(link):
        return False
    lim = int(link.get("limit_bytes") or 0)
    used = int(link.get("used_bytes") or 0)
    if lim > 0 and used >= lim:
        return False
    return True

def unique_ips_for_uuid(uuid: str) -> set:
    ips = set()
    for c in connections.values():
        if c.get("uuid") == uuid and c.get("ip"):
            ips.add(c["ip"])
    return ips


# ── Compat aliases for relay_vless / xhttp_siz10 ─────────────
is_link_allowed = is_allowed
hourly_traffic: dict = {}
def now_ir():
    return datetime.utcnow()

def is_ip_allowed(link: dict, uuid: str, ip: str) -> bool:
    limit = int(link.get("ip_limit") or 0)
    if limit <= 0:
        return True
    ips = unique_ips_for_uuid(uuid)
    if ip in ips:
        return True
    return len(ips) < limit

def generate_vless_link(uuid: str, host: str, remark: str = "PX", protocol: str = "vless-ws",
                       fingerprint: str = "chrome", alpn: str = "http/1.1", port: int = 443) -> str:
    fp = fingerprint if fingerprint in FINGERPRINTS else DEFAULT_FINGERPRINT
    label = quote(str(remark or "PX"), safe="")
    if protocol == "xhttp-stream-up":
        q = {
            "encryption": "none", "security": "tls", "type": "xhttp", "mode": "stream-up",
            "host": host, "path": f"/xhttp-siz10/stream-up/{uuid}", "sni": host,
            "fp": fp, "alpn": alpn or "h2,http/1.1",
        }
    else:
        q = {
            "encryption": "none", "security": "tls", "type": "ws",
            "host": host, "path": f"/ws/{uuid}", "sni": host,
            "fp": fp, "alpn": "http/1.1",
        }
    qs = "&".join(f"{k}={quote(str(v), safe=',/')}" for k, v in q.items())
    return f"vless://{uuid}@{host}:{port}?{qs}#{label}"

def link_info(link: dict, uid: str, host: str) -> dict:
    used = int(link.get("used_bytes") or 0)
    lim = int(link.get("limit_bytes") or 0)
    proto = link.get("protocol") or DEFAULT_PROTOCOL
    return {
        "uuid": uid,
        "id": uid,
        "label": link.get("label") or uid[:8],
        "protocol": proto,
        "active": is_allowed(link),
        "expired": is_expired(link),
        "used_bytes": used,
        "limit_bytes": lim,
        "expires_at": link.get("expires_at"),
        "ip_limit": int(link.get("ip_limit") or 0),
        "connection_limit": int(link.get("connection_limit") or 0),
        "speed_limit_bytes": int(link.get("speed_limit_bytes") or 0),
        "folder_id": str(link.get("folder_id") or "0"),
        "note": link.get("note") or "",
        "created_at": link.get("created_at"),
        "vless": generate_vless_link(uid, host, link.get("label") or "PX", proto,
                                    link.get("fingerprint") or DEFAULT_FINGERPRINT,
                                    link.get("alpn") or "http/1.1",
                                    int(link.get("port") or 443)),
        "sub_url": f"https://{host}/sub/{uid}",
        "connected_ips": len(unique_ips_for_uuid(uid)),
    }

async def make_link(**kw) -> tuple[str, dict]:
    uid = str(secrets.token_hex(4)) + "-" + str(secrets.token_hex(2)) + "-" + str(secrets.token_hex(2)) + "-" + str(secrets.token_hex(2)) + "-" + str(secrets.token_hex(6))
    # simpler uuid-like
    import uuid as _uuid
    uid = str(_uuid.uuid4())
    protocol = kw.get("protocol") or DEFAULT_PROTOCOL
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL
    link = {
        "label": (kw.get("label") or random_name()).strip()[:64],
        "protocol": protocol,
        "active": True,
        "used_bytes": 0,
        "limit_bytes": int(kw.get("limit_bytes") or 0),
        "expires_at": kw.get("expires_at"),
        "ip_limit": int(kw.get("ip_limit") or 0),
        "connection_limit": int(kw.get("connection_limit") or 0),
        "speed_limit_bytes": int(kw.get("speed_limit_bytes") or 0),
        "folder_id": str(kw.get("folder_id") or "0"),
        "fingerprint": kw.get("fingerprint") or DEFAULT_FINGERPRINT,
        "alpn": kw.get("alpn") or ("http/1.1" if protocol == "vless-ws" else "h2,http/1.1"),
        "port": int(kw.get("port") or 443),
        "note": (kw.get("note") or "")[:300],
        "created_at": now_iso(),
        "config_count": max(1, min(40, int(kw.get("config_count") or 1))),
    }
    async with LINKS_LOCK:
        LINKS[uid] = link
    await save_state()
    log_activity("link", f"کانفیگ «{link['label']}» ساخته شد", "ok")
    return uid, link

async def remove_link(uid: str):
    async with LINKS_LOCK:
        link = LINKS.pop(uid, None)
    if link:
        await save_state()
        log_activity("link", f"کانفیگ «{link.get('label')}» حذف شد", "warn")
        return link.get("label")
    return None

# ── Startup ─────────────────────────────────────────────────
http_client: httpx.AsyncClient | None = None

@app.on_event("startup")
async def startup():
    global SECRET_KEY, http_client
    SECRET_KEY = _load_secret()
    await load_state()
    http_client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=15.0), follow_redirects=True)
    # warm system metrics
    try:
        from system import sample
        sample()
    except Exception:
        pass
    logger.info("%s v%s on 0.0.0.0:%s data=%s", APP_NAME, APP_VERSION, PORT, DATA_DIR)

@app.on_event("shutdown")
async def shutdown():
    await save_state()
    if http_client:
        await http_client.aclose()

# ── Health ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": APP_NAME, "version": APP_VERSION}

# ── Setup & Auth routes ─────────────────────────────────────
@app.get("/setup", response_class=HTMLResponse)
async def setup_page():
    if not needs_setup():
        return RedirectResponse("/pxpanelworking", status_code=302)
    return HTMLResponse(SETUP_HTML)

@app.post("/api/setup")
async def api_setup(request: Request):
    global PASSWORD_HASH
    if not needs_setup():
        raise HTTPException(400, detail="already configured")
    body = await request.json()
    pw = str(body.get("password") or "")
    pw2 = str(body.get("password2") or "")
    if len(pw) < 8:
        raise HTTPException(400, detail="رمز حداقل ۸ کاراکتر")
    if pw != pw2:
        raise HTTPException(400, detail="رمزها یکسان نیستند")
    PASSWORD_HASH = hash_password(pw)
    await save_state()
    token = create_session(client_ip(request))
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=SESSION_TTL, secure=True)
    log_activity("auth", "راه‌اندازی اولیه انجام شد", "ok")
    return resp

@app.get("/pxpanelworking", response_class=HTMLResponse)
async def login_page(request: Request):
    if needs_setup():
        return RedirectResponse("/setup", status_code=302)
    token = request.cookies.get(SESSION_COOKIE)
    if session_ok(token):
        return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(LOGIN_HTML)

@app.post("/api/pxpanelworking")
async def api_login(request: Request):
    if needs_setup():
        raise HTTPException(503, detail="setup required")
    ip = client_ip(request)
    if login_locked(ip):
        raise HTTPException(429, detail="ایپی موقتاً قفل است (۳۰ دقیقه)")
    body = await request.json()
    pw = str(body.get("password") or "")
    if not PASSWORD_HASH or not verify_password(pw, PASSWORD_HASH):
        register_fail(ip)
        log_activity("auth", f"ورود ناموفق از {ip}", "warn")
        raise HTTPException(401, detail="رمز اشتباه است")
    clear_fails(ip)
    token = create_session(ip)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=SESSION_TTL, secure=True)
    log_activity("auth", f"ورود موفق از {ip}", "ok")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp

@app.get("/")
async def root(request: Request):
    """Always serve decoy reCAPTCHA landing — curl, browser, bots, anything."""
    return HTMLResponse(
        DECOY_HTML,
        status_code=200,
        media_type="text/html; charset=utf-8",
        headers={
            "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Language": "en",
            "Server": "cloudflare",  # soft fingerprint noise
        },
    )


@app.get("/robots.txt")
async def robots():
    return Response(
        "User-agent: *\nDisallow: /\n",
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


# Common probe paths → same decoy (no panel leak)
@app.get("/index.html")
@app.get("/home")
@app.get("/login")
@app.get("/admin")
@app.get("/panel")
@app.get("/wp-admin")
@app.get("/wp-login.php")
async def decoy_aliases(request: Request):
    return await root(request)

# ── Dashboard ───────────────────────────────────────────────
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if needs_setup():
        return RedirectResponse("/setup")
    if not session_ok(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/pxpanelworking")
    return HTMLResponse(DASH_HTML)

# ── API ─────────────────────────────────────────────────────
@app.get("/api/me")
async def api_me(_=Depends(require_auth)):
    return {"ok": True, "app": APP_NAME, "version": APP_VERSION}

@app.get("/api/stats")
async def api_stats(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    up = int(time.time() - stats.get("started_at", time.time()))
    return {
        "connections": len(connections),
        "links": len(LINKS),
        "active_links": sum(1 for L in LINKS.values() if is_allowed(L)),
        "traffic": int(stats.get("total_bytes") or 0),
        "uptime": up,
        "host": host,
        "requests": int(stats.get("total_requests") or 0),
        "errors": int(stats.get("total_errors") or 0),
    }

@app.get("/api/system")
async def api_system(_=Depends(require_auth)):
    try:
        from system import get_snapshot
        return get_snapshot()
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.get("/api/folders")
async def api_folders(_=Depends(require_auth)):
    return {"folders": list(FOLDERS.values())}

@app.post("/api/folders")
async def api_folder_create(request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = str(body.get("name") or "").strip()[:40]
    if not name:
        raise HTTPException(400, detail="نام لازم است")
    fid = secrets.token_hex(4)
    FOLDERS[fid] = {"id": fid, "name": name, "created_at": now_iso()}
    await save_state()
    return {"ok": True, "folder": FOLDERS[fid]}

@app.delete("/api/folders/{fid}")
async def api_folder_delete(fid: str, _=Depends(require_auth)):
    if fid == "0":
        raise HTTPException(400, detail="پوشه پیش‌فرض قابل حذف نیست")
    if fid not in FOLDERS:
        raise HTTPException(404)
    FOLDERS.pop(fid)
    async with LINKS_LOCK:
        for L in LINKS.values():
            if str(L.get("folder_id")) == fid:
                L["folder_id"] = "0"
    await save_state()
    return {"ok": True}

@app.get("/api/links")
async def api_links(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    out = []
    async with LINKS_LOCK:
        items = list(LINKS.items())
    for uid, link in items:
        info = link_info(link, uid, host)
        out.append(info)
    out.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"links": out}

@app.post("/api/links")
async def api_create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    protocol = str(body.get("protocol") or DEFAULT_PROTOCOL)
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL
    limit_bytes = 0
    if body.get("limit_value"):
        limit_bytes = parse_size_to_bytes(body.get("limit_value"), body.get("limit_unit") or "GB")
    days = safe_int(body.get("expires_days"), 0, 0, 3650)
    expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat() + "Z" if days > 0 else None
    speed_b = parse_speed_to_bytes(body.get("speed_limit_value") or 0, "MBIT")
    uid, link = await make_link(
        label=body.get("label") or random_name(),
        protocol=protocol,
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        ip_limit=safe_int(body.get("ip_limit"), 0, 0, 1000),
        connection_limit=safe_int(body.get("connection_limit"), 0, 0, 1000),
        speed_limit_bytes=speed_b,
        folder_id=str(body.get("folder_id") or "0"),
        note=body.get("note") or "",
        config_count=safe_int(body.get("config_count"), 1, 1, 40),
        fingerprint=body.get("fingerprint") or DEFAULT_FINGERPRINT,
        alpn=body.get("alpn") or "",
        port=safe_int(body.get("port"), 443, 1, 65535),
    )
    host = get_host(request)
    return {"ok": True, **link_info(link, uid, host)}

@app.patch("/api/links/{uid}")
async def api_patch_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(404)
        link = LINKS[uid]
        if "label" in body and str(body["label"]).strip():
            link["label"] = str(body["label"]).strip()[:64]
        if "active" in body:
            link["active"] = bool(body["active"])
        if "folder_id" in body:
            fid = str(body["folder_id"] or "0")
            link["folder_id"] = fid if fid in FOLDERS else "0"
        if "ip_limit" in body:
            link["ip_limit"] = safe_int(body["ip_limit"], 0, 0, 1000)
        if "connection_limit" in body:
            link["connection_limit"] = safe_int(body["connection_limit"], 0, 0, 1000)
        if "speed_limit_value" in body:
            link["speed_limit_bytes"] = parse_speed_to_bytes(body.get("speed_limit_value") or 0, "MBIT")
        if "limit_value" in body:
            link["limit_bytes"] = parse_size_to_bytes(body.get("limit_value"), body.get("limit_unit") or "GB")
        if "expires_days" in body:
            d = safe_int(body["expires_days"], 0, 0, 3650)
            link["expires_at"] = (datetime.utcnow() + timedelta(days=d)).isoformat() + "Z" if d > 0 else None
        if "protocol" in body and body["protocol"] in PROTOCOLS:
            link["protocol"] = body["protocol"]
        if "note" in body:
            link["note"] = str(body["note"] or "")[:300]
    await save_state()
    host = get_host(request)
    return {"ok": True, **link_info(LINKS[uid], uid, host)}

@app.delete("/api/links/{uid}")
async def api_delete_link(uid: str, _=Depends(require_auth)):
    label = await remove_link(uid)
    if label is None:
        raise HTTPException(404)
    return {"ok": True, "deleted": uid}

@app.get("/api/activity")
async def api_activity(_=Depends(require_auth)):
    return {"logs": list(activity_logs)[:80]}

@app.get("/api/protocols")
async def api_protocols(_=Depends(require_auth)):
    return {
        "protocols": [{"id": p, "label": PROTOCOL_LABELS.get(p, p)} for p in PROTOCOLS],
        "default": DEFAULT_PROTOCOL,
        "advanced": ["xhttp-stream-up"],
    }

# ── Subscription ────────────────────────────────────────────

def _sub_lines(uuid: str, link: dict, host: str) -> list[str]:
    n = max(1, min(40, int(link.get("config_count") or 1)))
    lines = []
    for i in range(n):
        name = link.get("label") or "PX"
        if n > 1:
            name = f"{name}-{i + 1}"
        lines.append(
            generate_vless_link(
                uuid,
                host,
                name,
                link.get("protocol") or DEFAULT_PROTOCOL,
                link.get("fingerprint") or DEFAULT_FINGERPRINT,
                link.get("alpn") or "http/1.1",
                int(link.get("port") or 443),
            )
        )
    return lines


def _wants_html(request: Request) -> bool:
    """Browser page vs raw subscription for clients."""
    if request.query_params.get("raw") in ("1", "true", "yes"):
        return False
    if request.query_params.get("format") == "base64":
        return False
    accept = (request.headers.get("accept") or "").lower()
    ua = (request.headers.get("user-agent") or "").lower()
    if "text/html" in accept:
        return True
    if any(x in ua for x in ("mozilla", "chrome", "safari", "edg/", "firefox", "mobile")):
        # still prefer raw if known proxy clients
        if any(x in ua for x in ("v2ray", "clash", "sing-box", "shadowrocket", "quantumult", "surge", "hiddify", "streisand", "nekobox", "passwall")):
            return False
        return True
    return False


def _fmt_expire(link: dict) -> str:
    exp = link.get("expires_at")
    if not exp:
        return "بدون انقضا"
    try:
        dt = datetime.fromisoformat(str(exp).replace("Z", ""))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(exp)[:16]


def render_sub_page(uuid: str, link: dict, host: str, lines: list[str], b64: str) -> str:
    label = link.get("label") or "PX"
    proto = link.get("protocol") or DEFAULT_PROTOCOL
    used = int(link.get("used_bytes") or 0)
    lim = int(link.get("limit_bytes") or 0)
    used_h = fmt_bytes(used)
    lim_h = fmt_bytes(lim) if lim > 0 else "∞"
    pct = min(100, int(used * 100 / lim)) if lim > 0 else 0
    status = "فعال" if is_allowed(link) else "غیرفعال"
    status_cls = "ok" if is_allowed(link) else "bad"
    ip_l = int(link.get("ip_limit") or 0) or "∞"
    conn_l = int(link.get("connection_limit") or 0) or "∞"
    speed = int(link.get("speed_limit_bytes") or 0)
    speed_h = f"{(speed * 8 / 1_000_000):.1f} Mbps" if speed > 0 else "∞"
    expire_h = _fmt_expire(link)
    sub_url = f"https://{host}/sub/{uuid}"
    raw_url = f"https://{host}/sub/{uuid}?raw=1"
    configs_html = ""
    for i, ln in enumerate(lines):
        configs_html += f"""
        <div class="cfg">
          <div class="cfg-top">
            <span class="tag">#{i + 1}</span>
            <button type="button" class="btn" onclick="copyText(this.getAttribute('data-c'))" data-c="{ln.replace('&', '&amp;').replace('"', '&quot;')}">کپی</button>
          </div>
          <code class="link">{ln}</code>
        </div>"""
    # escape for HTML in label etc
    def e(s):
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    label_e = e(label)
    return f"""<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PX · {label_e}</title>
<style>
:root{{
  --bg:#121214;--bg2:#1a1a1d;--bg3:#222226;--line:#2e2e33;
  --t1:#ececec;--t2:#a0a0a8;--t3:#6b6b74;
  --acc:#5b7cfa;--ok:#3d9a6a;--bad:#c45c5c;
  --r:12px;--font:'Segoe UI',Tahoma,system-ui,sans-serif;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--t1);font-family:var(--font);font-size:13px;direction:rtl;min-height:100vh;padding:28px 16px 48px}}
.wrap{{max-width:640px;margin:0 auto}}
.brand{{font-size:12px;color:var(--t3);letter-spacing:.08em;margin-bottom:8px}}
h1{{font-size:20px;font-weight:700;margin-bottom:6px}}
.sub{{color:var(--t3);font-size:12px;margin-bottom:18px}}
.card{{background:var(--bg2);border:1px solid var(--line);border-radius:var(--r);padding:16px;margin-bottom:12px}}
.row{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
@media(max-width:560px){{.row{{grid-template-columns:1fr}}}}
.stat .l{{font-size:11px;color:var(--t3);margin-bottom:4px}}
.stat .v{{font-size:15px;font-weight:600}}
.badge{{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;background:var(--bg3)}}
.badge.ok{{color:var(--ok);background:rgba(61,154,106,.12)}}
.badge.bad{{color:var(--bad);background:rgba(196,92,92,.12)}}
.bar{{height:8px;background:var(--line);border-radius:99px;overflow:hidden;margin-top:10px}}
.bar>i{{display:block;height:100%;background:var(--acc);width:{pct}%}}
.btn{{display:inline-flex;align-items:center;gap:6px;padding:8px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg3);color:var(--t1);cursor:pointer;font-size:12px;font-family:inherit}}
.btn:hover{{border-color:var(--t3)}}
.btn-p{{background:var(--acc);border-color:var(--acc);color:#fff}}
.actions{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}}
.cfg{{border:1px solid var(--line);border-radius:10px;padding:12px;margin-bottom:8px;background:var(--bg3)}}
.cfg-top{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}}
.tag{{font-size:11px;color:var(--t3)}}
code.link{{display:block;font-size:11px;word-break:break-all;color:var(--t2);line-height:1.55;font-family:ui-monospace,monospace}}
code.b64{{display:block;font-size:10px;word-break:break-all;color:var(--t3);max-height:120px;overflow:auto;line-height:1.5;font-family:ui-monospace,monospace;background:var(--bg);padding:10px;border-radius:8px;border:1px solid var(--line)}}
.foot{{margin-top:18px;text-align:center;color:var(--t3);font-size:11px}}
.toast{{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--bg3);border:1px solid var(--line);padding:10px 16px;border-radius:8px;opacity:0;transition:.2s;z-index:9}}
.toast.show{{opacity:1}}
h2{{font-size:13px;font-weight:600;margin-bottom:10px;color:var(--t2)}}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">PX SUBSCRIPTION</div>
  <h1>{label_e}</h1>
  <p class="sub">شناسه · <code style="color:var(--t2)">{e(uuid)}</code></p>

  <div class="card">
    <div class="row">
      <div class="stat"><div class="l">وضعیت</div><div class="v"><span class="badge {status_cls}">{status}</span></div></div>
      <div class="stat"><div class="l">پروتکل</div><div class="v">{e(proto)}</div></div>
      <div class="stat"><div class="l">مصرف</div><div class="v">{used_h} / {lim_h}</div></div>
      <div class="stat"><div class="l">انقضا</div><div class="v">{e(expire_h)}</div></div>
      <div class="stat"><div class="l">محدودیت IP</div><div class="v">{ip_l}</div></div>
      <div class="stat"><div class="l">کاربر همزمان</div><div class="v">{conn_l}</div></div>
      <div class="stat"><div class="l">سرعت</div><div class="v">{speed_h}</div></div>
      <div class="stat"><div class="l">تعداد در ساب</div><div class="v">{len(lines)}</div></div>
    </div>
    <div class="bar"><i></i></div>
    <div class="actions">
      <button class="btn btn-p" onclick="copyText('{e(sub_url)}')">کپی لینک ساب</button>
      <button class="btn" onclick="copyText('{e(raw_url)}')">کپی خروجی خام</button>
      <button class="btn" onclick="copyText(document.getElementById('b64').innerText)">کپی Base64</button>
    </div>
  </div>

  <div class="card">
    <h2>کانفیگ‌ها</h2>
    {configs_html}
  </div>

  <div class="card">
    <h2>Base64</h2>
    <code class="b64" id="b64">{e(b64)}</code>
    <div class="actions">
      <button class="btn" onclick="copyText(document.getElementById('b64').innerText)">کپی Base64</button>
      <a class="btn" href="{e(raw_url)}">دانلود raw</a>
    </div>
  </div>

  <div class="foot">PX · همه چیز روی /sub · بدون مسیر اضافه</div>
</div>
<div class="toast" id="toast">کپی شد</div>
<script>
function copyText(t){{
  navigator.clipboard.writeText(t).then(()=>{{
    const el=document.getElementById('toast');
    el.classList.add('show');
    setTimeout(()=>el.classList.remove('show'),1600);
  }}).catch(()=>{{}});
}}
</script>
</body>
</html>"""


@app.get("/sub/{uuid}")
async def sub_single(uuid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link:
        raise HTTPException(404, detail="not found")
    # allow page view even if near-limit; block only fully missing
    host = get_host(request)
    lines = _sub_lines(uuid, link, host)
    if not lines:
        raise HTTPException(404, detail="empty")
    plain = "\n".join(lines)
    b64 = base64.b64encode(plain.encode()).decode()

    # Stylish browser page — all info on /sub (no /info, no /user_info)
    if _wants_html(request):
        html = render_sub_page(uuid, link, host, lines, b64)
        return HTMLResponse(html)

    # Raw base64 for clients (v2rayNG, Hiddify, ...)
    used = int(link.get("used_bytes") or 0)
    lim = int(link.get("limit_bytes") or 0)
    exp = 0
    if link.get("expires_at"):
        try:
            exp = int(datetime.fromisoformat(str(link["expires_at"]).replace("Z", "")).timestamp())
        except Exception:
            exp = 0
    headers = {
        "profile-title": base64.b64encode((link.get("label") or "PX").encode()).decode(),
        "profile-update-interval": "12",
        "content-disposition": 'inline; filename="px.txt"',
        # traffic hint without separate user_info path
        "x-px-used": str(used),
        "x-px-total": str(lim),
        "x-px-expire": str(exp),
    }
    return Response(content=b64, media_type="text/plain; charset=utf-8", headers=headers)


# ── Optional modules ────────────────────────────────────────
try:
    from relay_vless import websocket_tunnel
    app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)
    logger.info("VLESS WS relay loaded")
except Exception as e:
    logger.warning("relay: %s", e)

try:
    from xhttp_siz10 import router as xhttp_router
    app.include_router(xhttp_router)
    logger.info("XHTTP loaded")
except Exception as e:
    logger.warning("xhttp: %s", e)

# ── HTML (matte · minimal · left sidebar) ───────────────────
MATTE_CSS = r"""
:root{
  --bg:#121214;--bg2:#1a1a1d;--bg3:#222226;--line:#2e2e33;
  --t1:#ececec;--t2:#a0a0a8;--t3:#6b6b74;
  --acc:#5b7cfa;--ok:#3d9a6a;--warn:#c4922a;--bad:#c45c5c;
  --r:10px;--sb:220px;--font:'Segoe UI',Tahoma,system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--t1);font-family:var(--font);font-size:13px}
a{color:var(--acc);text-decoration:none}
button,input,select{font-family:inherit}
.shell{display:flex;min-height:100vh}
.sb{width:var(--sb);background:var(--bg2);border-right:1px solid var(--line);display:flex;flex-direction:column;position:fixed;inset:0 auto 0 0;z-index:40}
.sb-brand{padding:18px 16px;border-bottom:1px solid var(--line);font-weight:700;font-size:15px;letter-spacing:.04em}
.sb-brand span{color:var(--t3);font-weight:500;font-size:11px;display:block;margin-top:3px}
.sb nav{flex:1;padding:10px 8px;overflow:auto}
.nav-btn{display:flex;align-items:center;gap:10px;width:100%;padding:10px 12px;border:none;background:transparent;color:var(--t2);border-radius:8px;cursor:pointer;font-size:13px;margin-bottom:2px;text-align:right;flex-direction:row-reverse;justify-content:flex-end}
.nav-btn:hover{background:var(--bg3);color:var(--t1)}
.nav-btn.on{background:var(--bg3);color:var(--t1);font-weight:600}
.nav-btn svg{width:16px;height:16px;flex-shrink:0;opacity:.85}
.sb-foot{padding:12px;border-top:1px solid var(--line)}
.main{margin-left:var(--sb);flex:1;padding:22px 24px 48px;min-width:0}
.page{display:none}.page.on{display:block}
.h1{font-size:17px;font-weight:700;margin-bottom:4px}
.sub{color:var(--t3);font-size:12px;margin-bottom:18px}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
@media(max-width:900px){.grid4{grid-template-columns:1fr 1fr}.sb{transform:translateX(-100%)}.main{margin-left:0}}
.card{background:var(--bg2);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;margin-bottom:12px}
.metric .l{font-size:11px;color:var(--t3);margin-bottom:6px}
.metric .v{font-size:20px;font-weight:700;letter-spacing:-.02em}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg3);color:var(--t1);cursor:pointer;font-size:12px}
.btn:hover{border-color:var(--t3)}
.btn-p{background:var(--acc);border-color:var(--acc);color:#fff}
.btn-d{color:var(--bad);border-color:rgba(196,92,92,.35)}
.btn-sm{padding:6px 8px}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 8px;text-align:right;border-bottom:1px solid var(--line);font-size:12px}
th{color:var(--t3);font-weight:600}
.field{margin-bottom:12px}
.field label{display:block;font-size:11px;color:var(--t3);margin-bottom:5px}
.field input,.field select{width:100%;padding:9px 10px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--t1);font-size:13px}
.field input:focus,.field select:focus{outline:none;border-color:var(--acc)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.ops{display:flex;gap:4px;flex-wrap:wrap}
.badge{display:inline-block;padding:2px 7px;border-radius:6px;font-size:10px;background:var(--bg3);color:var(--t2)}
.badge.on{background:rgba(61,154,106,.15);color:var(--ok)}
.badge.off{background:rgba(196,92,92,.12);color:var(--bad)}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--bg3);border:1px solid var(--line);padding:10px 16px;border-radius:8px;font-size:12px;z-index:99;opacity:0;pointer-events:none;transition:.2s}
.toast.show{opacity:1}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:80;padding:16px}
.modal-bg.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:18px;width:min(440px,100%);max-height:90vh;overflow:auto}
.modal h3{font-size:15px;margin-bottom:12px}
.adv{display:none;margin-top:8px;padding-top:8px;border-top:1px solid var(--line)}
.adv.open{display:block}
.sys-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
@media(max-width:900px){.sys-grid,.row2{grid-template-columns:1fr}}
.sys-card{background:var(--bg3);border:1px solid var(--line);border-radius:8px;padding:12px}
.sys-card .t{font-size:11px;color:var(--t3)}
.sys-card .p{font-size:18px;font-weight:700;margin:4px 0}
.bar{height:6px;background:var(--line);border-radius:99px;overflow:hidden}
.bar>i{display:block;height:100%;background:var(--acc);border-radius:99px}
.bar>i.w{background:var(--warn)}.bar>i.c{background:var(--bad)}
.muted{color:var(--t3);font-size:11px}
.switch{position:relative;width:36px;height:20px;display:inline-block}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;inset:0;background:var(--line);border-radius:20px;cursor:pointer}
.slider:before{content:"";position:absolute;width:14px;height:14px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.15s}
.switch input:checked+.slider{background:var(--ok)}
.switch input:checked+.slider:before{transform:translateX(16px)}
body{direction:rtl}
"""

def _auth_shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html lang="fa"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
{MATTE_CSS}
.auth{{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
.auth-box{{width:min(360px,100%);background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:28px 24px}}
.auth-box h1{{font-size:18px;margin-bottom:6px}}
.auth-box p{{color:var(--t3);font-size:12px;margin-bottom:18px}}
</style></head><body><div class="auth"><div class="auth-box">{body}</div></div>
<script>
async function post(url,body){{
  const r=await fetch(url,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}});
  const j=await r.json().catch(()=>({{}}));
  if(!r.ok) throw new Error(j.detail||j.error||'error');
  return j;
}}
</script></body></html>"""


DECOY_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
<meta name="description" content="Security check">
<title>Just a moment...</title>
<style>
html,body{height:100%;margin:0;padding:0}
body{
  font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,Cantarell,"Helvetica Neue",Arial,sans-serif;
  background:#f0f2f5;color:#1c1e21;
  display:flex;align-items:center;justify-content:center;
  min-height:100vh;padding:20px;
  -webkit-font-smoothing:antialiased;
}
.wrap{width:min(400px,100%)}
.box{
  background:#ffffff;
  border:1px solid #dadce0;
  border-radius:8px;
  box-shadow:0 1px 2px rgba(60,64,67,.3),0 1px 3px 1px rgba(60,64,67,.15);
  padding:32px 28px 24px;
}
.row-top{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.cf-mark{
  width:36px;height:36px;border-radius:4px;background:#f48120;
  display:flex;align-items:center;justify-content:center;flex-shrink:0;
}
.cf-mark svg{width:22px;height:22px}
h1{font-size:16px;font-weight:600;margin:0;color:#202124;line-height:1.35}
.lead{font-size:13px;color:#5f6368;line-height:1.55;margin:0 0 20px}
.widget{
  border:1px solid #d3d3d3;border-radius:3px;background:#f9f9f9;
  padding:12px 12px 12px 14px;display:flex;align-items:center;gap:14px;
  min-height:78px;user-select:none;
}
.check{
  width:28px;height:28px;border:2px solid #c1c1c1;border-radius:2px;
  background:#fff;cursor:pointer;flex-shrink:0;
  display:flex;align-items:center;justify-content:center;position:relative;
}
.check.spin::before{
  content:"";width:16px;height:16px;border-radius:50%;
  border:2px solid #1a73e8;border-top-color:transparent;
  animation:r .65s linear infinite;
}
.check.done{background:#1a73e8;border-color:#1a73e8}
.check.done svg{display:block}
.check svg{display:none;width:16px;height:16px}
@keyframes r{to{transform:rotate(360deg)}}
.label{font-size:14px;color:#202124;flex:1}
.rc{
  text-align:right;line-height:1.2;margin-left:auto;flex-shrink:0;
}
.rc b{display:block;font-size:10px;color:#555;letter-spacing:.02em}
.rc i{display:block;font-size:9px;color:#9aa0a6;font-style:normal;margin-top:2px}
.meta{margin-top:18px;font-size:11px;color:#9aa0a6;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
.meta a{color:#9aa0a6;text-decoration:none;pointer-events:none}
.msg{margin-top:14px;font-size:12px;color:#5f6368;min-height:18px}
.msg.err{color:#d93025}
.footer{
  margin-top:14px;text-align:center;font-size:11px;color:#9aa0a6;
}
</style>
</head>
<body>
<div class="wrap">
  <div class="box">
    <div class="row-top">
      <div class="cf-mark" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="#fff"><path d="M16.5 12.5c0-.3-.1-.5-.3-.7l-3.2-3.2c-.4-.4-1-.4-1.4 0-.4.4-.4 1 0 1.4L13.6 12l-2 2c-.4.4-.4 1 0 1.4.4.4 1 .4 1.4 0l3.2-3.2c.2-.2.3-.4.3-.7z"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zm0 18c-4.4 0-8-3.6-8-8s3.6-8 8-8 8 3.6 8 8-3.6 8-8 8z"/></svg>
      </div>
      <h1>Checking if the site connection is secure</h1>
    </div>
    <p class="lead">This website uses a security service to protect against malicious bots. Please complete the challenge below to continue.</p>
    <div class="widget">
      <div class="check" id="ck" role="checkbox" aria-checked="false" tabindex="0" title="Verify"></div>
      <div class="label" id="lb">I&apos;m not a robot</div>
      <div class="rc"><b>reCAPTCHA</b><i>Privacy · Terms</i></div>
    </div>
    <div class="msg" id="msg">Enable JavaScript and cookies to continue</div>
    <div class="meta">
      <span>Ray ID: <span id="ray">—</span></span>
      <span><a href="#">Privacy</a> · <a href="#">Terms</a></span>
    </div>
  </div>
  <div class="footer">Performance &amp; security by Cloudflare</div>
</div>
<script>
(function () {
  function ray() {
    try {
      var a = new Uint8Array(8);
      crypto.getRandomValues(a);
      return Array.prototype.map.call(a, function (b) {
        return ("0" + b.toString(16)).slice(-2);
      }).join("");
    } catch (e) {
      return String(Date.now().toString(16)) + Math.random().toString(16).slice(2, 10);
    }
  }
  document.getElementById("ray").textContent = ray();
  var ck = document.getElementById("ck");
  var lb = document.getElementById("lb");
  var msg = document.getElementById("msg");
  var busy = false;
  msg.textContent = "Checking your browser before accessing this site.";
  setTimeout(function () {
    if (!busy) msg.textContent = "Waiting for verification…";
  }, 1400);
  function go() {
    if (busy) return;
    busy = true;
    ck.classList.add("spin");
    lb.textContent = "Verifying…";
    msg.className = "msg";
    msg.textContent = "Verifying you are human. This may take a few seconds.";
    setTimeout(function () {
      ck.classList.remove("spin");
      ck.classList.add("done");
      ck.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3"><path d="M5 13l4 4L19 7"/></svg>';
      lb.textContent = "I\'m not a robot";
      msg.className = "msg err";
      msg.textContent = "Verification failed. Please try again later.";
      busy = false;
      setTimeout(function () {
        ck.classList.remove("done");
        ck.innerHTML = "";
        msg.className = "msg";
        msg.textContent = "Waiting for verification…";
      }, 4500);
    }, 1600 + Math.floor(Math.random() * 1400));
  }
  ck.addEventListener("click", go);
  ck.addEventListener("keydown", function (e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      go();
    }
  });
})();
</script>
</body>
</html>
"""

SETUP_HTML = _auth_shell("PX · Setup", """
<h1>راه‌اندازی PX</h1>
<p>یک‌بار رمز عبور مدیریت را تنظیم کنید. این صفحه بعداً غیرفعال می‌شود.</p>
<div class="field"><label>رمز عبور (حداقل ۸ کاراکتر)</label><input type="password" id="pw" autocomplete="new-password"></div>
<div class="field"><label>تکرار رمز</label><input type="password" id="pw2" autocomplete="new-password"></div>
<button class="btn btn-p" style="width:100%" onclick="go()">ذخیره و ورود</button>
<p id="err" class="muted" style="margin-top:10px;color:var(--bad)"></p>
<script>
async function go(){
  try{
    await post('/api/setup',{password:pw.value,password2:pw2.value});
    location.href='/dashboard';
  }catch(e){err.textContent=e.message}
}
</script>
""")

LOGIN_HTML = _auth_shell("PX · Access", """
<h1>PX Panel</h1>
<p>ورود امن مدیریت</p>
<div class="field"><label>رمز عبور</label><input type="password" id="pw" autocomplete="current-password" autofocus></div>
<button class="btn btn-p" style="width:100%" onclick="go()">ورود</button>
<p id="err" class="muted" style="margin-top:10px;color:var(--bad)"></p>
<script>
async function go(){
  try{
    await post('/api/pxpanelworking',{password:pw.value});
    location.href='/dashboard';
  }catch(e){err.textContent=e.message}
}
pw.addEventListener('keydown',e=>{if(e.key==='Enter')go()});
</script>
""")

DASH_HTML = f"""<!DOCTYPE html>
<html lang="fa">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PX Panel</title>
<style>{MATTE_CSS}</style>
</head>
<body>
<div class="shell">
<aside class="sb">
  <div class="sb-brand">PX<span>v{APP_VERSION}</span></div>
  <nav>
    <button class="nav-btn on" data-p="dash" onclick="go('dash')">داشبورد
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg></button>
    <button class="nav-btn" data-p="configs" onclick="go('configs')">کانفیگ‌ها
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></button>
    <button class="nav-btn" data-p="create" onclick="go('create')">ساخت
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg></button>
    <button class="nav-btn" data-p="folders" onclick="go('folders')">پوشه‌ها
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/></svg></button>
    <button class="nav-btn" data-p="logs" onclick="go('logs')">لاگ
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg></button>
  </nav>
  <div class="sb-foot">
    <button class="btn" style="width:100%" onclick="logout()">خروج</button>
  </div>
</aside>
<main class="main">
  <section class="page on" id="p-dash">
    <div class="h1">داشبورد</div>
    <div class="sub">آمار لحظه‌ای سرویس و منابع</div>
    <div class="grid4">
      <div class="card metric"><div class="l">اتصالات فعال</div><div class="v" id="mConns">—</div></div>
      <div class="card metric"><div class="l">ترافیک کل</div><div class="v" id="mTraffic">—</div></div>
      <div class="card metric"><div class="l">کانفیگ‌ها</div><div class="v" id="mLinks">—</div></div>
      <div class="card metric"><div class="l">آپتایم</div><div class="v" id="mUp" style="font-size:16px">—</div></div>
    </div>
    <div class="card">
      <div class="h1" style="font-size:13px;margin-bottom:10px">منابع سیستم</div>
      <div class="sys-grid">
        <div class="sys-card"><div class="t">CPU</div><div class="p" id="sCpu">—</div><div class="bar"><i id="bCpu"></i></div></div>
        <div class="sys-card"><div class="t">RAM</div><div class="p" id="sRam">—</div><div class="bar"><i id="bRam"></i></div></div>
        <div class="sys-card"><div class="t">DISK</div><div class="p" id="sDisk">—</div><div class="bar"><i id="bDisk"></i></div></div>
        <div class="sys-card"><div class="t">NET</div><div class="p" id="sNet">—</div><div class="muted" id="sNetM">—</div></div>
      </div>
    </div>
  </section>

  <section class="page" id="p-configs">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px">
      <div><div class="h1">کانفیگ‌ها</div><div class="sub" style="margin:0">مدیریت لینک‌ها و محدودیت‌ها</div></div>
      <button class="btn btn-p" onclick="go('create')">ساخت جدید</button>
    </div>
    <div class="card" style="overflow:auto">
      <table>
        <thead><tr><th>نام</th><th>پروتکل</th><th>وضعیت</th><th>مصرف</th><th>IP/User</th><th>پوشه</th><th></th></tr></thead>
        <tbody id="tb"></tbody>
      </table>
    </div>
  </section>

  <section class="page" id="p-create">
    <div class="h1">ساخت کانفیگ</div>
    <div class="sub">VLESS WS پیش‌فرض · XHTTP در پیشرفته</div>
    <div class="card" style="max-width:520px">
      <div class="field"><label>نام</label><input id="cName" placeholder="auto"></div>
      <div class="row2">
        <div class="field"><label>تعداد در ساب</label><input id="cCount" type="number" value="1" min="1" max="40"></div>
        <div class="field"><label>انقضا (روز)</label><input id="cDays" type="number" value="0" min="0"></div>
      </div>
      <div class="row2">
        <div class="field"><label>حجم (GB) · 0=∞</label><input id="cLimit" type="number" value="0" min="0"></div>
        <div class="field"><label>سرعت (Mbps) · 0=∞</label><input id="cSpeed" type="number" value="0" min="0"></div>
      </div>
      <div class="row2">
        <div class="field"><label>محدودیت IP</label><input id="cIp" type="number" value="0" min="0"></div>
        <div class="field"><label>محدودیت کاربر</label><input id="cConn" type="number" value="0" min="0"></div>
      </div>
      <div class="field"><label>پوشه</label><select id="cFolder"></select></div>
      <button type="button" class="btn" onclick="document.getElementById('adv').classList.toggle('open')">تنظیمات پیشرفته</button>
      <div class="adv" id="adv">
        <div class="field"><label>پروتکل</label>
          <select id="cProto"><option value="vless-ws">VLESS WS (پایدار Railway)</option><option value="xhttp-stream-up">XHTTP Fast</option></select>
        </div>
        <div class="field"><label>یادداشت</label><input id="cNote"></div>
      </div>
      <button class="btn btn-p" style="width:100%;margin-top:12px" onclick="createLink()">ساخت</button>
      <div id="created" class="muted" style="margin-top:12px;word-break:break-all"></div>
    </div>
  </section>

  <section class="page" id="p-folders">
    <div class="h1">پوشه‌ها</div>
    <div class="sub">دسته‌بندی کانفیگ‌ها برای تیم فروش</div>
    <div class="card" style="max-width:420px">
      <div class="field"><label>نام پوشه جدید</label><input id="fName"></div>
      <button class="btn btn-p" onclick="addFolder()">افزودن</button>
    </div>
    <div class="card"><div id="fList"></div></div>
  </section>

  <section class="page" id="p-logs">
    <div class="h1">لاگ فعالیت</div>
    <div class="sub">آخرین رویدادها</div>
    <div class="card" id="logBox" class="muted">—</div>
  </section>
</main>
</div>
<div class="toast" id="toast"></div>
<div class="modal-bg" id="editBg">
  <div class="modal">
    <h3>ویرایش کانفیگ</h3>
    <input type="hidden" id="eId">
    <div class="field"><label>نام</label><input id="eName"></div>
    <div class="row2">
      <div class="field"><label>حجم (GB)</label><input id="eLimit" type="number" min="0"></div>
      <div class="field"><label>سرعت Mbps</label><input id="eSpeed" type="number" min="0"></div>
    </div>
    <div class="row2">
      <div class="field"><label>IP limit</label><input id="eIp" type="number" min="0"></div>
      <div class="field"><label>User limit</label><input id="eConn" type="number" min="0"></div>
    </div>
    <div class="field"><label>پوشه</label><select id="eFolder"></select></div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px">
      <button class="btn" onclick="closeEdit()">انصراف</button>
      <button class="btn btn-p" onclick="saveEdit()">ذخیره</button>
    </div>
  </div>
</div>
<script>
const $ = id => document.getElementById(id);
let folders={{}};
function toast(m){{const t=$('toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2200)}}
function fmtB(n){{n=Number(n)||0;const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){{n/=1024;i++}}return(i?n.toFixed(1):n)+' '+u[i]}}
function fmtUp(s){{s=Number(s)||0;const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return h+'س '+m+'د'}}
async function api(url,opt){{
  const r=await fetch(url,opt);
  if(r.status===401){{location.href='/pxpanelworking';return null}}
  const j=await r.json().catch(()=>({{}}));
  if(!r.ok){{toast(j.detail||j.error||'خطا');return null}}
  return j;
}}
function go(name){{
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.toggle('on',b.dataset.p===name));
  $('p-'+name).classList.add('on');
  if(name==='configs')loadLinks();
  if(name==='folders')loadFolders();
  if(name==='logs')loadLogs();
  if(name==='create')fillFolders('cFolder');
}}
async function logout(){{await api('/api/logout',{{method:'POST'}});location.href='/pxpanelworking'}}
function setBar(id,pct){{
  const el=$(id);if(!el)return;const p=Math.max(0,Math.min(100,pct||0));
  el.style.width=p+'%';el.className='';if(p>=90)el.className='c';else if(p>=70)el.className='w';
}}
async function refresh(){{
  const s=await api('/api/stats');
  if(s){{
    $('mConns').textContent=s.connections;
    $('mTraffic').textContent=fmtB(s.traffic);
    $('mLinks').textContent=s.active_links+' / '+s.links;
    $('mUp').textContent=fmtUp(s.uptime);
  }}
  const sys=await api('/api/system');
  if(sys&&sys.ok!==false){{
    const c=sys.cpu||{{}},r=sys.ram||{{}},d=sys.disk||{{}},n=sys.net||{{}};
    $('sCpu').textContent=(c.percent??0).toFixed(1)+'%';
    $('sRam').textContent=(r.percent??0).toFixed(1)+'%';
    $('sDisk').textContent=(d.percent??0).toFixed(1)+'%';
    $('sNet').textContent=((n.down_mbps||0).toFixed(2))+' ↓';
    $('sNetM').textContent='↑ '+(n.up_mbps||0).toFixed(2)+' Mbps';
    setBar('bCpu',c.percent);setBar('bRam',r.percent);setBar('bDisk',d.percent);
  }}
}}
async function loadFolders(){{
  const r=await api('/api/folders');if(!r)return;
  folders={{}};
  (r.folders||[]).forEach(f=>folders[f.id]=f.name);
  fillFolders('cFolder');fillFolders('eFolder');
  $('fList').innerHTML=(r.folders||[]).map(f=>`<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line)">
    <span>${{f.name}}</span>${{f.id==='0'?'':`<button class="btn btn-sm btn-d" onclick="delFolder('${{f.id}}')">حذف</button>`}}</div>`).join('')||'—';
}}
function fillFolders(selId){{
  const s=$(selId);if(!s)return;
  s.innerHTML=Object.entries(folders).map(([id,n])=>`<option value="${{id}}">${{n}}</option>`).join('')||'<option value="0">پیش‌فرض</option>';
}}
async function addFolder(){{
  const name=$('fName').value.trim();if(!name)return;
  const r=await api('/api/folders',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{name}})}});
  if(r){{$('fName').value='';toast('افزوده شد');loadFolders()}}
}}
async function delFolder(id){{
  if(!confirm('حذف پوشه؟'))return;
  const r=await api('/api/folders/'+id,{{method:'DELETE'}});if(r){{toast('حذف شد');loadFolders()}}
}}
async function loadLinks(){{
  await loadFolders();
  const r=await api('/api/links');if(!r)return;
  const rows=r.links||[];
  if(!rows.length){{$('tb').innerHTML='<tr><td colspan="7" class="muted" style="text-align:center;padding:24px">کانفیگی نیست</td></tr>';return}}
  $('tb').innerHTML=rows.map(l=>{{
    const on=l.active&&!l.expired;
    return `<tr>
      <td><b>${{esc(l.label)}}</b></td>
      <td><span class="badge">${{esc(l.protocol)}}</span></td>
      <td><span class="badge ${{on?'on':'off'}}">${{on?'فعال':'خاموش'}}</span>
        <label class="switch" style="margin-right:6px;vertical-align:middle"><input type="checkbox" ${{on?'checked':''}} onchange="tog('${{l.uuid}}',this.checked)"><span class="slider"></span></label>
      </td>
      <td>${{fmtB(l.used_bytes)}}${{l.limit_bytes?' / '+fmtB(l.limit_bytes):''}}</td>
      <td>${{l.ip_limit||'∞'}} / ${{l.connection_limit||'∞'}}</td>
      <td class="muted">${{esc(folders[l.folder_id]||'—')}}</td>
      <td class="ops">
        <button class="btn btn-sm" title="ویرایش" onclick='edit(${{JSON.stringify(l)}})'><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg></button>
        <button class="btn btn-sm" title="کپی" onclick="copyTxt(${{JSON.stringify(l.vless)}})"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
        <button class="btn btn-sm" title="ساب" onclick="copyTxt(${{JSON.stringify(l.sub_url)}})"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg></button>
        <button class="btn btn-sm btn-d" onclick="delLink('${{l.uuid}}')"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg></button>
      </td>
    </tr>`;
  }}).join('');
}}
function esc(s){{return String(s??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c])}}
function copyTxt(t){{navigator.clipboard.writeText(t);toast('کپی شد')}}
async function tog(id,on){{await api('/api/links/'+id,{{method:'PATCH',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{active:on}})}});loadLinks()}}
async function delLink(id){{if(!confirm('حذف؟'))return;await api('/api/links/'+id,{{method:'DELETE'}});loadLinks()}}
function edit(l){{
  $('eId').value=l.uuid;$('eName').value=l.label||'';
  $('eLimit').value=l.limit_bytes? (l.limit_bytes/1073741824).toFixed(3):0;
  $('eSpeed').value=l.speed_limit_bytes? ((l.speed_limit_bytes*8)/1e6).toFixed(2):0;
  $('eIp').value=l.ip_limit||0;$('eConn').value=l.connection_limit||0;
  fillFolders('eFolder');$('eFolder').value=l.folder_id||'0';
  $('editBg').classList.add('open');
}}
function closeEdit(){{$('editBg').classList.remove('open')}}
async function saveEdit(){{
  const id=$('eId').value;
  const body={{
    label:$('eName').value,limit_value:Number($('eLimit').value)||0,limit_unit:'GB',
    speed_limit_value:Number($('eSpeed').value)||0,
    ip_limit:Number($('eIp').value)||0,connection_limit:Number($('eConn').value)||0,
    folder_id:$('eFolder').value
  }};
  const r=await api('/api/links/'+id,{{method:'PATCH',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}});
  if(r){{toast('ذخیره شد');closeEdit();loadLinks()}}
}}
async function createLink(){{
  const body={{
    label:$('cName').value||undefined,
    config_count:Math.max(1,Math.min(40,Number($('cCount').value)||1)),
    expires_days:Number($('cDays').value)||0,
    limit_value:Number($('cLimit').value)||0,limit_unit:'GB',
    speed_limit_value:Number($('cSpeed').value)||0,
    ip_limit:Number($('cIp').value)||0,connection_limit:Number($('cConn').value)||0,
    folder_id:$('cFolder').value||'0',
    protocol:$('cProto').value||'vless-ws',
    note:$('cNote').value||''
  }};
  const r=await api('/api/links',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}});
  if(r){{
    toast('ساخته شد');
    $('created').innerHTML=`<div style="margin-top:8px"><b>VLESS</b><br><code style="font-size:11px">${{esc(r.vless)}}</code><br><br><b>SUB</b><br><code style="font-size:11px">${{esc(r.sub_url)}}</code>
    <div style="margin-top:8px"><button class="btn btn-sm" onclick="copyTxt(${{JSON.stringify(r.vless)}})">کپی VLESS</button>
    <button class="btn btn-sm" onclick="copyTxt(${{JSON.stringify(r.sub_url)}})">کپی ساب</button></div></div>`;
  }}
}}
async function loadLogs(){{
  const r=await api('/api/activity');if(!r)return;
  const logs=r.logs||[];
  $('logBox').innerHTML=logs.length?logs.map(x=>`<div style="padding:6px 0;border-bottom:1px solid var(--line)"><span class="muted">${{esc(x.time||'')}}</span> · ${{esc(x.msg||'')}}</div>`).join(''):'لاگی نیست';
}}
loadFolders();refresh();setInterval(refresh,2000);
</script>
</body></html>
"""

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, proxy_headers=True, forwarded_allow_ips="*",
                timeout_keep_alive=75, ws_ping_interval=20, ws_ping_timeout=30, workers=1, log_level="info")
