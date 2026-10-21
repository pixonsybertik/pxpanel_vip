# relay_vless.py — high-throughput VLESS WebSocket relay (Railway)
# Goals: stable long sessions + max upload/download speed

from __future__ import annotations

import asyncio
import secrets
import socket
import time
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    is_ip_allowed,
    save_state,
    log_activity,
    now_ir,
)
from speed_limit import throttle

# Large buffers → fewer syscalls, better throughput behind Railway edge
RELAY_BUF = 512 * 1024
WRITE_DRAIN_THRESHOLD = 1024 * 1024
TCP_CONNECT_TIMEOUT = 20.0
FIRST_MSG_TIMEOUT = 45.0
# Quota accounting batched (avoid lock on every packet)
QUOTA_FLUSH_BYTES = 64 * 1024
QUOTA_FLUSH_SEC = 0.35


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return ws.client.host if ws.client else "0.0.0.0"


async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1
    pos += 16
    addon_len = chunk[pos]
    pos += 1 + addon_len
    command = chunk[pos]
    pos += 1
    port = int.from_bytes(chunk[pos : pos + 2], "big")
    pos += 2
    addr_type = chunk[pos]
    pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos : pos + 4])
        pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]
        pos += 1
        address = chunk[pos : pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif addr_type == 3:
        ab = chunk[pos : pos + 16]
        pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i + 1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]


class Quota:
    """Batch traffic accounting to avoid locking on every packet."""

    __slots__ = ("uid", "pending", "last_flush", "ok")

    def __init__(self, uid: str):
        self.uid = uid
        self.pending = 0
        self.last_flush = time.monotonic()
        self.ok = True

    async def add(self, n: int) -> bool:
        if not self.ok or n <= 0:
            return self.ok
        self.pending += n
        now = time.monotonic()
        if self.pending >= QUOTA_FLUSH_BYTES or (now - self.last_flush) >= QUOTA_FLUSH_SEC:
            return await self.flush()
        return True

    async def flush(self) -> bool:
        n = self.pending
        self.pending = 0
        self.last_flush = time.monotonic()
        if n <= 0:
            return self.ok
        async with LINKS_LOCK:
            link = LINKS.get(self.uid)
            if link is None or not is_link_allowed(link):
                self.ok = False
                return False
            link["used_bytes"] = int(link.get("used_bytes") or 0) + n
            stats["total_bytes"] = int(stats.get("total_bytes") or 0) + n
            try:
                key = now_ir().strftime("%H:00")
                hourly_traffic[key] = int(hourly_traffic.get(key, 0)) + n
            except Exception:
                pass
            lim = int(link.get("limit_bytes") or 0)
            used = int(link.get("used_bytes") or 0)
            if lim > 0 and used >= lim:
                self.ok = False
                return False
        return True


async def check_and_use(uid: str, n: int) -> bool:
    """Compatibility helper for xhttp module."""
    q = Quota(uid)
    q.pending = n
    return await q.flush()


def _tune_socket(writer: asyncio.StreamWriter) -> None:
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass
    for opt, val in (
        ("TCP_KEEPIDLE", 45),
        ("TCP_KEEPINTVL", 15),
        ("TCP_KEEPCNT", 6),
    ):
        try:
            const = getattr(socket, opt, None)
            if const is not None:
                sock.setsockopt(socket.IPPROTO_TCP, const, val)
        except Exception:
            pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
    except Exception:
        pass


async def relay_ws_to_tcp(
    ws: WebSocket,
    writer: asyncio.StreamWriter,
    conn_id: str,
    quota: Quota,
):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes")
            if data is None:
                text = msg.get("text")
                if text is None:
                    continue
                data = text.encode("utf-8", errors="ignore")
            if not data:
                continue
            if not await quota.add(len(data)):
                try:
                    await ws.close(code=1008, reason="quota")
                except Exception:
                    pass
                break
            await throttle(quota.uid, len(data))
            if conn_id in connections:
                connections[conn_id]["bytes"] = int(connections[conn_id].get("bytes") or 0) + len(data)
            writer.write(data)
            # drain only when buffer is large — critical for upload speed
            if writer.transport.get_write_buffer_size() >= WRITE_DRAIN_THRESHOLD:
                await writer.drain()
        try:
            await writer.drain()
        except Exception:
            pass
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception:
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass
        await quota.flush()


async def relay_tcp_to_ws(
    ws: WebSocket,
    reader: asyncio.StreamReader,
    conn_id: str,
    quota: Quota,
):
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await quota.add(len(data)):
                try:
                    await ws.close(code=1008, reason="quota")
                except Exception:
                    pass
                break
            await throttle(quota.uid, len(data))
            if conn_id in connections:
                connections[conn_id]["bytes"] = int(connections[conn_id].get("bytes") or 0) + len(data)
            await ws.send_bytes(data)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception:
        pass
    finally:
        await quota.flush()


async def websocket_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning("🚫 WS rejected uuid=%s… (not allowed)", uuid[:8])
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)

    if not is_ip_allowed(link, uuid, ip):
        logger.warning("🚫 WS rejected uuid=%s… ip=%s", uuid[:8], ip)
        log_activity("connection", f"اتصال {ip} رد شد (IP limit)", "warn")
        await ws.close(code=1008, reason="ip limit reached")
        return

    conn_limit = int((link or {}).get("connection_limit") or 0)
    if conn_limit > 0:
        cur = sum(1 for c in connections.values() if c.get("uuid") == uuid)
        if cur >= conn_limit:
            await ws.close(code=1008, reason="connection limit")
            return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info("✅ WS [%s] uuid=%s… ip=%s", conn_id, uuid[:8], ip)
    log_activity("connection", f"اتصال از {ip}", "info")
    writer = None
    quota = Quota(uuid)

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=FIRST_MSG_TIMEOUT)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        command, address, port, payload = await parse_vless_header(first_chunk)

        if command != 1:
            # TCP only — UDP unstable on Railway edge
            try:
                await ws.send_bytes(b"\x00\x00")
            except Exception:
                pass
            await ws.close(code=1008, reason="tcp only")
            return

        if not await quota.add(len(first_chunk)):
            await ws.close(code=1008, reason="quota")
            return

        stats["total_requests"] = int(stats.get("total_requests") or 0) + 1
        connections[conn_id]["bytes"] = len(first_chunk)
        logger.info("➡️  [%s] → %s:%s", conn_id, address, port)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port),
            timeout=TCP_CONNECT_TIMEOUT,
        )
        _tune_socket(writer)

        # Immediate VLESS OK so client can stream (ping + real traffic)
        await ws.send_bytes(b"\x00\x00")

        if payload:
            writer.write(payload)
            await writer.drain()

        t_up = asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, quota))
        t_down = asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, quota))

        # Wait until BOTH sides finish — prevents mid-session drop when one
        # direction briefly idles (common cause of "می‌پره و برمی‌گرده")
        done, pending = await asyncio.wait(
            {t_up, t_down},
            return_when=asyncio.FIRST_COMPLETED,
        )
        # Give the other direction time to flush remaining data
        if pending:
            try:
                await asyncio.wait(pending, timeout=8.0)
            except Exception:
                pass
            for t in pending:
                if not t.done():
                    t.cancel()
                    try:
                        await t
                    except Exception:
                        pass

        await quota.flush()
        try:
            asyncio.create_task(save_state())
        except Exception:
            pass

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] = int(stats.get("total_errors") or 0) + 1
        error_logs.append({"error": "timeout", "time": datetime.now().isoformat()})
        logger.warning("WS timeout [%s]", conn_id)
    except Exception as exc:
        stats["total_errors"] = int(stats.get("total_errors") or 0) + 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error("WS error [%s]: %s", conn_id, exc)
    finally:
        await quota.flush()
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
