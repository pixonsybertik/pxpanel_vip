# system.py — Live system metrics for PXPanel (Railway / Linux)
# CPU · RAM · Disk · Network bandwidth with history for charts

from __future__ import annotations

import os
import time
from collections import deque
from pathlib import Path
from typing import Any

# Optional high-quality metrics
try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except Exception:
    psutil = None  # type: ignore
    _HAS_PSUTIL = False

HISTORY_LEN = 60  # ~60 samples for line chart
_history: dict[str, deque] = {
    "ts": deque(maxlen=HISTORY_LEN),
    "cpu": deque(maxlen=HISTORY_LEN),
    "ram": deque(maxlen=HISTORY_LEN),
    "disk": deque(maxlen=HISTORY_LEN),
    "net_up_mbps": deque(maxlen=HISTORY_LEN),
    "net_down_mbps": deque(maxlen=HISTORY_LEN),
}

_last_net: dict[str, float] | None = None
_last_net_ts: float | None = None
_boot_ts: float = time.time()


def _read_proc_cpu() -> float:
    """CPU percent from /proc/stat (delta needs two reads — use cached)."""
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline()
        parts = line.split()
        if parts[0] != "cpu":
            return 0.0
        nums = [float(x) for x in parts[1:8]]
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
        total = sum(nums)
        prev = getattr(_read_proc_cpu, "_prev", None)
        _read_proc_cpu._prev = (idle, total)  # type: ignore
        if not prev:
            return 0.0
        d_idle = idle - prev[0]
        d_total = total - prev[1]
        if d_total <= 0:
            return 0.0
        return max(0.0, min(100.0, (1.0 - d_idle / d_total) * 100.0))
    except Exception:
        return 0.0


def _read_mem() -> tuple[float, int, int]:
    """Return (percent, used_bytes, total_bytes)."""
    if _HAS_PSUTIL:
        try:
            m = psutil.virtual_memory()
            return float(m.percent), int(m.used), int(m.total)
        except Exception:
            pass
    try:
        info: dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                info[k.strip()] = int(v.strip().split()[0]) * 1024  # kB → bytes
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        used = max(0, total - avail)
        pct = (used / total * 100.0) if total else 0.0
        return pct, used, total
    except Exception:
        return 0.0, 0, 0


def _read_disk(path: str | None = None) -> tuple[float, int, int]:
    path = path or os.environ.get("DATA_DIR") or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH") or "/"
    try:
        path = str(Path(path).resolve())
    except Exception:
        path = "/"
    if _HAS_PSUTIL:
        try:
            d = psutil.disk_usage(path)
            return float(d.percent), int(d.used), int(d.total)
        except Exception:
            try:
                d = psutil.disk_usage("/")
                return float(d.percent), int(d.used), int(d.total)
            except Exception:
                pass
    try:
        st = os.statvfs(path)
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bavail
        used = total - free
        pct = (used / total * 100.0) if total else 0.0
        return pct, int(used), int(total)
    except Exception:
        return 0.0, 0, 0


def _read_net_counters() -> tuple[int, int]:
    """(bytes_recv, bytes_sent) across all non-loopback ifaces."""
    if _HAS_PSUTIL:
        try:
            n = psutil.net_io_counters(pernic=False)
            return int(n.bytes_recv), int(n.bytes_sent)
        except Exception:
            pass
    recv = sent = 0
    try:
        with open("/proc/net/dev", "r", encoding="utf-8") as f:
            lines = f.readlines()[2:]
        for line in lines:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            name = name.strip()
            if name == "lo":
                continue
            cols = rest.split()
            if len(cols) < 9:
                continue
            recv += int(cols[0])
            sent += int(cols[8])
    except Exception:
        pass
    return recv, sent


def _cpu_percent() -> float:
    if _HAS_PSUTIL:
        try:
            return float(psutil.cpu_percent(interval=None))
        except Exception:
            pass
    return _read_proc_cpu()


def _loadavg() -> list[float]:
    try:
        return [round(x, 2) for x in os.getloadavg()]
    except Exception:
        return [0.0, 0.0, 0.0]


def _uptime_sec() -> float:
    if _HAS_PSUTIL:
        try:
            return max(0.0, time.time() - float(psutil.boot_time()))
        except Exception:
            pass
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            return float(f.read().split()[0])
    except Exception:
        return max(0.0, time.time() - _boot_ts)


def _fmt_bytes(n: int) -> str:
    n = float(max(0, n))
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def sample() -> dict[str, Any]:
    """Take one sample, update history, return full snapshot."""
    global _last_net, _last_net_ts

    cpu = round(_cpu_percent(), 1)
    ram_pct, ram_used, ram_total = _read_mem()
    disk_pct, disk_used, disk_total = _read_disk()
    recv, sent = _read_net_counters()
    now = time.time()

    up_mbps = down_mbps = 0.0
    if _last_net is not None and _last_net_ts is not None:
        dt = max(0.05, now - _last_net_ts)
        down_mbps = max(0.0, (recv - _last_net["recv"]) * 8 / dt / 1_000_000)
        up_mbps = max(0.0, (sent - _last_net["sent"]) * 8 / dt / 1_000_000)
    _last_net = {"recv": float(recv), "sent": float(sent)}
    _last_net_ts = now

    ram_pct = round(ram_pct, 1)
    disk_pct = round(disk_pct, 1)
    up_mbps = round(up_mbps, 2)
    down_mbps = round(down_mbps, 2)

    _history["ts"].append(now)
    _history["cpu"].append(cpu)
    _history["ram"].append(ram_pct)
    _history["disk"].append(disk_pct)
    _history["net_up_mbps"].append(up_mbps)
    _history["net_down_mbps"].append(down_mbps)

    cores = 1
    if _HAS_PSUTIL:
        try:
            cores = int(psutil.cpu_count() or 1)
        except Exception:
            cores = 1
    else:
        try:
            cores = max(1, len(open("/proc/cpuinfo").read().split("processor")) - 1)
        except Exception:
            cores = 1

    return {
        "ok": True,
        "ts": now,
        "cpu": {
            "percent": cpu,
            "cores": cores,
            "loadavg": _loadavg(),
        },
        "ram": {
            "percent": ram_pct,
            "used": ram_used,
            "total": ram_total,
            "used_h": _fmt_bytes(ram_used),
            "total_h": _fmt_bytes(ram_total),
        },
        "disk": {
            "percent": disk_pct,
            "used": disk_used,
            "total": disk_total,
            "used_h": _fmt_bytes(disk_used),
            "total_h": _fmt_bytes(disk_total),
            "path": os.environ.get("DATA_DIR")
            or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH")
            or "/",
        },
        "net": {
            "up_mbps": up_mbps,
            "down_mbps": down_mbps,
            "rx_bytes": recv,
            "tx_bytes": sent,
            "rx_h": _fmt_bytes(recv),
            "tx_h": _fmt_bytes(sent),
        },
        "uptime_sec": round(_uptime_sec(), 0),
        "backend": "psutil" if _HAS_PSUTIL else "procfs",
        "history": {
            "cpu": list(_history["cpu"]),
            "ram": list(_history["ram"]),
            "disk": list(_history["disk"]),
            "net_up_mbps": list(_history["net_up_mbps"]),
            "net_down_mbps": list(_history["net_down_mbps"]),
        },
    }


def get_snapshot() -> dict[str, Any]:
    # first call may return 0 CPU with procfs — sample twice
    if len(_history["cpu"]) < 2:
        sample()
    return sample()
