#!/usr/bin/env python3
"""Collect raw Pi resource/interface samples without producing summaries."""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


STOP = False


def stop(*_: object) -> None:
    global STOP
    STOP = True


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def cpu_totals() -> tuple[int, int]:
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    values = [int(value) for value in fields]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def memory() -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, raw = line.split(":", 1)
        values[key] = int(raw.strip().split()[0])
    available = values["MemAvailable"]
    return values["MemTotal"] - available, available


def netdev(interface: str) -> list[int]:
    for line in Path("/proc/net/dev").read_text().splitlines():
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        if name.strip() == interface:
            values = [int(item) for item in raw.split()]
            return [
                values[1], values[0], values[3], values[2],
                values[9], values[8], values[11], values[10],
            ]
    raise ValueError(f"interface not present in /proc/net/dev: {interface}")


def temperature() -> str:
    raw = read_text(Path("/sys/class/thermal/thermal_zone0/temp"))
    if raw is None:
        return ""
    try:
        return f"{int(raw) / 1000.0:.3f}"
    except ValueError:
        return ""


def frequency() -> str:
    raw = read_text(Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"))
    return raw or ""


def throttled() -> str:
    if shutil.which("vcgencmd"):
        process = subprocess.run(
            ["vcgencmd", "get_throttled"],
            text=True,
            capture_output=True,
            check=False,
        )
        return (process.stdout or process.stderr).strip()
    return ""


def rss_kb(pid: int | None) -> str:
    if not pid:
        return ""
    status = read_text(Path(f"/proc/{pid}/status"))
    if not status:
        return ""
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return line.split()[1]
    return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interval-s", type=float, required=True)
    parser.add_argument("--controller-pid", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.run_id.startswith("RECON_"):
        raise ValueError("run ID must begin with RECON_")
    if args.interval_s <= 0:
        raise ValueError("interval must be positive")
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    previous_total, previous_idle = cpu_totals()
    index = 0
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "run_id", "sample_index", "realtime_iso", "mono_ns",
                "cpu_percent", "load_1m", "memory_used_kb",
                "memory_available_kb", "temperature_c", "cpu_frequency_khz",
                "throttled_flags", "rx_packets", "rx_bytes", "rx_dropped",
                "rx_errors", "tx_packets", "tx_bytes", "tx_dropped",
                "tx_errors", "controller_rss_kb",
            ]
        )
        deadline = time.monotonic()
        while not STOP:
            deadline += args.interval_s
            now_total, now_idle = cpu_totals()
            total_delta = now_total - previous_total
            idle_delta = now_idle - previous_idle
            cpu = 100.0 * (total_delta - idle_delta) / total_delta if total_delta else 0.0
            previous_total, previous_idle = now_total, now_idle
            used, available = memory()
            rx_packets, rx_bytes, rx_dropped, rx_errors, tx_packets, tx_bytes, tx_dropped, tx_errors = netdev(args.interface)
            writer.writerow(
                [
                    args.run_id,
                    index,
                    datetime.now(timezone.utc).isoformat(),
                    time.monotonic_ns(),
                    f"{cpu:.6f}",
                    f"{os.getloadavg()[0]:.6f}",
                    used,
                    available,
                    temperature(),
                    frequency(),
                    throttled(),
                    rx_packets,
                    rx_bytes,
                    rx_dropped,
                    rx_errors,
                    tx_packets,
                    tx_bytes,
                    tx_dropped,
                    tx_errors,
                    rss_kb(args.controller_pid),
                ]
            )
            handle.flush()
            index += 1
            delay = deadline - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())