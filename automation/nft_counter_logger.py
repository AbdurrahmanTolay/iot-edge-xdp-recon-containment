#!/usr/bin/env python3
"""Sample the project-owned nftables drop counter for C4 interval evidence."""

from __future__ import annotations

import argparse
import csv
import json
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

STOP = False


def stop(*_: object) -> None:
    global STOP
    STOP = True


def packet_counter() -> tuple[int | None, str]:
    process = subprocess.run(
        ["nft", "-j", "list", "chain", "inet", "recon_test", "recon_input"],
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        return None, (process.stderr or process.stdout).strip()
    document = json.loads(process.stdout)
    for item in document.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        for expression in rule.get("expr", []):
            counter = expression.get("counter")
            if counter and "packets" in counter:
                return int(counter["packets"]), ""
    return None, "dedicated counter expression not found"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interval-ms", type=int, required=True)
    args = parser.parse_args()
    if not args.run_id.startswith("RECON_") or args.interval_ms <= 0:
        raise ValueError("invalid run ID or interval")
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    previous_sample_ns: int | str = ""
    index = 0
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "run_id", "sample_index", "realtime_iso",
                "sample_start_mono_ns", "sample_end_mono_ns",
                "previous_sample_end_mono_ns", "drop_packets", "status",
                "error",
            ]
        )
        deadline = time.monotonic()
        while not STOP:
            start_ns = time.monotonic_ns()
            packets, error = packet_counter()
            end_ns = time.monotonic_ns()
            writer.writerow(
                [
                    args.run_id, index, datetime.now(timezone.utc).isoformat(),
                    start_ns, end_ns, previous_sample_ns,
                    "" if packets is None else packets,
                    "OK" if packets is not None else "UNAVAILABLE",
                    error,
                ]
            )
            handle.flush()
            previous_sample_ns = end_ns
            index += 1
            deadline += args.interval_ms / 1000.0
            delay = deadline - time.monotonic()
            if delay > 0:
                time.sleep(delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())