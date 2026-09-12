#!/usr/bin/env python3
"""Execute exactly one finalized physical run; never assign final status.

Workload configuration files named by the manifest are JSON objects with name,
role (server/client/scanner), command (argument list), and optional cwd and
environment. Commands run without a shell after placeholder substitution.
Remote execution is explicit (for example, an approved ssh command), never
assumed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]


@dataclass
class ManagedProcess:
    name: str
    role: str
    process: subprocess.Popen[str]
    log_handle: Any


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def marker(path: Path, run_id: str, event: str, **fields: object) -> None:
    row = {
        "run_id": run_id,
        "event": event,
        "realtime_iso": iso_now(),
        "mono_ns": time.monotonic_ns(),
        **fields,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def substitute(value: str, context: dict[str, str]) -> str:
    for key, replacement in context.items():
        value = value.replace("{" + key + "}", replacement)
    return value


def start_process(
    spec: dict[str, Any],
    context: dict[str, str],
    raw_dir: Path,
    inherited_env: dict[str, str],
) -> ManagedProcess:
    name = str(spec["name"])
    role = str(spec["role"])
    command = [substitute(str(item), context) for item in spec["command"]]
    if not command:
        raise ValueError(f"empty workload command: {name}")
    cwd = Path(substitute(str(spec.get("cwd", ROOT)), context))
    environment = inherited_env.copy()
    environment.update(
        {
            str(key): substitute(str(value), context)
            for key, value in dict(spec.get("environment", {})).items()
        }
    )
    log_path = raw_dir / "process_logs" / f"{name}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("a", encoding="utf-8")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    pid_dir = raw_dir / "pids"
    pid_dir.mkdir(exist_ok=True)
    (pid_dir / f"{name}.pid").write_text(f"{process.pid}\n", encoding="utf-8")
    return ManagedProcess(name, role, process, log_handle)


def stop_process(managed: ManagedProcess, timeout_s: float = 5.0) -> int:
    if managed.process.poll() is None:
        os.killpg(managed.process.pid, signal.SIGTERM)
        try:
            managed.process.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            os.killpg(managed.process.pid, signal.SIGKILL)
            managed.process.wait(timeout=2)
    managed.log_handle.close()
    return int(managed.process.returncode or 0)


def controller_command(
    manifest: dict[str, Any], raw_dir: Path, runtime: dict[str, Any]
) -> list[str]:
    binary = str(runtime.get("controller_binary", ROOT / "implementation/controller/recon_controller"))
    obj = str(runtime.get("xdp_object", ROOT / "implementation/xdp/xdp_recon.o"))
    mode = str(manifest["xdp_mode_actual"]).lower()
    selected = "rate" if manifest["configuration"] == "C1" else "dual"
    command = [
        binary,
        "--run-id", str(manifest["run_id"]),
        "--interface", str(manifest["interface_actual"]),
        "--object", obj,
        "--xdp-mode", mode,
        "--configuration", str(manifest["configuration"]),
        "--selected-detector", selected,
        "--short-window-s", str(manifest["short_window_s"]),
        "--long-window-s", str(manifest["long_window_s"]),
        "--rate-window-s", str(manifest["rate_window_s"]),
        "--short-threshold", str(manifest["short_threshold"]),
        "--long-threshold", str(manifest["long_threshold"]),
        "--rate-count-threshold", str(manifest["rate_count_threshold"]),
        "--poll-ms", str(manifest["controller_poll_ms"]),
        "--quarantine-s", str(manifest["quarantine_s"]),
        "--cooldown-s", str(manifest["cooldown_s"]),
        "--cleanup-grace-s", str(manifest["cleanup_grace_s"]),
        "--telemetry-capacity", str(manifest["telemetry_capacity"]),
        "--allowlist-capacity", str(manifest["allowlist_capacity"]),
        "--quarantine-capacity", str(manifest["quarantine_capacity"]),
        "--controller-csv", str(raw_dir / "controller.csv"),
        "--stats-csv", str(raw_dir / "xdp_stats.csv"),
        "--probe-csv", str(raw_dir / "gateway_probe_events.csv"),
        "--nft-adapter", str(ROOT / "implementation/comparators/nftables_quarantine.sh"),
    ]
    for address in manifest["allowlisted_ips"]:
        command.extend(["--allowlist-ip", str(address)])
    return command


def capture_environment(manifest: dict[str, Any], raw_dir: Path) -> dict[str, Any]:
    subprocess.run(
        [
            str(ROOT / "automation/pi_environment_probe.sh"),
            "--interface", str(manifest["interface_requested"]),
            "--output-dir", str(raw_dir),
        ],
        check=True,
    )
    environment = load_json(raw_dir / "environment.json")
    selected = environment.get("selected_interface", {})
    manifest["interface_actual"] = selected.get("name")
    manifest["kernel"] = environment.get("kernel")
    manifest["nic_driver"] = selected.get("driver")
    manifest["mtu"] = int(selected["mtu"]) if selected.get("mtu") else None
    speed = selected.get("speed_mbps_sysfs")
    manifest["link_speed_mbps"] = int(speed) if speed and str(speed).isdigit() else None
    governors = environment.get("cpu", {}).get("governors", {})
    manifest["cpu_governor"] = next((value for value in governors.values() if value), None)
    manifest["offload_state"] = selected.get("offload_features")
    manifest["environment_realtime_iso"] = environment.get("collected_realtime_iso")
    boot_id = Path("/proc/sys/kernel/random/boot_id")
    manifest["boot_id"] = boot_id.read_text().strip() if boot_id.exists() else None
    manifest["gateway_ip_actual"] = None
    address_probe = selected.get("addresses") or {}
    if address_probe.get("value"):
        address_document = json.loads(address_probe["value"])
        local_addresses = {
            item.get("local")
            for link in address_document
            for item in link.get("addr_info", [])
            if item.get("family") == "inet"
        }
        if manifest.get("gateway_ip") in local_addresses:
            manifest["gateway_ip_actual"] = manifest.get("gateway_ip")
    return environment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--raw-root", type=Path, default=ROOT / "experiments/raw")
    parser.add_argument("--runtime-config", type=Path)
    parser.add_argument("--acknowledge-authorized-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not args.acknowledge_authorized_run:
        LOGGER.error("--acknowledge-authorized-run is required")
        return 2
    manifest = load_json(args.manifest)
    run_id = str(manifest.get("run_id", ""))
    if not run_id.startswith("RECON_") or manifest.get("manifest_status") != "FINALIZED":
        raise ValueError("a finalized RECON_ manifest is required")
    raw_dir = args.raw_root / run_id
    if raw_dir.exists() and any(raw_dir.iterdir()):
        raise FileExistsError(f"raw run directory is not empty: {raw_dir}")
    raw_dir.mkdir(parents=True, exist_ok=True)
    runtime = load_json(args.runtime_config) if args.runtime_config else {}
    markers = raw_dir / "markers.jsonl"
    completion = raw_dir / "provisional_completion.json"
    managed: list[ManagedProcess] = []
    exit_codes: dict[str, int] = {}
    run_error: str | None = None

    shutil.copy2(args.manifest, raw_dir / "manifest.planned.json")
    capture_environment(manifest, raw_dir)
    guard = runtime.get("thermal_guard")
    if guard:
        required_guard = ("max_c", "max_wait_s", "poll_s")
        if any(guard.get(field) is None for field in required_guard):
            raise ValueError("thermal_guard values are not finalized")
        subprocess.run(
            [
                str(ROOT / "automation/temperature_guard.sh"),
                "--max-c", str(guard["max_c"]),
                "--max-wait-s", str(guard["max_wait_s"]),
                "--poll-s", str(guard["poll_s"]),
                "--output", str(raw_dir / "temperature_guard.json"),
            ],
            check=True,
        )
    if manifest["configuration"] == "C0_T0":
        manifest["xdp_mode_actual"] = "NONE"
    else:
        mode_probe_path = runtime.get("xdp_mode_probe")
        if not mode_probe_path:
            raise ValueError("runtime config must identify xdp_mode_probe JSON")
        mode_probe = load_json(Path(mode_probe_path))
        selected_mode = mode_probe.get("selected_mode")
        if selected_mode not in {"native", "generic"}:
            raise RuntimeError("no verified XDP mode is available")
        manifest["xdp_mode_actual"] = selected_mode.upper()
    sync_path = raw_dir / "sync_check.json"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "automation/sync_check.py"),
            "--output", str(sync_path),
        ],
        check=True,
    )
    sync = load_json(sync_path)
    manifest["clock_sync_method"] = sync.get("method")
    manifest["clock_sync_status"] = sync.get("status")
    manifest["clock_offset_us"] = sync.get("offset_us")
    manifest["clock_uncertainty_us"] = sync.get("uncertainty_us")
    manifest["temperature_guard_log"] = (
        str(raw_dir / "temperature_guard.json") if guard else None
    )
    (raw_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    target = manifest.get("target_manifest")
    if target and sha256(Path(target)) != manifest.get("target_manifest_sha256"):
        raise ValueError("target manifest hash mismatch")
    subprocess.run(
        [
            str(ROOT / "automation/health_check.sh"),
            "--manifest", str(raw_dir / "manifest.json"),
            "--output", str(raw_dir / "health.json"),
        ],
        check=True,
    )
    manifest["health_log"] = str(raw_dir / "health.json")
    (raw_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    context = {
        "run_id": run_id,
        "raw_dir": str(raw_dir),
        "gateway_ip": str(manifest["gateway_ip"]),
        "scanner_ip": str(manifest.get("scanner_ip") or ""),
        "target_manifest": str(target or ""),
        "seed": str(manifest["random_seed"]),
        "probe_interval_ms": str(manifest.get("probe_interval_ms") or ""),
    }
    workload_specs = [load_json(Path(path)) for path in manifest["workload_configs"]]
    inherited_env = os.environ.copy()
    inherited_env["RECON_NFT_LOG"] = str(raw_dir / "nftables.csv")

    marker(markers, run_id, "RUN_START")
    try:
        if manifest["configuration"] != "C0_T0":
            spec = {
                "name": "controller",
                "role": "controller",
                "command": controller_command(manifest, raw_dir, runtime),
                "cwd": str(ROOT),
            }
            managed.append(start_process(spec, context, raw_dir, inherited_env))
            time.sleep(float(runtime["startup_check_s"]))
            if managed[-1].process.poll() is not None:
                raise RuntimeError("controller exited during startup")

        controller_pid = next(
            (item.process.pid for item in managed if item.role == "controller"), None
        )
        resource_command = [
            sys.executable,
            str(ROOT / "automation/resource_logger.py"),
            "--run-id", run_id,
            "--interface", str(manifest["interface_actual"]),
            "--output", str(raw_dir / "resource.csv"),
            "--interval-s", str(runtime["resource_interval_s"]),
        ]
        if controller_pid:
            resource_command.extend(["--controller-pid", str(controller_pid)])
        managed.append(
            start_process(
                {"name": "resource_logger", "role": "logger", "command": resource_command},
                context, raw_dir, inherited_env,
            )
        )
        if manifest["configuration"] == "C4":
            managed.append(
                start_process(
                    {
                        "name": "nft_counter_logger",
                        "role": "logger",
                        "command": [
                            sys.executable,
                            str(ROOT / "automation/nft_counter_logger.py"),
                            "--run-id", run_id,
                            "--output", str(raw_dir / "nft_stats.csv"),
                            "--interval-ms", str(manifest["controller_poll_ms"]),
                        ],
                    },
                    context, raw_dir, inherited_env,
                )
            )

        for spec in workload_specs:
            if spec.get("role") in {"server", "client"}:
                managed.append(start_process(spec, context, raw_dir, inherited_env))
        marker(markers, run_id, "LEGITIMATE_WORKLOAD_START")
        time.sleep(float(manifest["warmup_s"]))

        scanner_specs = [spec for spec in workload_specs if spec.get("role") == "scanner"]
        if manifest["protocol_mode"] != "NONE" and len(scanner_specs) != 1:
            raise ValueError("exactly one scanner workload is required")
        for spec in scanner_specs:
            managed.append(start_process(spec, context, raw_dir, inherited_env))
        marker(markers, run_id, "SCAN_START")
        time.sleep(float(manifest["scan_s"]))
        for item in list(managed):
            if item.role == "scanner":
                rc = stop_process(item)
                exit_codes[item.name] = rc
                managed.remove(item)
                if rc != 0:
                    raise RuntimeError(
                        f"scanner process {item.name} exited with code {rc}"
                    )
        marker(markers, run_id, "SCAN_STOP")

        post_s = max(
            float(manifest["minimum_post_scan_s"]),
            float(manifest["quarantine_s"])
            + float(manifest["cooldown_s"])
            + float(manifest["recovery_s"]),
        )
        time.sleep(post_s)
        marker(markers, run_id, "RECOVERY_OBSERVATION_COMPLETE")
    except Exception as exc:
        run_error = f"{exc.__class__.__name__}: {exc}"
        LOGGER.exception("run failed provisionally")
    finally:
        for item in reversed(managed):
            try:
                exit_codes[item.name] = stop_process(item)
            except Exception as exc:
                exit_codes[item.name] = 255
                if run_error is None:
                    run_error = f"stop {item.name}: {exc}"
        if shutil.which("bpftool"):
            pin_dir = Path("/sys/fs/bpf/recon_test")
            for name in ("recon_allowlist", "recon_telemetry", "recon_quarantine", "recon_counters"):
                pin = pin_dir / name
                if pin.exists():
                    with (raw_dir / f"{name}_final.json").open("w", encoding="utf-8") as handle:
                        subprocess.run(
                            ["bpftool", "-j", "map", "dump", "pinned", str(pin)],
                            stdout=handle, stderr=subprocess.STDOUT, check=False, text=True,
                        )
        marker(markers, run_id, "RUN_STOP", provisional_error=run_error)
        completion.write_text(
            json.dumps(
                {
                    "run_id": run_id,
                    "provisional_complete": run_error is None,
                    "error": run_error,
                    "process_exit_codes": exit_codes,
                    "end_realtime_iso": iso_now(),
                    "end_mono_ns": time.monotonic_ns(),
                },
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
    return 0 if run_error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())