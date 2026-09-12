#!/usr/bin/env bash
set -euo pipefail

# No temperature limit is embedded. Calibration/operations must supply it.
max_c=""
max_wait_s=""
poll_s=""
output=""
while (($#)); do
    case "$1" in
        --max-c) max_c="${2:?missing max temperature}"; shift 2 ;;
        --max-wait-s) max_wait_s="${2:?missing max wait}"; shift 2 ;;
        --poll-s) poll_s="${2:?missing poll interval}"; shift 2 ;;
        --output) output="${2:?missing output}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -n "$max_c" && -n "$max_wait_s" && -n "$poll_s" && -n "$output" ]] || {
    echo "--max-c, --max-wait-s, --poll-s, and --output are required" >&2
    exit 2
}

MAX_C="$max_c" MAX_WAIT_S="$max_wait_s" POLL_S="$poll_s" OUTPUT="$output" \
python3 - <<'PY'
import json, os, pathlib, shutil, subprocess, time
from datetime import datetime, timezone

limit = float(os.environ["MAX_C"])
max_wait = float(os.environ["MAX_WAIT_S"])
poll = float(os.environ["POLL_S"])
if poll <= 0 or max_wait < 0:
    raise ValueError("invalid guard timing")
samples = []
start = time.monotonic()
passed = False
while True:
    try:
        temperature = int(pathlib.Path("/sys/class/thermal/thermal_zone0/temp").read_text()) / 1000.0
    except (OSError, ValueError):
        temperature = None
    throttling = None
    if shutil.which("vcgencmd"):
        proc = subprocess.run(["vcgencmd", "get_throttled"], text=True, capture_output=True)
        throttling = (proc.stdout or proc.stderr).strip() or None
    elapsed = time.monotonic() - start
    samples.append({
        "realtime_iso": datetime.now(timezone.utc).isoformat(),
        "mono_ns": time.monotonic_ns(),
        "temperature_c": temperature,
        "throttling_state": throttling,
        "elapsed_s": elapsed,
    })
    if temperature is not None and temperature <= limit:
        passed = True
        break
    if elapsed >= max_wait:
        break
    time.sleep(poll)
result = {
    "configured_max_c": limit,
    "configured_max_wait_s": max_wait,
    "configured_poll_s": poll,
    "passed": passed,
    "wait_duration_s": time.monotonic() - start,
    "samples": samples,
}
path = pathlib.Path(os.environ["OUTPUT"])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(result, indent=2) + "\n")
raise SystemExit(0 if passed else 1)
PY