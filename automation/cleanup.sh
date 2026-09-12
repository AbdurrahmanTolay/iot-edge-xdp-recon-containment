#!/usr/bin/env bash
set -euo pipefail

manifest=""
raw_dir=""
result=""
while (($#)); do
    case "$1" in
        --manifest) manifest="${2:?missing manifest}"; shift 2 ;;
        --raw-dir) raw_dir="${2:?missing raw directory}"; shift 2 ;;
        --result) result="${2:?missing result path}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -f "$manifest" && -d "$raw_dir" && -n "$result" ]] || {
    echo "--manifest, --raw-dir, and --result are required" >&2
    exit 2
}

readarray -t fields < <(python3 - "$manifest" <<'PY'
import json, sys
m=json.load(open(sys.argv[1]))
print(m.get("interface_actual") or m.get("interface_requested") or "")
print((m.get("xdp_mode_actual") or m.get("xdp_mode_requested") or "").lower())
PY
)
interface="${fields[0]}"
mode="${fields[1]}"
failures=()

for pidfile in "$raw_dir"/pids/*.pid; do
    [[ -e "$pidfile" ]] || continue
    pid="$(cat "$pidfile")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..20}; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    kill -0 "$pid" 2>/dev/null && failures+=("process_alive:$pidfile")
done

if [[ -n "$interface" ]] && command -v ip >/dev/null 2>&1; then
    if [[ "$mode" == "native" ]]; then
        ip link set dev "$interface" xdp off >/dev/null 2>&1 || true
    elif [[ "$mode" == "generic" ]]; then
        ip link set dev "$interface" xdpgeneric off >/dev/null 2>&1 || true
    fi
    state="$(cat "/sys/class/net/$interface/operstate" 2>/dev/null || true)"
    [[ "$state" == "up" || "$state" == "unknown" ]] || failures+=("interface_state:$state")
fi

implementation/comparators/nftables_cleanup.sh \
    --run-id "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["run_id"])' "$manifest")" \
    --log "$raw_dir/nftables.csv" || failures+=("nftables_cleanup")

pin_dir="/sys/fs/bpf/recon_test"
if [[ -d "$pin_dir" ]]; then
    rm -f "$pin_dir/recon_allowlist" "$pin_dir/recon_telemetry" \
        "$pin_dir/recon_quarantine" "$pin_dir/recon_counters" || failures+=("pin_remove")
    rmdir "$pin_dir" 2>/dev/null || true
fi
[[ ! -e "$pin_dir/recon_quarantine" ]] || failures+=("quarantine_pin_remains")

FAILURES="$(printf '%s\n' "${failures[@]-}")" RESULT="$result" python3 - <<'PY'
import json, os, pathlib, time
failures=[line for line in os.environ.get("FAILURES","").splitlines() if line]
path=pathlib.Path(os.environ["RESULT"])
path.parent.mkdir(parents=True,exist_ok=True)
path.write_text(json.dumps({
    "mono_ns": time.monotonic_ns(),
    "success": not failures,
    "failures": failures,
},indent=2)+"\n")
raise SystemExit(0 if not failures else 1)
PY