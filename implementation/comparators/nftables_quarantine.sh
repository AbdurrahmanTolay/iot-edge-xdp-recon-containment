#!/usr/bin/env bash
set -euo pipefail

# Project-owned nftables adapter for C4. It touches only:
#   table inet recon_test
#   set   inet recon_test quarantine_v4
# The table is intentionally separate from all host firewall tables.

TABLE_FAMILY="inet"
TABLE_NAME="recon_test"
SET_NAME="quarantine_v4"
CHAIN_NAME="recon_input"

action="${1:-}"
[[ -n "$action" ]] || { echo "action required: init|insert|remove|flush|destroy|verify-empty" >&2; exit 2; }
shift

run_id=""
source_ipv4=""
timeout_ms="0"
log_path="${RECON_NFT_LOG:-}"
while (($#)); do
    case "$1" in
        --run-id) run_id="${2:?missing run id}"; shift 2 ;;
        --source) source_ipv4="${2:?missing source}"; shift 2 ;;
        --timeout-ms) timeout_ms="${2:?missing timeout}"; shift 2 ;;
        --log) log_path="${2:?missing log path}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v nft >/dev/null 2>&1 || { echo "nft is required" >&2; exit 2; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "root is required" >&2; exit 2; }
if [[ -n "$run_id" && ! "$run_id" =~ ^RECON_[A-Za-z0-9_-]+$ ]]; then
    echo "invalid RECON_ run ID" >&2
    exit 2
fi
if [[ "$action" == "insert" || "$action" == "remove" ]]; then
    python3 - "$source_ipv4" <<'PY'
import ipaddress, sys
ipaddress.IPv4Address(sys.argv[1])
PY
fi
[[ "$timeout_ms" =~ ^[0-9]+$ ]] || { echo "timeout must be integer milliseconds" >&2; exit 2; }

mono_ns() { python3 -c 'import time; print(time.monotonic_ns())'; }
wall_iso() { python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).isoformat())'; }

ensure_table() {
    if ! nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
        nft -f - <<NFT
add table $TABLE_FAMILY $TABLE_NAME
add set $TABLE_FAMILY $TABLE_NAME $SET_NAME { type ipv4_addr; flags timeout; }
add chain $TABLE_FAMILY $TABLE_NAME $CHAIN_NAME { type filter hook input priority -5; policy accept; }
add rule $TABLE_FAMILY $TABLE_NAME $CHAIN_NAME ip saddr @$SET_NAME counter drop comment "iot-recon-xdp C4"
NFT
    fi
}

start_ns="$(mono_ns)"
rc=0
detail=""
set +e
case "$action" in
    init)
        ensure_table
        rc=$?
        ;;
    insert)
        [[ "$timeout_ms" -gt 0 ]] || { echo "insert requires positive --timeout-ms" >&2; exit 2; }
        ensure_table || rc=$?
        if [[ $rc -eq 0 ]]; then
            detail="$(nft add element "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" \
                "{ $source_ipv4 timeout ${timeout_ms}ms }" 2>&1)"
            rc=$?
        fi
        ;;
    remove)
        if nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
            detail="$(nft delete element "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" \
                "{ $source_ipv4 }" 2>&1)"
            rc=$?
            # Already-expired timed entries are logically absent.
            [[ $rc -eq 0 ]] || rc=0
        fi
        ;;
    flush)
        if nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
            detail="$(nft flush set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" 2>&1)"
            rc=$?
        fi
        ;;
    destroy)
        if nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
            detail="$(nft delete table "$TABLE_FAMILY" "$TABLE_NAME" 2>&1)"
            rc=$?
        fi
        ;;
    verify-empty)
        if nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
            listing="$(nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" 2>&1)"
            rc=$?
            if [[ $rc -eq 0 && "$listing" == *"elements ="* ]]; then
                rc=5
                detail="set contains elements"
            fi
        fi
        ;;
    *)
        echo "unknown action: $action" >&2
        exit 2
        ;;
esac
set -e
end_ns="$(mono_ns)"

if [[ -n "$log_path" ]]; then
    mkdir -p "$(dirname "$log_path")"
    if [[ ! -s "$log_path" ]]; then
        echo "run_id,realtime_iso,action,source_ipv4,timeout_ms,start_mono_ns,end_mono_ns,result,detail" >>"$log_path"
    fi
    safe_detail="${detail//,/;}"
    printf '%s,%s,%s,%s,%s,%s,%s,%s,"%s"\n' \
        "$run_id" "$(wall_iso)" "$action" "$source_ipv4" "$timeout_ms" \
        "$start_ns" "$end_ns" "$([[ $rc -eq 0 ]] && echo SUCCESS || echo FAILED)" \
        "$safe_detail" >>"$log_path"
fi

if [[ $rc -ne 0 ]]; then
    echo "nftables action failed: action=$action rc=$rc detail=$detail" >&2
fi
exit "$rc"