#ifndef IOT_RECON_XDP_COMMON_H
#define IOT_RECON_XDP_COMMON_H

#include <linux/bpf.h>
#include <linux/types.h>

enum recon_allowlist_flags {
    RECON_ALLOW_ADMIN   = 1U << 0,
    RECON_ALLOW_CONTROL = 1U << 1,
};

enum recon_quarantine_reason {
    RECON_Q_REASON_UNSPECIFIED     = 0,
    RECON_Q_REASON_RATE            = 1,
    RECON_Q_REASON_SHORT_DIVERSITY = 2,
    RECON_Q_REASON_LONG_DIVERSITY  = 3,
    RECON_Q_REASON_DUAL_BOTH       = 4,
};

enum recon_counter_id {
    RECON_CNT_IPV4_PACKETS = 0,
    RECON_CNT_TCP_PROBE_CANDIDATES,
    RECON_CNT_UDP_PROBE_CANDIDATES,
    RECON_CNT_ALLOWLIST_PASS,
    RECON_CNT_ACTIVE_QUARANTINE_DROP,
    RECON_CNT_EXPIRED_QUARANTINE_PASS,
    RECON_CNT_TELEMETRY_UPDATE_OK,
    RECON_CNT_TELEMETRY_INSERT_FAIL,
    RECON_CNT_ATTEMPT_COUNTER_SATURATED,
    RECON_CNT_UNSUPPORTED_PACKETS,
    RECON_CNT_TRUNCATED_PACKETS,
    RECON_CNT_FRAGMENT_CASES,
    RECON_CNT_INVALID_SYN_FLAG_COMBINATIONS,
    RECON_CNT_OTHER_MAP_ERRORS,
    RECON_CNT_RESERVED_14,
    RECON_CNT_RESERVED_15,
    RECON_COUNTER_COUNT
};

struct ipv4_source_key {
    __be32 source_ipv4;
};

struct allowlist_value {
    __u32 flags;
};

struct recon_tuple_key {
    __be32 source_ipv4;
    __u16 destination_port; /* host byte order */
    __u8 l4_protocol;
    __u8 reserved;
};

struct recon_telemetry_value {
    struct bpf_spin_lock lock;
    __u32 reserved;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 attempts;
};

struct recon_quarantine_value {
    struct bpf_spin_lock lock;
    __u32 reason_code;
    __u64 expiry_ns;
    __u64 first_drop_ns;
    __u64 drop_count;
};

_Static_assert(sizeof(struct ipv4_source_key) == 4, "ipv4_source_key ABI");
_Static_assert(sizeof(struct allowlist_value) == 4, "allowlist_value ABI");
_Static_assert(sizeof(struct recon_tuple_key) == 8, "recon_tuple_key ABI");
_Static_assert(sizeof(struct recon_telemetry_value) == 32, "telemetry ABI");
_Static_assert(sizeof(struct recon_quarantine_value) == 32, "quarantine ABI");

#endif
