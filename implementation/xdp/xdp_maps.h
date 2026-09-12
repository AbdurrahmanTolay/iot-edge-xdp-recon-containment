#ifndef IOT_RECON_XDP_MAPS_H
#define IOT_RECON_XDP_MAPS_H

#include "bpf_helpers_min.h"
#include "xdp_common.h"

/* Defaults are overridden by the userspace loader before bpf_object__load(). */
#define RECON_ALLOWLIST_CAPACITY_DEFAULT 64
#define RECON_TELEMETRY_CAPACITY_DEFAULT 4096
#define RECON_QUARANTINE_CAPACITY_DEFAULT 1024

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RECON_ALLOWLIST_CAPACITY_DEFAULT);
    __type(key, struct ipv4_source_key);
    __type(value, struct allowlist_value);
} allowlist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RECON_TELEMETRY_CAPACITY_DEFAULT);
    __type(key, struct recon_tuple_key);
    __type(value, struct recon_telemetry_value);
} telemetry_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RECON_QUARANTINE_CAPACITY_DEFAULT);
    __type(key, struct ipv4_source_key);
    __type(value, struct recon_quarantine_value);
} quarantine_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, RECON_COUNTER_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} counters_map SEC(".maps");

#endif
