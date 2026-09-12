#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>

#include "bpf_helpers_min.h"
#include "xdp_common.h"
#include "xdp_maps.h"

struct recon_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#define RECON_IP_MF     0x2000
#define RECON_IP_OFFSET 0x1FFF

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static __always_inline __u16 bpf_ntohs16(__u16 x)
{
    return __builtin_bswap16(x);
}

static __always_inline void count(enum recon_counter_id id)
{
    __u32 key = (__u32)id;
    __u64 *v = bpf_map_lookup_elem(&counters_map, &key);

    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline int allowlisted(__be32 src)
{
    struct ipv4_source_key key = {
        .source_ipv4 = src
    };

    return bpf_map_lookup_elem(&allowlist_map, &key) != 0;
}

static __always_inline int update_existing(
    struct recon_telemetry_value *v,
    __u64 now)
{
    int saturated = 0;

    /*
     * IMPORTANT:
     * No BPF helper/function calls are allowed while holding
     * a bpf_spin_lock.
     */
    bpf_spin_lock(&v->lock);

    if (now > v->last_seen_ns)
        v->last_seen_ns = now;

    if (v->attempts != ~0ULL) {
        v->attempts++;
    } else {
        saturated = 1;
    }

    bpf_spin_unlock(&v->lock);

    /*
     * Counter helpers are called only after releasing the lock.
     */
    if (saturated)
        count(RECON_CNT_ATTEMPT_COUNTER_SATURATED);

    count(RECON_CNT_TELEMETRY_UPDATE_OK);

    return 0;
}

static __always_inline void update_telemetry(
    const struct recon_tuple_key *key,
    __u64 now)
{
    struct recon_telemetry_value *cur;

    cur = bpf_map_lookup_elem(&telemetry_map, key);

    if (cur) {
        update_existing(cur, now);
        return;
    }

    struct recon_telemetry_value fresh = {};

    fresh.first_seen_ns = now;
    fresh.last_seen_ns = now;
    fresh.attempts = 1;

    long rc = bpf_map_update_elem(
        &telemetry_map,
        key,
        &fresh,
        BPF_NOEXIST);

    if (rc == 0) {
        count(RECON_CNT_TELEMETRY_UPDATE_OK);
        return;
    }

    /*
     * A concurrent insertion may have won.
     * Perform one bounded relookup.
     */
    cur = bpf_map_lookup_elem(&telemetry_map, key);

    if (cur) {
        update_existing(cur, now);
        return;
    }

    count(RECON_CNT_TELEMETRY_INSERT_FAIL);
    count(RECON_CNT_OTHER_MAP_ERRORS);
}

static __always_inline int enforce_quarantine(
    __be32 src,
    __u64 now)
{
    struct ipv4_source_key key = {
        .source_ipv4 = src
    };

    struct recon_quarantine_value *q;

    q = bpf_map_lookup_elem(&quarantine_map, &key);

    if (!q)
        return XDP_PASS;

    /*
     * Kernel-side logical expiry.
     *
     * A stale map entry must not continue blocking traffic
     * merely because userspace cleanup has not run yet.
     */
    if (now >= q->expiry_ns) {
        count(RECON_CNT_EXPIRED_QUARANTINE_PASS);
        return XDP_PASS;
    }

    /*
     * No helper calls occur while this lock is held.
     */
    bpf_spin_lock(&q->lock);

    if (q->first_drop_ns == 0)
        q->first_drop_ns = now;

    if (q->drop_count != ~0ULL)
        q->drop_count++;

    bpf_spin_unlock(&q->lock);

    count(RECON_CNT_ACTIVE_QUARANTINE_DROP);

    return XDP_DROP;
}

SEC("xdp")
int xdp_recon(struct xdp_md *ctx)
{
    void *data;
    void *data_end;

    struct ethhdr *eth;

    __u16 proto;
    __u64 now;

    void *cursor;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    eth = data;

    /*
     * Ethernet header bounds check.
     */
    if ((void *)(eth + 1) > data_end) {
        count(RECON_CNT_TRUNCATED_PACKETS);
        return XDP_PASS;
    }

    proto = bpf_ntohs16(eth->h_proto);
    cursor = eth + 1;

    /*
     * Support exactly one VLAN tag.
     */
    if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
        struct recon_vlan_hdr *vh = cursor;

        if ((void *)(vh + 1) > data_end) {
            count(RECON_CNT_TRUNCATED_PACKETS);
            return XDP_PASS;
        }

        proto = bpf_ntohs16(vh->h_vlan_encapsulated_proto);
        cursor = vh + 1;

        /*
         * Double-tagged frames are intentionally not interpreted
         * for reconnaissance telemetry.
         */
        if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
            count(RECON_CNT_UNSUPPORTED_PACKETS);
            return XDP_PASS;
        }
    }

    /*
     * Only IPv4 is part of the frozen experiment telemetry model.
     */
    if (proto != ETH_P_IP) {
        count(RECON_CNT_UNSUPPORTED_PACKETS);
        return XDP_PASS;
    }

    struct iphdr *iph = cursor;

    /*
     * Validate minimum IPv4 header.
     */
    if ((void *)(iph + 1) > data_end) {
        count(RECON_CNT_TRUNCATED_PACKETS);
        return XDP_PASS;
    }

    if (iph->version != 4 || iph->ihl < 5) {
        count(RECON_CNT_TRUNCATED_PACKETS);
        return XDP_PASS;
    }

    /*
     * IPv4 IHL is four bits.
     *
     * Valid range after the preceding check:
     * 20 ... 60 bytes.
     */
    __u32 ihl_bytes = (__u32)iph->ihl * 4;

    if ((void *)iph + ihl_bytes > data_end) {
        count(RECON_CNT_TRUNCATED_PACKETS);
        return XDP_PASS;
    }

    /*
     * Validate IPv4 total length without adding an untrusted
     * packet-derived scalar directly to a packet pointer.
     */
    __u32 total_len = (__u32)bpf_ntohs16(iph->tot_len);

    if (total_len < ihl_bytes) {
        count(RECON_CNT_TRUNCATED_PACKETS);
        return XDP_PASS;
    }

    __u32 available =
        (__u32)((char *)data_end - (char *)iph);

    if (total_len > available) {
        count(RECON_CNT_TRUNCATED_PACKETS);
        return XDP_PASS;
    }

    count(RECON_CNT_IPV4_PACKETS);

    now = bpf_ktime_get_ns();

    /*
     * Administrative allowlist has precedence over telemetry
     * and quarantine.
     */
    if (allowlisted(iph->saddr)) {
        count(RECON_CNT_ALLOWLIST_PASS);
        return XDP_PASS;
    }

    /*
     * Fragments do not generate transport-level telemetry because
     * later fragments may not contain a complete TCP/UDP header.
     *
     * They remain subject to active quarantine.
     */
    __u16 frag = bpf_ntohs16(iph->frag_off);

    if ((frag & (RECON_IP_MF | RECON_IP_OFFSET)) != 0) {
        count(RECON_CNT_FRAGMENT_CASES);
        return enforce_quarantine(iph->saddr, now);
    }

    struct recon_tuple_key tkey = {
        .source_ipv4 = iph->saddr,
        .destination_port = 0,
        .l4_protocol = 0,
        .reserved = 0,
    };

    int candidate = 0;

    /*
     * ihl_bytes has already been verifier-bounded to 20...60.
     */
    void *l4 = (void *)iph + ihl_bytes;

    /*
     * TCP reconnaissance candidate:
     *
     * SYN = 1
     * ACK = 0
     * FIN = 0
     * RST = 0
     *
     * ECE/CWR are permitted.
     *
     * Retransmissions increment attempt count but do not create
     * additional diversity because the telemetry map key remains
     * (source IPv4, protocol, destination port).
     */
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;

        if ((void *)(tcp + 1) > data_end) {
            count(RECON_CNT_TRUNCATED_PACKETS);
            return enforce_quarantine(iph->saddr, now);
        }

        if (tcp->syn && (tcp->fin || tcp->rst)) {
            count(RECON_CNT_INVALID_SYN_FLAG_COMBINATIONS);
        }
        else if (
            tcp->syn &&
            !tcp->ack &&
            !tcp->fin &&
            !tcp->rst)
        {
            candidate = 1;

            tkey.destination_port =
                bpf_ntohs16(tcp->dest);

            tkey.l4_protocol = IPPROTO_TCP;

            count(RECON_CNT_TCP_PROBE_CANDIDATES);
        }
    }

    /*
     * Every structurally valid UDP datagram is a reconnaissance
     * telemetry candidate.
     */
    else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;

        if ((void *)(udp + 1) > data_end) {
            count(RECON_CNT_TRUNCATED_PACKETS);
            return enforce_quarantine(iph->saddr, now);
        }

        __u16 ulen = bpf_ntohs16(udp->len);

        if (ulen < sizeof(*udp)) {
            count(RECON_CNT_TRUNCATED_PACKETS);
            return enforce_quarantine(iph->saddr, now);
        }

        /*
         * Verifier-friendly UDP length validation.
         */
        __u32 udp_available =
            (__u32)((char *)data_end - (char *)udp);

        if ((__u32)ulen > udp_available) {
            count(RECON_CNT_TRUNCATED_PACKETS);
            return enforce_quarantine(iph->saddr, now);
        }

        candidate = 1;

        tkey.destination_port =
            bpf_ntohs16(udp->dest);

        tkey.l4_protocol = IPPROTO_UDP;

        count(RECON_CNT_UDP_PROBE_CANDIDATES);
    }

    /*
     * Frozen Stage-B processing order:
     *
     * 1. Update reconnaissance telemetry.
     * 2. Enforce active quarantine.
     *
     * Therefore traffic remains observable during quarantine
     * before the packet is dropped.
     */
    if (candidate)
        update_telemetry(&tkey, now);

    return enforce_quarantine(iph->saddr, now);
}

char LICENSE[] SEC("license") = "GPL";
