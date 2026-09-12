#ifndef IOT_RECON_BPF_HELPERS_MIN_H
#define IOT_RECON_BPF_HELPERS_MIN_H

#include <linux/bpf.h>
#include <linux/types.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define __array(name, val) val *name[]
#define __ulong(name, val) enum { ___bpf_concat(__unique_value, __COUNTER__) = val } name
#define ___bpf_concat(a, b) a ## b

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_ktime_get_ns)(void) =
    (void *)BPF_FUNC_ktime_get_ns;
static void (*bpf_spin_lock)(struct bpf_spin_lock *lock) =
    (void *)BPF_FUNC_spin_lock;
static void (*bpf_spin_unlock)(struct bpf_spin_lock *lock) =
    (void *)BPF_FUNC_spin_unlock;

#endif
