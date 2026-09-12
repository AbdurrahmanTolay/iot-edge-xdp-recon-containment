
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "recon_controller.h"
#include "state_machine.h"
#include "../xdp/xdp_common.h"

struct config {
    const char *run_id;
    const char *interface;
    const char *object_path;
    const char *xdp_mode;
    const char *configuration;
    const char *selected_detector;
    double short_window_s;
    double long_window_s;
    double rate_window_s;
    uint64_t short_threshold;
    uint64_t long_threshold;
    uint64_t rate_count_threshold;
    unsigned poll_ms;
    double quarantine_s;
    double cooldown_s;
    double cleanup_grace_s;
    uint32_t telemetry_capacity;
    uint32_t allowlist_capacity;
    uint32_t quarantine_capacity;
    const char *controller_csv;
    const char *stats_csv;
    const char *probe_csv;
    const char *nft_adapter;
    const char *allowlist_ips[64];
    size_t allowlist_count;
};

struct source_aggregate {
    __be32 src;
    uint64_t short_unique;
    uint64_t long_unique;
    uint64_t short_attempts;
    uint64_t long_attempts;
    uint64_t earliest_ns;
    uint64_t latest_ns;
};

static volatile sig_atomic_t stop_flag;
static struct bpf_object *g_obj;
static int g_ifindex;
static __u32 g_xdp_flags;

static void on_signal(int sig)
{
    (void)sig;
    stop_flag = 1;
}

uint64_t recon_monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void iso_now(char *buf, size_t n)
{
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);
    snprintf(buf, n, "%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec);
}

static void usage(FILE *f, const char *argv0)
{
    fprintf(f,
        "Usage: %s --run-id ID --interface IF --object FILE --xdp-mode MODE "
        "--configuration C --selected-detector NAME [options]\n", argv0);
}

static int parse_u64(const char *s, uint64_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || !end || *end)
        return -1;
    *out = (uint64_t)v;
    return 0;
}

static int parse_u32(const char *s, uint32_t *out)
{
    uint64_t v;
    if (parse_u64(s, &v) || v > UINT32_MAX)
        return -1;
    *out = (uint32_t)v;
    return 0;
}

static int parse_double(const char *s, double *out)
{
    char *end = NULL;
    errno = 0;
    double v = strtod(s, &end);
    if (errno || !end || *end)
        return -1;
    *out = v;
    return 0;
}

static int parse_args(int argc, char **argv, struct config *c)
{
    memset(c, 0, sizeof(*c));
    c->poll_ms = 1000;
    c->telemetry_capacity = 4096;
    c->allowlist_capacity = 64;
    c->quarantine_capacity = 1024;

    enum {
        OPT_RUN_ID = 1000, OPT_INTERFACE, OPT_OBJECT, OPT_XDP_MODE,
        OPT_CONFIGURATION, OPT_SELECTED_DETECTOR, OPT_SHORT_WINDOW,
        OPT_LONG_WINDOW, OPT_RATE_WINDOW, OPT_SHORT_THRESHOLD,
        OPT_LONG_THRESHOLD, OPT_RATE_THRESHOLD, OPT_POLL_MS,
        OPT_QUARANTINE, OPT_COOLDOWN, OPT_CLEANUP_GRACE,
        OPT_TELEM_CAP, OPT_ALLOW_CAP, OPT_QUAR_CAP, OPT_CONTROLLER_CSV,
        OPT_STATS_CSV, OPT_PROBE_CSV, OPT_NFT_ADAPTER, OPT_ALLOWLIST_IP
    };
    static const struct option opts[] = {
        {"run-id", required_argument, 0, OPT_RUN_ID},
        {"interface", required_argument, 0, OPT_INTERFACE},
        {"object", required_argument, 0, OPT_OBJECT},
        {"xdp-mode", required_argument, 0, OPT_XDP_MODE},
        {"configuration", required_argument, 0, OPT_CONFIGURATION},
        {"selected-detector", required_argument, 0, OPT_SELECTED_DETECTOR},
        {"short-window-s", required_argument, 0, OPT_SHORT_WINDOW},
        {"long-window-s", required_argument, 0, OPT_LONG_WINDOW},
        {"rate-window-s", required_argument, 0, OPT_RATE_WINDOW},
        {"short-threshold", required_argument, 0, OPT_SHORT_THRESHOLD},
        {"long-threshold", required_argument, 0, OPT_LONG_THRESHOLD},
        {"rate-count-threshold", required_argument, 0, OPT_RATE_THRESHOLD},
        {"poll-ms", required_argument, 0, OPT_POLL_MS},
        {"quarantine-s", required_argument, 0, OPT_QUARANTINE},
        {"cooldown-s", required_argument, 0, OPT_COOLDOWN},
        {"cleanup-grace-s", required_argument, 0, OPT_CLEANUP_GRACE},
        {"telemetry-capacity", required_argument, 0, OPT_TELEM_CAP},
        {"allowlist-capacity", required_argument, 0, OPT_ALLOW_CAP},
        {"quarantine-capacity", required_argument, 0, OPT_QUAR_CAP},
        {"controller-csv", required_argument, 0, OPT_CONTROLLER_CSV},
        {"stats-csv", required_argument, 0, OPT_STATS_CSV},
        {"probe-csv", required_argument, 0, OPT_PROBE_CSV},
        {"nft-adapter", required_argument, 0, OPT_NFT_ADAPTER},
        {"allowlist-ip", required_argument, 0, OPT_ALLOWLIST_IP},
        {0,0,0,0}
    };

    int o;
    while ((o = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (o) {
        case OPT_RUN_ID: c->run_id = optarg; break;
        case OPT_INTERFACE: c->interface = optarg; break;
        case OPT_OBJECT: c->object_path = optarg; break;
        case OPT_XDP_MODE: c->xdp_mode = optarg; break;
        case OPT_CONFIGURATION: c->configuration = optarg; break;
        case OPT_SELECTED_DETECTOR: c->selected_detector = optarg; break;
        case OPT_SHORT_WINDOW: if (parse_double(optarg,&c->short_window_s)) return -1; break;
        case OPT_LONG_WINDOW: if (parse_double(optarg,&c->long_window_s)) return -1; break;
        case OPT_RATE_WINDOW: if (parse_double(optarg,&c->rate_window_s)) return -1; break;
        case OPT_SHORT_THRESHOLD: if (parse_u64(optarg,&c->short_threshold)) return -1; break;
        case OPT_LONG_THRESHOLD: if (parse_u64(optarg,&c->long_threshold)) return -1; break;
        case OPT_RATE_THRESHOLD: if (parse_u64(optarg,&c->rate_count_threshold)) return -1; break;
        case OPT_POLL_MS: { uint32_t v; if (parse_u32(optarg,&v)) return -1; c->poll_ms=v; } break;
        case OPT_QUARANTINE: if (parse_double(optarg,&c->quarantine_s)) return -1; break;
        case OPT_COOLDOWN: if (parse_double(optarg,&c->cooldown_s)) return -1; break;
        case OPT_CLEANUP_GRACE: if (parse_double(optarg,&c->cleanup_grace_s)) return -1; break;
        case OPT_TELEM_CAP: if (parse_u32(optarg,&c->telemetry_capacity)) return -1; break;
        case OPT_ALLOW_CAP: if (parse_u32(optarg,&c->allowlist_capacity)) return -1; break;
        case OPT_QUAR_CAP: if (parse_u32(optarg,&c->quarantine_capacity)) return -1; break;
        case OPT_CONTROLLER_CSV: c->controller_csv = optarg; break;
        case OPT_STATS_CSV: c->stats_csv = optarg; break;
        case OPT_PROBE_CSV: c->probe_csv = optarg; break;
        case OPT_NFT_ADAPTER: c->nft_adapter = optarg; break;
        case OPT_ALLOWLIST_IP:
            if (c->allowlist_count >= 64) return -1;
            c->allowlist_ips[c->allowlist_count++] = optarg;
            break;
        default: return -1;
        }
    }

    if (!c->run_id || !c->interface || !c->object_path || !c->xdp_mode ||
        !c->configuration || !c->selected_detector || !c->controller_csv ||
        !c->stats_csv || !c->probe_csv)
        return -1;
    return 0;
}

static __u32 xdp_flags_from_mode(const char *mode)
{
    if (!strcmp(mode, "native"))
        return XDP_FLAGS_DRV_MODE;
    if (!strcmp(mode, "generic"))
        return XDP_FLAGS_SKB_MODE;
    return 0;
}

static int set_map_capacity(struct bpf_object *obj, const char *name, uint32_t cap)
{
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if (!m) {
        fprintf(stderr, "map not found: %s\n", name);
        return -1;
    }
    if (bpf_map__set_max_entries(m, cap)) {
        fprintf(stderr, "failed setting max_entries for %s\n", name);
        return -1;
    }
    return 0;
}

static int open_load_attach(const struct config *c,
                            int *allow_fd, int *tele_fd, int *quar_fd, int *cnt_fd)
{
    struct bpf_program *prog;
    int prog_fd;

    g_obj = bpf_object__open_file(c->object_path, NULL);
    if (libbpf_get_error(g_obj)) {
        fprintf(stderr, "bpf_object__open_file failed\n");
        g_obj = NULL;
        return -1;
    }

    if (set_map_capacity(g_obj,"allowlist_map",c->allowlist_capacity) ||
        set_map_capacity(g_obj,"telemetry_map",c->telemetry_capacity) ||
        set_map_capacity(g_obj,"quarantine_map",c->quarantine_capacity))
        return -1;

    if (bpf_object__load(g_obj)) {
        fprintf(stderr, "bpf_object__load failed: %s\n", strerror(errno));
        return -1;
    }

    *allow_fd = bpf_object__find_map_fd_by_name(g_obj, "allowlist_map");
    *tele_fd  = bpf_object__find_map_fd_by_name(g_obj, "telemetry_map");
    *quar_fd  = bpf_object__find_map_fd_by_name(g_obj, "quarantine_map");
    *cnt_fd   = bpf_object__find_map_fd_by_name(g_obj, "counters_map");
    if (*allow_fd < 0 || *tele_fd < 0 || *quar_fd < 0 || *cnt_fd < 0) {
        fprintf(stderr, "required map fd missing\n");
        return -1;
    }

    prog = bpf_object__find_program_by_name(g_obj, "xdp_recon");
    if (!prog) {
        fprintf(stderr, "program xdp_recon not found\n");
        return -1;
    }
    prog_fd = bpf_program__fd(prog);
    g_ifindex = if_nametoindex(c->interface);
    if (!g_ifindex) {
        fprintf(stderr, "unknown interface: %s\n", c->interface);
        return -1;
    }
    g_xdp_flags = xdp_flags_from_mode(c->xdp_mode);
    if (!g_xdp_flags) {
        fprintf(stderr, "invalid xdp mode: %s\n", c->xdp_mode);
        return -1;
    }
    if (bpf_xdp_attach(g_ifindex, prog_fd, g_xdp_flags, NULL)) {
        fprintf(stderr, "bpf_xdp_attach failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static void detach_xdp(void)
{
    if (g_ifindex > 0 && g_xdp_flags)
        bpf_xdp_detach(g_ifindex, g_xdp_flags, NULL);
    if (g_obj) {
        bpf_object__close(g_obj);
        g_obj = NULL;
    }
}

static int populate_allowlist(int fd, const struct config *c)
{
    for (size_t i=0;i<c->allowlist_count;i++) {
        struct in_addr addr;
        if (inet_pton(AF_INET,c->allowlist_ips[i],&addr) != 1) {
            fprintf(stderr,"invalid allowlist ip: %s\n",c->allowlist_ips[i]);
            return -1;
        }
        struct ipv4_source_key key = {.source_ipv4 = addr.s_addr};
        struct allowlist_value val = {.flags = RECON_ALLOW_ADMIN};
        if (bpf_map_update_elem(fd,&key,&val,BPF_ANY)) {
            fprintf(stderr,"allowlist update failed: %s\n",strerror(errno));
            return -1;
        }
    }
    return 0;
}

static bool source_allowlisted(int fd, __be32 src)
{
    struct ipv4_source_key key = {.source_ipv4=src};
    struct allowlist_value v;
    return bpf_map_lookup_elem(fd,&key,&v) == 0;
}

static int read_telemetry_value(int fd, const struct recon_tuple_key *key,
                                struct recon_telemetry_value *v)
{
#ifdef BPF_F_LOCK
    if (bpf_map_lookup_elem_flags(fd,key,v,BPF_F_LOCK) == 0)
        return 0;
#endif
    return bpf_map_lookup_elem(fd,key,v);
}

static int read_quarantine_value(int fd, const struct ipv4_source_key *key,
                                 struct recon_quarantine_value *v)
{
#ifdef BPF_F_LOCK
    if (bpf_map_lookup_elem_flags(fd,key,v,BPF_F_LOCK) == 0)
        return 0;
#endif
    return bpf_map_lookup_elem(fd,key,v);
}

static int aggregate_for_source(int tele_fd, __be32 src, uint64_t now,
                                uint64_t short_ns, uint64_t long_ns,
                                struct source_aggregate *agg,
                                FILE *probe_csv, const char *run_id,
                                uint64_t sample_index)
{
    struct recon_tuple_key key, next;
    bool have = false;
    memset(agg,0,sizeof(*agg));
    agg->src = src;

    while (bpf_map_get_next_key(tele_fd, have ? &key : NULL, &next) == 0) {
        key = next;
        have = true;
        if (key.source_ipv4 != src)
            continue;

        struct recon_telemetry_value v;
        if (read_telemetry_value(tele_fd,&key,&v))
            continue;

        uint64_t age = now >= v.last_seen_ns ? now-v.last_seen_ns : 0;
        if (age <= long_ns) {
            agg->long_unique++;
            agg->long_attempts += v.attempts;
            if (!agg->earliest_ns || v.first_seen_ns < agg->earliest_ns)
                agg->earliest_ns = v.first_seen_ns;
            if (v.last_seen_ns > agg->latest_ns)
                agg->latest_ns = v.last_seen_ns;
        }
        if (age <= short_ns) {
            agg->short_unique++;
            agg->short_attempts += v.attempts;
        }

        if (probe_csv) {
            char ip[INET_ADDRSTRLEN];
            struct in_addr a = {.s_addr=key.source_ipv4};
            inet_ntop(AF_INET,&a,ip,sizeof(ip));
            fprintf(probe_csv,"%s,%llu,%s,%u,%u,%llu,%llu,%llu\n",
                    run_id,
                    (unsigned long long)sample_index,
                    ip,key.l4_protocol,key.destination_port,
                    (unsigned long long)v.first_seen_ns,
                    (unsigned long long)v.last_seen_ns,
                    (unsigned long long)v.attempts);
        }
    }
    return 0;
}

static int collect_sources(int tele_fd, __be32 *sources, size_t cap, size_t *n)
{
    struct recon_tuple_key key, next;
    bool have=false;
    *n=0;
    while (bpf_map_get_next_key(tele_fd,have?&key:NULL,&next)==0) {
        key=next; have=true;
        bool seen=false;
        for(size_t i=0;i<*n;i++) if(sources[i]==key.source_ipv4){seen=true;break;}
        if(!seen && *n<cap) sources[(*n)++]=key.source_ipv4;
    }
    return 0;
}

static bool detector_positive(const struct config *c, const struct source_aggregate *a,
                              bool *rate_pos, bool *short_pos, bool *long_pos)
{
    *rate_pos = a->short_attempts >= c->rate_count_threshold;
    *short_pos = a->short_unique >= c->short_threshold;
    *long_pos = a->long_unique >= c->long_threshold;
    if (!strcmp(c->selected_detector,"rate")) return *rate_pos;
    if (!strcmp(c->selected_detector,"short")) return *short_pos;
    if (!strcmp(c->selected_detector,"dual")) return *short_pos || *long_pos;
    return false;
}

static int install_xdp_quarantine(int fd, __be32 src, uint32_t reason,
                                  uint64_t now, uint64_t quarantine_ns)
{
    struct ipv4_source_key key={.source_ipv4=src};
    struct recon_quarantine_value v={};
    v.reason_code=reason;
    v.expiry_ns=now+quarantine_ns;
    return bpf_map_update_elem(fd,&key,&v,BPF_ANY);
}

static int remove_quarantine(int fd, __be32 src)
{
    struct ipv4_source_key key={.source_ipv4=src};
    if (bpf_map_delete_elem(fd,&key)==0 || errno==ENOENT)
        return 0;
    return -1;
}

static int run_nft_adapter(const struct config *c,
                           const char *action,
                           __be32 src,
                           uint64_t timeout_ms)
{
    if (!c || !c->nft_adapter || !action)
        return -1;

    char ip[INET_ADDRSTRLEN] = {0};
    char timeout_buf[32] = {0};
    struct in_addr ia = {.s_addr = src};

    if (src != 0 &&
        !inet_ntop(AF_INET, &ia, ip, sizeof(ip)))
        return -1;

    snprintf(timeout_buf, sizeof(timeout_buf), "%llu",
             (unsigned long long)timeout_ms);

    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        if (!strcmp(action, "init")) {
            execl(c->nft_adapter,
                  c->nft_adapter,
                  "init",
                  "--run-id", c->run_id,
                  (char *)NULL);
        } else if (!strcmp(action, "insert")) {
            execl(c->nft_adapter,
                  c->nft_adapter,
                  "insert",
                  "--run-id", c->run_id,
                  "--source", ip,
                  "--timeout-ms", timeout_buf,
                  (char *)NULL);
        } else if (!strcmp(action, "remove")) {
            execl(c->nft_adapter,
                  c->nft_adapter,
                  "remove",
                  "--run-id", c->run_id,
                  "--source", ip,
                  (char *)NULL);
        }

        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        return -1;
    }

    if (!WIFEXITED(status))
        return -1;

    return WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int install_nft_quarantine(const struct config *c,
                                  __be32 src,
                                  uint64_t quarantine_ns)
{
    uint64_t timeout_ms = quarantine_ns / 1000000ULL;

    if (timeout_ms == 0)
        timeout_ms = 1;

    return run_nft_adapter(c, "insert", src, timeout_ms);
}

static int remove_nft_quarantine(const struct config *c, __be32 src)
{
    return run_nft_adapter(c, "remove", src, 0);
}

static uint64_t sum_percpu_counter(int fd, uint32_t key)
{
    int ncpu=libbpf_num_possible_cpus();
    if(ncpu<=0) return 0;
    uint64_t *vals=calloc((size_t)ncpu,sizeof(*vals));
    if(!vals) return 0;
    uint64_t sum=0;
    if(bpf_map_lookup_elem(fd,&key,vals)==0)
        for(int i=0;i<ncpu;i++) sum+=vals[i];
    free(vals);
    return sum;
}

static void write_stats(FILE *f,const char *run_id,int cnt_fd,uint64_t sample)
{
    char iso[64]; iso_now(iso,sizeof(iso));
    uint64_t now=recon_monotonic_ns();
    fprintf(f,"%s,%llu,%s,%llu",
            run_id,(unsigned long long)sample,iso,(unsigned long long)now);
    for(uint32_t k=0;k<RECON_COUNTER_COUNT;k++)
        fprintf(f,",%llu",(unsigned long long)sum_percpu_counter(cnt_fd,k));
    fputc('\n',f); fflush(f);
}

int main(int argc,char **argv)
{
    struct config c;
    if(parse_args(argc,argv,&c)){
        usage(stderr,argv[0]);
        return 2;
    }

    signal(SIGINT,on_signal);
    signal(SIGTERM,on_signal);

    int allow_fd=-1,tele_fd=-1,quar_fd=-1,cnt_fd=-1;
    if(open_load_attach(&c,&allow_fd,&tele_fd,&quar_fd,&cnt_fd))
        return 3;
    if(populate_allowlist(allow_fd,&c)){
        detach_xdp();
        return 4;
    }

    if(!strcmp(c.configuration,"C4")){
        if(run_nft_adapter(&c,"init",0,0)!=0){
            fprintf(stderr,"failed to initialize C4 nftables adapter\n");
            detach_xdp();
            return 6;
        }
    }

    FILE *fc=fopen(c.controller_csv,"w");
    FILE *fs=fopen(c.stats_csv,"w");
    FILE *fp=fopen(c.probe_csv,"w");
    if(!fc||!fs||!fp){
        perror("fopen");
        if(fc)fclose(fc); if(fs)fclose(fs); if(fp)fclose(fp);
        detach_xdp(); return 5;
    }

    fprintf(fc,"run_id,sample_index,realtime_iso,mono_ns,src_ipv4,selected_detector,rate_count,short_unique_targets,long_unique_targets,short_attempts,long_attempts,rate_threshold,short_threshold,long_threshold,state_before,state_after,transition_reason,selected_enforcement,policy_action,policy_update_start_ns,policy_update_end_ns,policy_update_result,quarantine_expiry_ns,first_drop_ns,drop_count,controller_loop_us,telemetry_entries_seen,integrity_flags\n");
    fprintf(fs,"run_id,sample_index,realtime_iso,mono_ns,ipv4_packets,tcp_probe_candidates,udp_probe_candidates,allowlist_pass,active_quarantine_drop,expired_quarantine_pass,telemetry_update_ok,telemetry_insert_fail,attempt_saturated,unsupported,truncated,fragment,invalid_syn,map_errors,reserved14,reserved15\n");
    fprintf(fp,"run_id,sample_index,src_ipv4,protocol,destination_port,first_seen_ns,last_seen_ns,attempts\n");

    __be32 sources[4096];
    struct recon_state_ctx states[4096];
    __be32 state_src[4096];
    size_t state_n=0;
    memset(states,0,sizeof(states));

    uint64_t short_ns=(uint64_t)(c.short_window_s*1e9);
    uint64_t long_ns=(uint64_t)(c.long_window_s*1e9);
    uint64_t quarantine_ns=(uint64_t)(c.quarantine_s*1e9);
    uint64_t cooldown_ns=(uint64_t)(c.cooldown_s*1e9);
    uint64_t cleanup_grace_ns=(uint64_t)(c.cleanup_grace_s*1e9);
    uint64_t sample=0;

    while(!stop_flag){
        uint64_t loop_start=recon_monotonic_ns(), now=loop_start;
        size_t nsrc=0;
        collect_sources(tele_fd,sources,4096,&nsrc);

        for(size_t i=0;i<nsrc;i++){
            __be32 src=sources[i];
            size_t si=state_n;
            for(size_t j=0;j<state_n;j++) if(state_src[j]==src){si=j;break;}
            if(si==state_n && state_n<4096){
                state_src[state_n]=src;
                states[state_n].state=RECON_STATE_NORMAL;
                si=state_n++;
            }
            if(si>=4096) continue;

            struct source_aggregate a;
            aggregate_for_source(tele_fd,src,now,short_ns,long_ns,&a,NULL,NULL,sample);
            bool rp,sp,lp;
            bool pos=detector_positive(&c,&a,&rp,&sp,&lp);
            bool al=source_allowlisted(allow_fd,src);

            enum recon_state before=states[si].state;
            bool policy_installed=false, policy_failed=false;
            uint64_t pstart=0,pend=0,expiry=states[si].quarantine_expiry_ns;
            const char *action="NONE", *result="NOT_REQUESTED";

            struct recon_transition t=recon_state_step(&states[si],al,pos,now,
                                                       quarantine_ns,cooldown_ns,
                                                       false,false);
            if(t.request_policy_install){
                pstart=recon_monotonic_ns();
                action = !strcmp(c.configuration,"C2") ? "HYPOTHETICAL_APPLY" : "APPLY";
                if(!strcmp(c.configuration,"C2")){
                    result="NOT_EXECUTED";
                } else {
                    uint32_t reason = !strcmp(c.selected_detector,"rate") ?
                        RECON_Q_REASON_RATE :
                        (sp && lp ? RECON_Q_REASON_DUAL_BOTH :
                         sp ? RECON_Q_REASON_SHORT_DIVERSITY :
                              RECON_Q_REASON_LONG_DIVERSITY);
                    int install_rc;
                    if(!strcmp(c.configuration,"C4")){
                        install_rc=install_nft_quarantine(&c,src,quarantine_ns);
                    } else {
                        install_rc=install_xdp_quarantine(
                            quar_fd,src,reason,now,quarantine_ns);
                    }

                    if(install_rc==0){
                        policy_installed=true;
                        result="OK";
                        expiry=now+quarantine_ns;
                    } else {
                        policy_failed=true;
                        result="ERROR";
                    }
                }
                pend=recon_monotonic_ns();
                if(policy_installed || policy_failed)
                    t=recon_state_step(&states[si],al,pos,now,
                                       quarantine_ns,cooldown_ns,
                                       policy_installed,policy_failed);
            }

            /*
             * Snapshot kernel quarantine evidence before any requested
             * userspace removal.  XDP updates first_drop_ns and drop_count
             * while enforcement is active.
             */
            uint64_t first_drop_ns=0, drop_count=0;
            if(strcmp(c.configuration,"C2") &&
               strcmp(c.configuration,"C4")){
                struct ipv4_source_key qkey={.source_ipv4=src};
                struct recon_quarantine_value qv;
                memset(&qv,0,sizeof(qv));
                if(read_quarantine_value(quar_fd,&qkey,&qv)==0){
                    first_drop_ns=qv.first_drop_ns;
                    drop_count=qv.drop_count;
                    if(qv.expiry_ns)
                        expiry=qv.expiry_ns;
                }
            }

            /*
             * Logical expiry is enforced in XDP using expiry_ns.
             * Physical deletion is delayed by cleanup_grace_ns so an
             * expired stale entry can be observed passing packets.
             */
            if(!strcmp(c.configuration,"C4")){
                if(t.request_policy_remove){
                    action="REMOVE";
                    pstart=recon_monotonic_ns();

                    if(remove_nft_quarantine(&c,src)==0)
                        result="OK";
                    else
                        result="ERROR";

                    pend=recon_monotonic_ns();
                }
            }
            else if(strcmp(c.configuration,"C2")){
                struct ipv4_source_key cleanup_key={.source_ipv4=src};
                struct recon_quarantine_value cleanup_qv;
                memset(&cleanup_qv,0,sizeof(cleanup_qv));

                if(read_quarantine_value(
                        quar_fd,&cleanup_key,&cleanup_qv)==0){

                    bool remove_due=false;

                    if(t.request_policy_remove &&
                       cleanup_grace_ns==0){
                        remove_due=true;
                    }
                    else if(states[si].state==RECON_STATE_COOLDOWN &&
                            cleanup_qv.expiry_ns!=0 &&
                            now>=cleanup_qv.expiry_ns &&
                            now-cleanup_qv.expiry_ns>=cleanup_grace_ns){
                        remove_due=true;
                    }

                    if(remove_due){
                        action="REMOVE";
                        pstart=recon_monotonic_ns();

                        if(remove_quarantine(quar_fd,src)==0)
                            result="OK";
                        else
                            result="ERROR";

                        pend=recon_monotonic_ns();
                    }
                }
            }

            char ip[INET_ADDRSTRLEN],iso[64];
            struct in_addr ia={.s_addr=src};
            inet_ntop(AF_INET,&ia,ip,sizeof(ip));
            iso_now(iso,sizeof(iso));
            uint64_t loop_us=(recon_monotonic_ns()-loop_start)/1000ULL;
            fprintf(fc,"%s,%llu,%s,%llu,%s,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%s,%s,%s,%s,%llu,%llu,%s,%llu,%llu,%llu,%llu,%zu,%s\n",
                    c.run_id,(unsigned long long)sample,iso,(unsigned long long)now,ip,
                    c.selected_detector,
                    (unsigned long long)a.short_attempts,
                    (unsigned long long)a.short_unique,
                    (unsigned long long)a.long_unique,
                    (unsigned long long)a.short_attempts,
                    (unsigned long long)a.long_attempts,
                    (unsigned long long)c.rate_count_threshold,
                    (unsigned long long)c.short_threshold,
                    (unsigned long long)c.long_threshold,
                    recon_state_name(before),recon_state_name(states[si].state),
                    recon_transition_reason_name(t.reason),
                    !strcmp(c.configuration,"C4")?"NFT":
                    !strcmp(c.configuration,"C2")?"ALERT_ONLY":"XDP",
                    action,(unsigned long long)pstart,(unsigned long long)pend,result,
                    (unsigned long long)expiry,
                    (unsigned long long)first_drop_ns,
                    (unsigned long long)drop_count,
                    (unsigned long long)loop_us,nsrc,
                    states[si].integrity_fault?"POLICY_INSTALL_FAILURE":"");
        }

        /* Append snapshot first-seen evidence; analysis deduplicates by tuple. */
        for(size_t i=0;i<nsrc;i++){
            struct source_aggregate tmp;
            aggregate_for_source(tele_fd,sources[i],now,short_ns,long_ns,&tmp,fp,c.run_id,sample);
        }
        write_stats(fs,c.run_id,cnt_fd,sample++);
        fflush(fc); fflush(fp);

        struct timespec req={.tv_sec=c.poll_ms/1000,
                             .tv_nsec=(long)(c.poll_ms%1000)*1000000L};
        nanosleep(&req,NULL);
    }

    fclose(fc); fclose(fs); fclose(fp);
    detach_xdp();
    return 0;
}
