#ifndef IOT_RECON_STATE_MACHINE_H
#define IOT_RECON_STATE_MACHINE_H

#include <stdbool.h>
#include <stdint.h>

enum recon_state {
    RECON_STATE_NORMAL = 0,
    RECON_STATE_SUSPECT,
    RECON_STATE_QUARANTINED,
    RECON_STATE_COOLDOWN
};

enum recon_transition_reason {
    RECON_TR_NONE = 0,
    RECON_TR_DETECTOR_POSITIVE,
    RECON_TR_POLICY_INSTALLED,
    RECON_TR_POLICY_INSTALL_FAILED,
    RECON_TR_QUARANTINE_EXPIRED,
    RECON_TR_COOLDOWN_NEGATIVE,
    RECON_TR_COOLDOWN_POSITIVE,
    RECON_TR_ALLOWLIST_OVERRIDE
};

struct recon_state_ctx {
    enum recon_state state;
    uint64_t quarantine_expiry_ns;
    uint64_t cooldown_until_ns;
    bool integrity_fault;
};

struct recon_transition {
    enum recon_state before;
    enum recon_state after;
    enum recon_transition_reason reason;
    bool request_policy_install;
    bool request_policy_remove;
};

struct recon_transition recon_state_step(
    struct recon_state_ctx *ctx,
    bool allowlisted,
    bool detector_positive,
    uint64_t now_ns,
    uint64_t quarantine_ns,
    uint64_t cooldown_ns,
    bool policy_installed,
    bool policy_install_failed);

const char *recon_state_name(enum recon_state state);
const char *recon_transition_reason_name(enum recon_transition_reason reason);

#endif
