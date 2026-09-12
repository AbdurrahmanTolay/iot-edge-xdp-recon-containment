#include "state_machine.h"

static struct recon_transition tr(enum recon_state before, enum recon_state after,
                                  enum recon_transition_reason reason,
                                  bool install, bool remove)
{
    struct recon_transition out = {
        .before = before,
        .after = after,
        .reason = reason,
        .request_policy_install = install,
        .request_policy_remove = remove,
    };
    return out;
}

struct recon_transition recon_state_step(
    struct recon_state_ctx *ctx,
    bool allowlisted,
    bool detector_positive,
    uint64_t now_ns,
    uint64_t quarantine_ns,
    uint64_t cooldown_ns,
    bool policy_installed,
    bool policy_install_failed)
{
    enum recon_state before = ctx->state;

    if (allowlisted) {
        ctx->state = RECON_STATE_NORMAL;
        ctx->quarantine_expiry_ns = 0;
        ctx->cooldown_until_ns = 0;
        return tr(before, ctx->state, RECON_TR_ALLOWLIST_OVERRIDE, false, true);
    }

    if (policy_install_failed) {
        ctx->integrity_fault = true;
        ctx->state = RECON_STATE_SUSPECT;
        return tr(before, ctx->state, RECON_TR_POLICY_INSTALL_FAILED, false, false);
    }

    if (before == RECON_STATE_NORMAL && detector_positive) {
        ctx->state = RECON_STATE_SUSPECT;
        return tr(before, ctx->state, RECON_TR_DETECTOR_POSITIVE, true, false);
    }

    if (before == RECON_STATE_SUSPECT) {
        if (policy_installed) {
            ctx->state = RECON_STATE_QUARANTINED;
            ctx->quarantine_expiry_ns = now_ns + quarantine_ns;
            return tr(before, ctx->state, RECON_TR_POLICY_INSTALLED, false, false);
        }
        if (!detector_positive) {
            ctx->state = RECON_STATE_NORMAL;
            return tr(before, ctx->state, RECON_TR_NONE, false, false);
        }
    }

    if (before == RECON_STATE_QUARANTINED &&
        ctx->quarantine_expiry_ns != 0 &&
        now_ns >= ctx->quarantine_expiry_ns) {
        ctx->state = RECON_STATE_COOLDOWN;
        ctx->cooldown_until_ns = now_ns + cooldown_ns;
        return tr(before, ctx->state, RECON_TR_QUARANTINE_EXPIRED, false, true);
    }

    if (before == RECON_STATE_COOLDOWN && now_ns >= ctx->cooldown_until_ns) {
        if (detector_positive) {
            ctx->state = RECON_STATE_SUSPECT;
            return tr(before, ctx->state, RECON_TR_COOLDOWN_POSITIVE, true, false);
        }
        ctx->state = RECON_STATE_NORMAL;
        return tr(before, ctx->state, RECON_TR_COOLDOWN_NEGATIVE, false, false);
    }

    return tr(before, ctx->state, RECON_TR_NONE, false, false);
}

const char *recon_state_name(enum recon_state state)
{
    switch (state) {
    case RECON_STATE_NORMAL: return "NORMAL";
    case RECON_STATE_SUSPECT: return "SUSPECT";
    case RECON_STATE_QUARANTINED: return "QUARANTINED";
    case RECON_STATE_COOLDOWN: return "COOLDOWN";
    default: return "UNKNOWN";
    }
}

const char *recon_transition_reason_name(enum recon_transition_reason reason)
{
    switch (reason) {
    case RECON_TR_NONE: return "NONE";
    case RECON_TR_DETECTOR_POSITIVE: return "DETECTOR_POSITIVE";
    case RECON_TR_POLICY_INSTALLED: return "POLICY_INSTALLED";
    case RECON_TR_POLICY_INSTALL_FAILED: return "POLICY_INSTALL_FAILED";
    case RECON_TR_QUARANTINE_EXPIRED: return "QUARANTINE_EXPIRED";
    case RECON_TR_COOLDOWN_NEGATIVE: return "COOLDOWN_NEGATIVE";
    case RECON_TR_COOLDOWN_POSITIVE: return "COOLDOWN_POSITIVE";
    case RECON_TR_ALLOWLIST_OVERRIDE: return "ALLOWLIST_OVERRIDE";
    default: return "UNKNOWN";
    }
}
