#ifndef IOT_RECON_CONTROLLER_H
#define IOT_RECON_CONTROLLER_H

#include <stdint.h>

enum recon_detector_kind {
    DETECTOR_NONE = 0,
    DETECTOR_RATE,
    DETECTOR_SHORT,
    DETECTOR_DUAL
};

enum recon_enforcement_kind {
    ENFORCEMENT_NONE = 0,
    ENFORCEMENT_ALERT_ONLY,
    ENFORCEMENT_XDP,
    ENFORCEMENT_NFT
};

uint64_t recon_monotonic_ns(void);

#endif
