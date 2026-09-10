# Bounded eBPF/XDP Service-Diversity Telemetry for Reconnaissance Containment at the IoT Edge

This repository is the reproducibility package for the manuscript:

> **Bounded eBPF/XDP Service-Diversity Telemetry for Reconnaissance Containment at the IoT Edge**

**Author:** Abdurrahman Tolay  
**Affiliation:** Department of Computer Engineering, Graduate Education Institute, Istinye University, Türkiye

## Overview

This work evaluates gateway-resident reconnaissance containment using bounded eBPF/XDP telemetry, source-level temporal aggregation, dual-horizon service-diversity detection, and reversible time-limited quarantine on a Raspberry Pi 4 IoT edge gateway.

The scientific campaign contains **124 accepted physical MAIN runs** covering fast and paced reconnaissance, TCP/UDP and mixed-protocol probing, targeted-service variants, benign diversity, legitimate IoT service checks, alternative enforcement backends, and bounded telemetry-state pressure.

The repository is intended to preserve implementation, experiment, analysis, and provenance artifacts used by the manuscript. It does **not** claim that the evaluated Raspberry Pi platform, detector thresholds, or backend timings generalize to all IoT gateways or reconnaissance strategies.

## Main evaluated configurations

- **C0_T0:** no XDP attachment and no reconnaissance controller; application/resource monitoring only.
- **C0_T1:** generic/SKB XDP plus telemetry/controller monitoring with the dual detector selected; no policy action occurred in the accepted benign S0A runs.
- **C1:** implemented cumulative-attempt comparator plus XDP quarantine. This is **not** an exact sliding-window packet-rate estimator.
- **C2:** dual-horizon service-diversity detector in alert/hypothetical mode; no actual policy installation.
- **C3:** the same dual-horizon detector plus XDP quarantine.
- **C4:** the same dual-horizon detector plus timed **nftables local-input** quarantine; no XDP quarantine installation.

All XDP-enabled scientific MAIN runs used **generic/SKB XDP**. Native-driver XDP performance was not evaluated.

## Frozen detector parameters

The dual-horizon detector counts distinct `(transport protocol, destination port)` tuples per source IPv4 using inclusive horizons:

- short horizon: **5 s**, threshold **5**
- long horizon: **30 s**, threshold **6**
- trigger: `short >= 5 OR long >= 6`

C1 uses the implemented cumulative-attempt comparator with threshold **81** and a nominal 5 s reference. Its implementation semantics must not be interpreted as a generic packet-rate detector.

Source IPv4 is an operational grouping key, not authenticated identity.

## Containment timing

The manuscript separates four gateway-local timing boundaries:

- `t0`: earliest qualifying gateway-observed scanner probe
- `tD`: earliest selected detector-positive controller event
- `tM`: first successful actual policy-installation completion
- `tE`: effective-enforcement evidence

For XDP, `tE` is an exact kernel first-drop timestamp. For nftables, effective enforcement is interval-censored between counter-sampling endpoints. No midpoint is substituted as an exact event.

## Pre-Containment Exposure metrics

For each run, `A` is the full pre-specified intended attack-target set and `G` is the set of gateway-observed scanner tuples. Only `A ∩ G` can contribute to exposure.

**PCPE** counts intended protocol/port tuples first observed strictly before a containment boundary. **PCF** divides PCPE by the full intended-target-set size `|A|`, including intended targets that were not observed under pressure.

PCPE/PCF quantify intended-target exposure. They do **not** measure confirmed open services, successful application interaction, or compromise.

## Key frozen results

### Matched detector comparison

Ten C1/C3 pairs were matched across S1 and S3P3 by scenario, repetition, and random seed:

- C1 detected: **0/10**
- C3 detected: **10/10**
- exact two-sided McNemar: **p = 0.001953125**

This result applies to the implemented comparators and matched workloads only.

### Matched enforcement-path comparison

Across ten matched C3/C4 pairs, the tested nftables adapter/path added a mean **302.192 ms** to detector-to-installation time relative to direct XDP map-based installation.

- 95% paired-bootstrap CI for the mean difference: **286.596–317.941 ms**
- all 10/10 paired differences were positive
- exact two-sided sign-test: **p = 0.001953125**

This is an integration-path result, not an intrinsic nftables timing bound.

### Bounded-state pressure

The telemetry map is a fixed-capacity, non-LRU hash with **4096 entries** and no in-run stale-entry reclamation. In S7L3, first positive saturation evidence occurred after `tD`, `tM`, and `tE` in all three repetitions. The reported containment boundaries therefore remained usable, while subsequent telemetry coverage became incomplete.

## Scientific-run governance

The campaign contains **124 accepted physical scientific MAIN runs**. Two failed original attempts were preserved with unreused identifiers, and accepted retries received distinct identifiers. Failed originals, engineering preflights, calibration runs, and other nonaccepted executions are excluded from final scientific statistics.

The accepted-run registry controls quantitative eligibility.

## Recorded provenance digests

The following SHA-256 values are copied from the frozen project record. They should be re-verified against uploaded files before a tagged archival release.

| Artifact | Recorded SHA-256 |
|---|---|
| Frozen scientific parameters | `f506c2d0477c32097cf9a4bedb919b1a6d4e28a1823a0d5dbd2d37d0d2b627ef` |
| Accepted-run registry | `f3b8ad46b89252a1673c49b2129dd4d5ab6431045c5297c310e4bc7630fc7dca` |
| Analysis-ready dataset | `f660090aa2c6abee1f193529bf467cbc6b815a9e51a00a6baabc3badb057dbc4` |
| Final result layer | `e5dfd4ff20f5aad5d5f1212633a4120fa7269eead6cd36be3350b08723ec4697` |
| Run-level PCPE/PCF layer | `e814cd3a49bd0b6768651bb94a92c9ac67895519ebffb84c4f95113d184e6b15` |
| MAIN implementation freeze v2 | `c0f2db9e5732645da2da9c89b4798f82c6d54ff1ee85ac78fb906cfcbdfbaabc` |
| Runtime configuration | `fb7bbddc3acd46331658376f7d518024d30eb936b05e2710b86a5e1140d1686a` |
| Run-manifest schema | `89fd0e953105b50d366aaadc28a08729b5890fad6a272f0d158c1f0835cfce36` |

## Intended repository structure

```text
implementation/    frozen XDP, controller, and backend source
workloads/         frozen workload-generation material
configs/           frozen experiment/configuration material
data/              accepted-run registry and analysis-ready data
results/           frozen final result layers
provenance/        freeze manifests and SHA-256 records
figures/           figure/table source material where available
docs/              reproducibility and release documentation
```

Only the exact frozen files used for the manuscript should be uploaded. Source code or scientific evidence must **not** be reconstructed from manuscript prose or old console logs.

## Repository status

This repository is currently being populated from the frozen project workspace. Until the exact scientific files and provenance manifests are uploaded and hash-verified, treat this repository as **release preparation**, not the final archival package.

## Citation

Citation metadata are provided in `CITATION.cff`. A journal DOI or archival repository DOI will be added only after one exists; none is invented here.
