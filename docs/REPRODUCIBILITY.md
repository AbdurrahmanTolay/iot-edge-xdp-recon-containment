# Reproducibility Guide

This document describes how the public repository should map to the frozen experiment and manuscript evidence for **Bounded eBPF/XDP Service-Diversity Telemetry for Reconnaissance Containment at the IoT Edge**.

## Scope

The scientific unit is the physical MAIN run. The final quantitative analysis uses only the 124 accepted scientific MAIN runs identified by the frozen accepted-run registry.

Engineering preflights, calibration runs, failed original attempts, and other nonaccepted executions must not be mixed into the final scientific statistics. Failed originals remain part of provenance and their run identifiers are not reused.

## Runtime boundaries

All XDP-enabled MAIN runs use generic/SKB XDP on the Raspberry Pi 4 test gateway. Native-driver XDP was not evaluated.

The controller distinguishes detector-positive timing (`tD`), successful actual policy-installation completion (`tM`), and effective-enforcement evidence (`tE`). XDP `tE` is an exact kernel first-drop observation; nftables `tE` is interval-censored between counter-sampling endpoints.

## Detector semantics

C1 is the implemented cumulative-attempt comparator. It sums cumulative attempts for tuples whose latest observation remains within the short horizon and becomes positive at threshold 81. It must not be re-labelled as an exact sliding-window packet-rate estimator.

C2, C3, and C4 use the same dual-horizon service-diversity predicate: at least 5 distinct protocol/port tuples in the inclusive 5 s horizon OR at least 6 in the inclusive 30 s horizon.

## Exposure semantics

For a boundary `tB`, PCPE counts tuples in the intended target set that were gateway-observed strictly before `tB`. PCF divides PCPE by the full intended target-set size. Intended targets missing from telemetry under pressure remain in the PCF denominator and are not reconstructed.

Protocol/port targets are service proxies only; the metrics do not confirm open services or compromise.

## Bounded-state semantics

The telemetry map is fixed-capacity and non-LRU with 4096 entries. The MAIN controller performs no in-run stale-entry reclamation. Detector aging can remove a tuple from current horizon membership without releasing the telemetry-map entry.

Insertion failure is therefore meaningful scientific pressure evidence. In the S7L3 runs, positive saturation evidence occurred after the reported detection, installation, and effective-enforcement boundaries in every repetition; subsequent telemetry coverage was incomplete.

## Files that should be published

Upload the exact frozen files from the final project workspace rather than recreating them from console output or the manuscript. The release should include, where available:

- XDP source and headers;
- controller and state-machine source;
- nftables backend scripts and counter logger;
- workload-generation scripts/material;
- frozen parameters and implementation/runtime configuration;
- run-manifest schema;
- accepted scientific run registry;
- 124-row analysis-ready dataset;
- frozen final result layer;
- run-level PCPE/PCF layer;
- result/analysis metadata;
- figure/table source material;
- provenance/freeze manifests and SHA-256 records.

## Integrity check

Before tagging a release, compute SHA-256 digests over the uploaded scientific files and compare them with the recorded frozen digests. Any mismatch must be investigated rather than silently accepted.

The repository README currently lists the principal recorded digests. These are provenance records, not a substitute for re-hashing the uploaded files.

## Reproduction environment

The manuscript testbed used a Raspberry Pi 4 Model B Rev 1.1, aarch64, Linux 6.12.96+rpt-rpi-v8, bcmgenet Ethernet, bpffs mounted, `bpf.jit_enable=1`, `bpf.jit_harden=0`, and generic/SKB XDP. Kernel BTF vmlinux was unavailable.

A future public release should record build dependencies and exact commands from the frozen workspace. Do not infer or invent missing package versions.

## Archival release

After all exact artifacts are uploaded and verified, create a tagged GitHub release. If the repository is archived through Zenodo or another archival service, add the resulting DOI to `CITATION.cff` and the manuscript only after that DOI actually exists.
