# Release Checklist

Use this checklist before the repository URL is added to the manuscript Data and Code Availability statement.

- [ ] Upload exact frozen XDP source files.
- [ ] Upload exact frozen controller/state-machine source files.
- [ ] Upload exact nftables backend and counter-logging scripts used by MAIN.
- [ ] Upload exact workload-generation material used for the scientific campaign.
- [ ] Upload frozen scientific parameter/configuration files.
- [ ] Upload `implementation_freeze_v2.json`.
- [ ] Upload the run-manifest schema.
- [ ] Upload `main_accepted_scientific_runs_v1.csv` (124 accepted runs).
- [ ] Upload `main_analysis_ready_v1.csv` (124 rows).
- [ ] Upload `final_results_v1.csv` (376 rows).
- [ ] Upload `final_pcpe_pcf_runlevel_v1.csv` (98 rows).
- [ ] Upload corresponding analysis/result metadata.
- [ ] Preserve failed-original provenance and unreused run identifiers.
- [ ] Keep engineering preflights and calibration data clearly separate from accepted MAIN statistics.
- [ ] Upload figure/table source material where available.
- [ ] Recompute SHA-256 over every frozen scientific artifact after upload.
- [ ] Compare all recomputed digests against recorded project provenance.
- [ ] Investigate every mismatch; do not silently rewrite provenance.
- [ ] Confirm no secrets, credentials, private keys, tokens, or unrelated personal files are present.
- [ ] Confirm README wording matches the final manuscript.
- [ ] Choose and add an explicit software/data license before archival release.
- [ ] Create a tagged GitHub release only after the integrity audit passes.
- [ ] Optionally archive the release with Zenodo or another permanent archive.
- [ ] Add an archival DOI only after it exists.
- [ ] Only then add the verified repository/archival URL to the manuscript.

## Release gate

The repository should not be described as the final reproducibility package until the exact frozen implementation, accepted-run registry, analysis-ready data, final result layers, and provenance manifests are uploaded and hash-verified.
