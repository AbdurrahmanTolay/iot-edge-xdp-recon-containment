#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate deterministic blocked-randomized MAIN schedule."
    )
    p.add_argument("--matrix", type=Path, required=True)
    p.add_argument("--seed-record", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--metadata-output", type=Path, required=True)
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not args.matrix.is_file():
        raise SystemExit(f"missing matrix: {args.matrix}")

    if not args.seed_record.is_file():
        raise SystemExit(f"missing seed record: {args.seed_record}")

    rows = load_rows(args.matrix)

    if len(rows) != 124:
        raise SystemExit(
            f"expected 124 physical rows; found {len(rows)}"
        )

    seed_data = json.loads(
        args.seed_record.read_text(encoding="utf-8")
    )
    seed = int(seed_data["randomization_seed"])

    rng = random.Random(seed)

    # --------------------------------------------------------
    # Protect schedule from accidental overwrite.
    # The repository currently contains a header-only placeholder.
    # A populated schedule must never be overwritten.
    # --------------------------------------------------------
    if args.output.exists():
        existing = args.output.read_text(
            encoding="utf-8"
        ).strip().splitlines()

        if len(existing) > 1:
            raise SystemExit(
                f"REFUSE OVERWRITE: populated schedule exists: "
                f"{args.output}"
            )

    if args.metadata_output.exists():
        raise SystemExit(
            f"REFUSE OVERWRITE: metadata exists: "
            f"{args.metadata_output}"
        )

    by_key = {
        (
            r["scenario"],
            r["configuration"],
            int(r["repetition"])
        ): r
        for r in rows
    }

    if len(by_key) != 124:
        raise SystemExit(
            "duplicate scenario/configuration/repetition condition"
        )

    used: set[str] = set()
    blocks: list[dict] = []

    def take(scenario: str, config: str, rep: int) -> dict:
        key = (scenario, config, rep)

        if key not in by_key:
            raise SystemExit(f"missing physical condition: {key}")

        r = by_key[key]

        rid = r["physical_row_id"]

        if rid in used:
            raise SystemExit(
                f"physical row reused: {rid}"
            )

        used.add(rid)
        return r

    # ========================================================
    # A. Matched C1/C3/C4 blocks
    #
    # Same C3 run supports both comparisons:
    # C1 <-> C3 and C3 <-> C4.
    # Therefore each scenario/repetition forms a single
    # matched three-run block, randomized internally.
    # ========================================================
    for scenario in ("S1", "S3P3"):
        for rep in range(1, 6):
            members = [
                take(scenario, "C1", rep),
                take(scenario, "C3", rep),
                take(scenario, "C4", rep),
            ]

            rng.shuffle(members)

            blocks.append({
                "block_id":
                    f"MATCHED_{scenario}_R{rep:02d}",
                "block_type": "MATCHED_C1_C3_C4",
                "members": members,
            })

    # ========================================================
    # B. C0_T0 / C0_T1 overhead pairs
    # ========================================================
    for rep in range(1, 4):
        members = [
            take("S0A", "C0_T0", rep),
            take("S0A", "C0_T1", rep),
        ]

        rng.shuffle(members)

        blocks.append({
            "block_id": f"OVERHEAD_R{rep:02d}",
            "block_type": "MATCHED_C0",
            "members": members,
        })

    # ========================================================
    # C. C2 conditions
    #
    # Randomize within repetition and exact scan_s stratum.
    # Exact scan_s is used as the objective compatible-duration
    # stratum rather than inventing arbitrary short/medium bins.
    # ========================================================
    c2_groups = defaultdict(list)

    for r in rows:
        if r["configuration"] != "C2":
            continue

        key = (
            int(r["repetition"]),
            float(r["scan_s"])
        )

        if r["physical_row_id"] in used:
            raise SystemExit(
                f"unexpected reused C2 row: "
                f'{r["physical_row_id"]}'
            )

        used.add(r["physical_row_id"])
        c2_groups[key].append(r)

    for (rep, scan_s), members in sorted(c2_groups.items()):
        rng.shuffle(members)

        scan_label = str(scan_s).replace(".", "p")

        blocks.append({
            "block_id":
                f"C2_R{rep:02d}_SCAN_{scan_label}",
            "block_type": "C2_DURATION_STRATUM",
            "members": members,
        })

    # ========================================================
    # D. S7 pressure blocks.
    #
    # Internal order MUST remain L1 -> L2 -> L3.
    # Only placement of the repetition block is randomized.
    # ========================================================
    for rep in range(1, 4):
        members = [
            take("S7L1", "C3", rep),
            take("S7L2", "C3", rep),
            take("S7L3", "C3", rep),
        ]

        blocks.append({
            "block_id": f"S7_R{rep:02d}",
            "block_type": "S7_ASCENDING",
            "members": members,
        })

    # ========================================================
    # E. Remaining standalone C3 physical runs
    # ========================================================
    remaining = [
        r for r in rows
        if r["physical_row_id"] not in used
    ]

    for r in remaining:
        if r["configuration"] != "C3":
            raise SystemExit(
                "unexpected unassigned physical row: "
                f'{r["physical_row_id"]} '
                f'{r["scenario"]} '
                f'{r["configuration"]}'
            )

        used.add(r["physical_row_id"])

        blocks.append({
            "block_id":
                f'STANDALONE_{r["scenario"]}_'
                f'R{int(r["repetition"]):02d}',
            "block_type": "STANDALONE_C3",
            "members": [r],
        })

    if len(used) != 124:
        raise SystemExit(
            f"assigned {len(used)} physical rows, expected 124"
        )

    # --------------------------------------------------------
    # Global block randomization.
    #
    # Internal constraints have already been established.
    # --------------------------------------------------------
    rng.shuffle(blocks)

    schedule = []
    order = 0

    for block in blocks:
        for member_index, r in enumerate(
            block["members"], start=1
        ):
            order += 1

            scenario = r["scenario"]
            config = r["configuration"]
            rep = int(r["repetition"])

            run_id = (
                f"RECON_20260908_PI_MAIN_"
                f"{scenario}_{config}_R{rep:02d}"
            )

            schedule.append({
                "schedule_order": order,
                "run_id": run_id,
                "physical_row_id":
                    r["physical_row_id"],
                "randomization_block":
                    block["block_id"],
                "block_type":
                    block["block_type"],
                "block_member_order":
                    member_index,
                "random_seed": seed,
                "phase": "MAIN",
                "scenario": scenario,
                "scenario_point":
                    r["scenario_point"],
                "configuration": config,
                "repetition": rep,
                "target_manifest":
                    r["target_manifest"],
                "target_manifest_sha256":
                    r["target_manifest_sha256"],
                "freeze_version":
                    "MAIN_FREEZE_V1_20260908",
                "notes":
                    r["matrix_group"],
            })

    if len(schedule) != 124:
        raise SystemExit(
            f"schedule length {len(schedule)} != 124"
        )

    run_ids = [r["run_id"] for r in schedule]

    if len(run_ids) != len(set(run_ids)):
        raise SystemExit("duplicate run_id generated")

    physical_ids = [
        r["physical_row_id"]
        for r in schedule
    ]

    if len(physical_ids) != len(set(physical_ids)):
        raise SystemExit(
            "duplicate physical row in schedule"
        )

    # --------------------------------------------------------
    # Verify S7 order after global randomization.
    # --------------------------------------------------------
    for rep in range(1, 4):
        s7 = [
            r for r in schedule
            if r["randomization_block"]
            == f"S7_R{rep:02d}"
        ]

        actual = [r["scenario"] for r in s7]

        if actual != ["S7L1", "S7L2", "S7L3"]:
            raise SystemExit(
                f"S7 ordering violation R{rep}: {actual}"
            )

    fields = [
        "schedule_order",
        "run_id",
        "physical_row_id",
        "randomization_block",
        "block_type",
        "block_member_order",
        "random_seed",
        "phase",
        "scenario",
        "scenario_point",
        "configuration",
        "repetition",
        "target_manifest",
        "target_manifest_sha256",
        "freeze_version",
        "notes",
    ]

    args.output.parent.mkdir(
        parents=True, exist_ok=True
    )

    with args.output.open(
        "w", newline="", encoding="utf-8"
    ) as f:
        w = csv.DictWriter(
            f, fieldnames=fields
        )
        w.writeheader()
        w.writerows(schedule)

    metadata = {
        "schedule_version":
            "MAIN_SCHEDULE_V1_20260908",
        "status": "PRE_MAIN_FROZEN",
        "matrix_path": str(args.matrix),
        "matrix_sha256":
            sha256(args.matrix),
        "seed_record_path":
            str(args.seed_record),
        "seed_record_sha256":
            sha256(args.seed_record),
        "randomization_seed": seed,
        "generator_path":
            str(Path(__file__).resolve().relative_to(ROOT)),
        "generator_sha256":
            sha256(Path(__file__).resolve()),
        "schedule_path":
            str(args.output),
        "schedule_sha256":
            sha256(args.output),
        "physical_runs": 124,
        "block_count": len(blocks),
        "rules": [
            "C1/C3/C4 share one matched block per S1 or S3P3 repetition.",
            "Configuration order inside each matched C1/C3/C4 block is randomized.",
            "C0_T0/C0_T1 are paired by repetition and randomized internally.",
            "C2 conditions are randomized within repetition and exact scan_s strata.",
            "S7 remains L1-L2-L3 inside each repetition block.",
            "Global block placement is randomized.",
            "Each physical row appears exactly once."
        ],
        "governance_note": (
            "Generated before any MAIN physical run "
            "using the frozen deterministic seed."
        )
    }

    args.metadata_output.write_text(
        json.dumps(
            metadata,
            indent=2,
            sort_keys=True
        ) + "\n",
        encoding="utf-8"
    )

    print(f"SCHEDULE_ROWS={len(schedule)}")
    print(f"BLOCKS={len(blocks)}")
    print(f"SEED={seed}")
    print(
        f"SCHEDULE_SHA256={sha256(args.output)}"
    )
    print(
        f"METADATA_SHA256="
        f"{sha256(args.metadata_output)}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
