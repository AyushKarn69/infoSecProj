"""Collect fixed-threshold and risk-adaptive prototype measurements.

This runner exercises the actual crypto modules. Results are simulation data,
not formal secrecy or security proofs. Generated output includes row-level CSV,
summary JSON, and a small standalone SVG availability chart.
"""

from __future__ import annotations

import argparse
import csv
import json
import secrets
import statistics
import time
from pathlib import Path

from core.crypto.abss.abss_i import reconstruct
from core.crypto.encryption.aes_gcm import decrypt, encrypt, generate_dek
from core.crypto.ttss.ttss_i import EmbeddedShareBox
from core.crypto.ttss.ttss_ii import TTSSIIShareSet, share_ii, trace_ii

POLICIES = ("fixed-2-of-5", "fixed-3-of-5", "fixed-4-of-5", "risk-adaptive")


def measure_generation(threshold: int) -> tuple[TTSSIIShareSet, int, float, int]:
    secret = int.from_bytes(secrets.token_bytes(32), "big")
    started = time.perf_counter_ns()
    generation = share_ii(secret, n=5, threshold=threshold)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    serialized_bytes = sum(
        (share.modulus.bit_length() + 7) // 8
        + sum((residue.bit_length() + 7) // 8 for residue in share.residues)
        for share in generation.shares
    )
    return generation, secret, elapsed_ms, serialized_bytes


def measured_rotation(threshold: int) -> float:
    old_key = generate_dek()
    old_payload = encrypt(
        old_key, b"RiskShare evaluation payload", vault_id="experiment", epoch_id="before"
    )
    started = time.perf_counter_ns()
    plaintext = decrypt(old_key, old_payload)
    new_key = generate_dek()
    encrypt(new_key, plaintext, vault_id="experiment", epoch_id="after")
    share_ii(int.from_bytes(new_key, "big"), n=5, threshold=threshold)
    return (time.perf_counter_ns() - started) / 1_000_000


def choose_adaptive_threshold(compromised: int, unavailable: int) -> tuple[int, int]:
    # Scenario detector inputs are labeled assumptions: +20 per simulated
    # suspicious recovery indicator and +15 per missed heartbeat.
    score = min(100, compromised * 20 + unavailable * 15)
    return (2 if score < 30 else 3 if score < 60 else 4), score


def run(trials: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for trial in range(trials):
        generations = {threshold: measure_generation(threshold) for threshold in (2, 3, 4)}
        rotation_latency = {threshold: measured_rotation(threshold) for threshold in (2, 3, 4)}
        trace_cache: dict[tuple[int, int], tuple[float | None, bool | None]] = {}
        for unavailable in range(5):
            online_ids = tuple(range(1, 6 - unavailable))
            for compromised in range(5):
                adaptive_threshold, risk_score = choose_adaptive_threshold(compromised, unavailable)
                for policy in POLICIES:
                    threshold = (
                        int(policy.split("-")[1].split("-")[0])
                        if policy != "risk-adaptive"
                        else adaptive_threshold
                    )
                    generation, secret, generation_ms, share_bytes = generations[threshold]
                    available_ids = online_ids[:threshold]
                    recovery_ok = len(online_ids) >= threshold
                    recovery_ms: float | None = None
                    if recovery_ok:
                        started = time.perf_counter_ns()
                        recovered = reconstruct(
                            generation.parameters,
                            [generation.shares[index - 1] for index in available_ids],
                        )
                        recovery_ms = (time.perf_counter_ns() - started) / 1_000_000
                        if recovered != secret:
                            raise AssertionError(
                                "legitimate reconstruction returned the wrong secret"
                            )

                    compromised_ids = tuple(range(1, compromised + 1))
                    attacker_reconstruction = False
                    if len(compromised_ids) >= threshold:
                        attacker_secret = reconstruct(
                            generation.parameters,
                            [generation.shares[index - 1] for index in compromised_ids[:threshold]],
                        )
                        attacker_reconstruction = attacker_secret == secret

                    trace_ms: float | None = None
                    trace_correct: bool | None = None
                    trace_count = min(compromised, threshold - 1)
                    if trace_count:
                        cache_key = (threshold, compromised)
                        if cache_key not in trace_cache:
                            fixed = tuple(
                                generation.shares[index - 1] for index in range(1, trace_count + 1)
                            )
                            box = EmbeddedShareBox(
                                generation.parameters, generation.parameters.a1, fixed
                            )
                            started = time.perf_counter_ns()
                            traced = trace_ii(generation, box, trace_count, max_queries=64)
                            elapsed = (time.perf_counter_ns() - started) / 1_000_000
                            correct = traced is not None and traced[0] == frozenset(
                                compromised_ids[:trace_count]
                            )
                            trace_cache[cache_key] = (elapsed, correct)
                        trace_ms, trace_correct = trace_cache[cache_key]

                    rows.append(
                        {
                            "trial": trial,
                            "policy": policy,
                            "unavailable_nodes": unavailable,
                            "compromised_nodes": compromised,
                            "risk_score": risk_score if policy == "risk-adaptive" else None,
                            "threshold": threshold,
                            "legitimate_recovery_success": recovery_ok,
                            "legitimate_recovery_ms": recovery_ms,
                            "attacker_reconstruction": attacker_reconstruction,
                            "share_generation_ms": generation_ms,
                            "share_bytes_total": share_bytes,
                            "rotation_ms": rotation_latency[threshold],
                            "trace_ms": trace_ms,
                            "trace_correct": trace_correct,
                        }
                    )
    return rows


def summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    summaries = []
    for policy in POLICIES:
        selected = [row for row in rows if row["policy"] == policy]
        successful = sum(bool(row["legitimate_recovery_success"]) for row in selected)
        attacker_success = sum(bool(row["attacker_reconstruction"]) for row in selected)
        generation_ms = [float(row["share_generation_ms"]) for row in selected]
        recovery_ms = [
            float(row["legitimate_recovery_ms"])
            for row in selected
            if row["legitimate_recovery_ms"] is not None
        ]
        summaries.append(
            {
                "policy": policy,
                "scenarios": len(selected),
                "legitimate_recovery_rate": successful / len(selected),
                "attacker_reconstruction_rate": attacker_success / len(selected),
                "mean_share_generation_ms": statistics.fmean(generation_ms),
                "mean_successful_recovery_ms": statistics.fmean(recovery_ms)
                if recovery_ms
                else None,
            }
        )
    return summaries


def write_chart(summary: list[dict[str, object]], target: Path) -> None:
    width, height, left, top = 780, 360, 70, 40
    chart_width, chart_height = 650, 250
    bars = []
    for index, item in enumerate(summary):
        value = float(item["legitimate_recovery_rate"])
        x = left + index * 155 + 18
        bar_height = value * chart_height
        bars.append(
            f'<rect x="{x}" y="{top + chart_height - bar_height:.1f}" '
            f'width="88" height="{bar_height:.1f}" rx="5" fill="#55c9d8"/>'
            f'<text x="{x + 44}" y="{top + chart_height + 24}" '
            f'text-anchor="middle" fill="#a9bbc4" font-size="12">{item["policy"]}</text>'
            f'<text x="{x + 44}" y="{top + chart_height - bar_height - 8:.1f}" '
            f'text-anchor="middle" fill="#e5eef2" font-size="12">{value:.0%}</text>'
        )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">'
        '<rect width="100%" height="100%" fill="#071017"/>'
        '<text x="70" y="24" fill="#e5eef2" font-size="16">'
        'Legitimate recovery success across executed scenarios</text>'
        f'<path d="M{left} {top}V{top + chart_height}H{left + chart_width}" '
        'stroke="#31505e" fill="none"/>'
        + "".join(bars)
        + "</svg>"
    )
    target.write_text(svg, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--output", type=Path, default=Path("docs/experiments/results"))
    args = parser.parse_args()
    if args.trials < 1 or args.trials > 100:
        parser.error("--trials must be between 1 and 100")
    args.output.mkdir(parents=True, exist_ok=True)
    rows = run(args.trials)
    summary = summarize(rows)
    fields = list(rows[0])
    with (args.output / "riskshare-experiments.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    (args.output / "riskshare-experiments.json").write_text(
        json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf-8"
    )
    write_chart(summary, args.output / "recovery-availability.svg")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
