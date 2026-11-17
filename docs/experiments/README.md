# RiskShare prototype evaluation

Run `python scripts/run_experiments.py --trials 5` from the repository root to
write `results/riskshare-experiments.csv`, `results/riskshare-experiments.json`,
and `results/recovery-availability.svg`.

## Recorded run

The checked-in run contains five random cryptographic generations per threshold
and 25 deterministic availability/compromise scenarios per generation. Thus,
each policy has 125 rows. Times were collected on the development workstation
with Python 3.13 and the local OpenSSL/PyCA backend; they are measurements of
this prototype, not portable performance claims.

| Policy | Legitimate recoveries | Attacker reconstruction | Mean share generation | Mean successful reconstruction |
|---|---:|---:|---:|---:|
| Fixed 2-of-5 | 80% | 60% | 73.33 ms | 4.15 ms |
| Fixed 3-of-5 | 60% | 40% | 81.98 ms | 4.14 ms |
| Fixed 4-of-5 | 40% | 20% | 57.95 ms | 4.26 ms |
| Risk-adaptive | 48% | 20% | 65.56 ms | 4.11 ms |

The attack column counts only the scripted case where the first `k` nodes are
compromised and can pool their shares. It is not a probability estimate. The
adaptive detector inputs and node availability are scenario assumptions, not
field telemetry. The lower recovery rate under stricter thresholds reflects
the scenario's unavailable-node counts; the attacker column reflects the
chosen compromise counts. Generation time varies with random parameter sizes,
so these five trials are too small for conclusions about relative speed.

This runner measures key sharing/reconstruction, AES-GCM re-encryption during
rotation, availability, and the prototype trace routine. It does not measure
network latency, PostgreSQL/Redis throughput, concurrent workload, compromise
probability, or formal security. It should be treated as a reproducible smoke
evaluation, not a security evaluation.
