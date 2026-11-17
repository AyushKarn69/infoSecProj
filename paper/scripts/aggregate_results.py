"""Aggregate docs/experiments/results CSV into small pgfplots tables (stdlib only)."""
from __future__ import annotations
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "docs/experiments/results/riskshare-experiments.csv"
OUT = ROOT / "paper/data"
POL = ["fixed-2-of-5", "fixed-3-of-5", "fixed-4-of-5", "risk-adaptive"]
LBL = {"fixed-2-of-5": "Fixed2", "fixed-3-of-5": "Fixed3", "fixed-4-of-5": "Fixed4", "risk-adaptive": "Adaptive"}
rows = list(csv.DictReader(SRC.open(encoding="utf-8")))
f = lambda r, k: float(r[k]) if r[k] not in ("", "None") else None
t = lambda r, k: r[k] == "True"

def sd(x): return st.stdev(x) if len(x) > 1 else 0.0

with (OUT / "policy_summary.dat").open("w") as o:
    o.write("policy recovery attacker gen gensd rec recsd n\n")
    for p in POL:
        s = [r for r in rows if r["policy"] == p]
        gen = [f(r, "share_generation_ms") for r in s]
        rec = [f(r, "legitimate_recovery_ms") for r in s if f(r, "legitimate_recovery_ms") is not None]
        o.write(f"{LBL[p]} {100*sum(t(r,'legitimate_recovery_success') for r in s)/len(s):.1f} "
                f"{100*sum(t(r,'attacker_reconstruction') for r in s)/len(s):.1f} "
                f"{st.fmean(gen):.2f} {sd(gen):.2f} {st.fmean(rec):.3f} {sd(rec):.3f} {len(s)}\n")

fixed = [r for r in rows if r["policy"].startswith("fixed")]
with (OUT / "threshold_costs.dat").open("w") as o:
    o.write("t gen gensd rot rotsd rec recsd bytes trace tracesd tracen tracecorrect\n")
    for k in (2, 3, 4):
        s = [r for r in fixed if int(r["threshold"]) == k]
        per_trial = {}
        for r in s: per_trial[r["trial"]] = r
        gen = [f(r, "share_generation_ms") for r in per_trial.values()]
        rot = [f(r, "rotation_ms") for r in per_trial.values()]
        rec = [f(r, "legitimate_recovery_ms") for r in s if f(r, "legitimate_recovery_ms") is not None]
        uniq_trace = {(r["trial"], r["compromised_nodes"]): r for r in s if r["trace_ms"]}
        tr = [f(r, "trace_ms") for r in uniq_trace.values()]
        ok = sum(r["trace_correct"] == "True" for r in uniq_trace.values())
        by = st.fmean(f(r, "share_bytes_total") for r in per_trial.values())
        o.write(f"{k} {st.fmean(gen):.2f} {sd(gen):.2f} {st.fmean(rot):.2f} {sd(rot):.2f} "
                f"{st.fmean(rec):.3f} {sd(rec):.3f} {by:.0f} {st.fmean(tr):.2f} {sd(tr):.2f} {len(tr)} {ok}\n")

with (OUT / "adaptive_grid.dat").open("w") as o:
    o.write("u c score t rec att\n")
    for r in rows:
        if r["policy"] == "risk-adaptive" and r["trial"] == "0":
            o.write(f"{r['unavailable_nodes']} {r['compromised_nodes']} {r['risk_score']} {r['threshold']} "
                    f"{int(t(r,'legitimate_recovery_success'))} {int(t(r,'attacker_reconstruction'))}\n")
        if r["policy"] == "risk-adaptive" and r["trial"] == "0" and r["compromised_nodes"] == "4":
            o.write("\n")  # pgfplots matrix scanline separator

grid = [l.split() for l in (OUT / "adaptive_grid.dat").read_text().splitlines()[1:] if l.strip()]
NL = "\n"
(OUT / "grid_norecovery.dat").write_text("u c" + NL + "".join(f"{g[0]} {g[1]}{NL}" for g in grid if g[4] == "0"))
(OUT / "grid_attacker.dat").write_text("u c" + NL + "".join(f"{g[0]} {g[1]}{NL}" for g in grid if g[5] == "1"))

with (OUT / "per_trial_generation.dat").open("w") as o:
    o.write("trial t2 t3 t4\n")
    trials = sorted({r["trial"] for r in rows}, key=int)
    for tr in trials:
        g = {k: next(f(r, "share_generation_ms") for r in fixed if r["trial"] == tr and int(r["threshold"]) == k) for k in (2,3,4)}
        o.write(f"{int(tr)+1} {g[2]:.2f} {g[3]:.2f} {g[4]:.2f}\n")
print("rows", len(rows))
for p in sorted(OUT.glob("*.dat")): print(p.name); print(p.read_text())
