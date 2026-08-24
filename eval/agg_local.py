#!/usr/bin/env python3
"""
Aggregate CAPE reports ALREADY PULLED to disk (reports_corpus/<taskid>.json) and
compute paper Q1-Q3, Q6 across the expanded corpus, with a per-family breakdown.
Reuses the exact STIX-mapping logic from agg_corpus.py. Report-reading only.

Usage: python3 agg_local.py <reports_dir> <task_family_map.csv> [out.json]
"""
import json, os, sys, glob, statistics
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agg_corpus import observables, to_stix, HAVE_STIX


def load_family_map(path):
    m = {}
    with open(path) as f:
        for line in f.read().splitlines()[1:]:
            p = line.split(",")
            if len(p) >= 2:
                m[p[0]] = p[1]
    return m


def norm_family(fam):
    return {"njrat": "njRAT"}.get(fam, fam)


def main():
    rdir = sys.argv[1]
    fam_map = load_family_map(sys.argv[2])
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(rdir), "q_results_scaled.json")

    rows, durations, transforms = [], [], []
    tot_built = tot_valid = 0
    all_techs = set()
    per_family = defaultdict(lambda: {"n": 0, "yield": [], "techs": []})

    import time
    for p in sorted(glob.glob(os.path.join(rdir, "*.json")), key=lambda x: int(os.path.basename(x)[:-5]) if os.path.basename(x)[:-5].isdigit() else 0):
        tid = os.path.basename(p)[:-5]
        try:
            rep = json.load(open(p))
        except Exception as e:
            rows.append({"id": tid, "error": f"parse:{e}"}); continue
        o = observables(rep)
        yield_ = (1 if o["sha256"] else 0) + len(o["ips"]) + len(o["domains"]) + len(o["urls"]) + o["registry"]
        t0 = time.perf_counter()
        built, valid = to_stix(o)
        transforms.append((time.perf_counter() - t0) * 1000.0)
        tot_built += built; tot_valid += valid
        all_techs |= set(o["techs"])
        dur = (rep.get("info") or {}).get("duration")
        if isinstance(dur, (int, float)):
            durations.append(dur)
        fam = norm_family(fam_map.get(tid, "?"))
        per_family[fam]["n"] += 1
        per_family[fam]["yield"].append(yield_)
        per_family[fam]["techs"].append(len(o["techs"]))
        rows.append({"id": tid, "family": fam, "yield_Q2": yield_,
                     "attack_techniques_Q3": len(o["techs"]),
                     "stix_built": built, "stix_valid": valid,
                     "analysis_duration_s": dur})
        print(f"task {tid} [{fam}]: yield={yield_} techniques={len(o['techs'])} stix={valid}/{built} dur={dur}s")

    def pct(a, b): return round(100 * a / b, 1) if b else None
    def p(vals, q):
        vals = [v for v in vals if v is not None]
        if not vals: return None
        if len(vals) == 1: return round(vals[0], 1)
        return round(statistics.quantiles(vals, n=100)[q - 1], 1)
    ok = [r for r in rows if "error" not in r]
    ylds = [r["yield_Q2"] for r in ok]
    agg = {
        "samples": len(ok),
        "stix_lib_used": HAVE_STIX,
        "Q1_conversion_validity_pct": pct(tot_valid, tot_built),
        "Q1_objects": {"built": tot_built, "valid": tot_valid},
        "Q2_yield_mean": round(statistics.mean(ylds), 1) if ylds else None,
        "Q2_yield_median": round(statistics.median(ylds), 1) if ylds else None,
        "Q2_yield_range": [min(ylds, default=None), max(ylds, default=None)],
        "Q3_attack_techniques_total_unique": len(all_techs),
        "Q3_attack_techniques_mean_per_sample": round(statistics.mean([r["attack_techniques_Q3"] for r in ok]), 1) if ok else None,
        "Q6_analysis_duration_s_p50": p(durations, 50),
        "Q6_analysis_duration_s_p95": p(durations, 95),
        "Q6_stix_transform_ms_p50": p(transforms, 50),
        "Q6_stix_transform_ms_p95": p(transforms, 95),
    }
    fam_summary = {}
    for fam, d in sorted(per_family.items()):
        fam_summary[fam] = {"n": d["n"],
                            "yield_mean": round(statistics.mean(d["yield"]), 1) if d["yield"] else None,
                            "yield_range": [min(d["yield"]), max(d["yield"])] if d["yield"] else None,
                            "tech_mean": round(statistics.mean(d["techs"]), 1) if d["techs"] else None}
    json.dump({"aggregate": agg, "per_family": fam_summary, "per_sample": rows,
               "attack_techniques": sorted(all_techs)}, open(out, "w"), indent=2)
    print("\n=== AGGREGATE (Q1-Q3, Q6) over", len(ok), "samples ===")
    print(json.dumps(agg, indent=2))
    print("\n=== PER FAMILY ===")
    print(json.dumps(fam_summary, indent=2))
    print("wrote", out)


if __name__ == "__main__":
    main()
