#!/usr/bin/env python3
"""
Pull CAPE reports for the labelled corpus and compute paper Q1-Q3, Q6.
Report-reading only (open API) -- no LLM, no malware handling.

Q1 conversion validity : each report -> STIX 2.1 objects; % valid + completeness
Q2 IOC yield           : STIX observables per sample (file/network/registry)
Q3 ATT&CK coverage     : distinct techniques recovered from the ttps mapping
Q6 latency             : analysis duration (p50/p95) + STIX transform time (ms)

Writes q_results.json.  Usage: python3 agg_corpus.py <task_ids...>
"""
import json, os, sys, time, statistics, urllib.request

BASE = "https://cape.tech-4.eu/apiv2/tasks/get/report"
UA = "Mozilla/5.0 (Macintosh)"
# Optional Cloudflare clearance cookie (copy from browser after visiting the site):
#   export CAPE_CF="cf_clearance=xxxx; __cf_bm=yyyy"
CF = os.environ.get("CAPE_CF", "")
OUT = os.path.join(os.path.dirname(__file__), "q_results.json")
try:
    import stix2            # validates STIX 2.1 objects on construction
    HAVE_STIX = True
except Exception:
    HAVE_STIX = False


def fetch(tid):
    headers = {"User-Agent": UA}
    if CF:
        headers["Cookie"] = CF
    req = urllib.request.Request(f"{BASE}/{tid}/json/", headers=headers)
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read().decode())


def observables(rep):
    tf = (rep.get("target") or {}).get("file") or {}
    net = rep.get("network") or {}
    ips = sorted({(h.get("ip") if isinstance(h, dict) else h) for h in (net.get("hosts") or []) if h})
    doms = sorted({(d.get("domain") if isinstance(d, dict) else d) for d in (net.get("domains") or []) if d})
    urls = sorted({h.get("uri") for h in (net.get("http") or []) if isinstance(h, dict) and h.get("uri")})
    beh = ((rep.get("behavior") or {}).get("summary") or {})
    reg = len(beh.get("write_keys") or []) + len(beh.get("delete_keys") or [])
    techs = sorted({t for e in (rep.get("ttps") or []) for t in (e.get("ttps") or [])})
    return dict(sha256=tf.get("sha256"), md5=tf.get("md5"),
                ips=ips, domains=doms, urls=urls, registry=reg, techs=techs)


def to_stix(o):
    """Mirror the connector mapping; return (objects_built, objects_valid)."""
    built = valid = 0
    def mk(fn):
        nonlocal built, valid
        built += 1
        try:
            fn(); valid += 1
        except Exception:
            pass
    if o["sha256"]:
        if HAVE_STIX:
            mk(lambda: stix2.File(hashes={"SHA-256": o["sha256"], "MD5": o["md5"]} if o["md5"]
                                  else {"SHA-256": o["sha256"]}))
        else:
            mk(lambda: (_ for _ in ()).throw(StopIteration) if not o["sha256"] else None)
    for ip in o["ips"]:
        mk(lambda ip=ip: stix2.IPv4Address(value=ip) if HAVE_STIX else _valid_ip(ip))
    for d in o["domains"]:
        mk(lambda d=d: stix2.DomainName(value=d) if HAVE_STIX else _nonempty(d))
    for u in o["urls"]:
        mk(lambda u=u: stix2.URL(value=u) if HAVE_STIX else _nonempty(u))
    for t in o["techs"]:
        mk(lambda t=t: stix2.AttackPattern(name=t,
              external_references=[{"source_name": "mitre-attack", "external_id": t}])
              if HAVE_STIX else _valid_tech(t))
    return built, valid


def _nonempty(x):
    if not x:
        raise ValueError
def _valid_ip(x):
    p = str(x).split(".")
    if len(p) != 4 or not all(s.isdigit() and 0 <= int(s) <= 255 for s in p):
        raise ValueError
def _valid_tech(x):
    if not (str(x).startswith("T") and any(c.isdigit() for c in str(x))):
        raise ValueError


def main():
    ids = sys.argv[1:] or [str(i) for i in range(21, 28)]
    rows, durations, transforms = [], [], []
    tot_built = tot_valid = 0
    all_techs = set()
    for tid in ids:
        try:
            rep = fetch(tid)
        except Exception as e:
            rows.append({"id": tid, "error": str(e)}); continue
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
        rows.append({"id": tid, "sha256": (o["sha256"] or "")[:12],
                     "yield_Q2": yield_,
                     "iocs": {"file": 1 if o["sha256"] else 0, "ips": len(o["ips"]),
                              "domains": len(o["domains"]), "urls": len(o["urls"]),
                              "registry": o["registry"]},
                     "attack_techniques_Q3": len(o["techs"]),
                     "stix_built": built, "stix_valid": valid,
                     "analysis_duration_s": dur})
        print(f"task {tid}: yield={yield_} techniques={len(o['techs'])} "
              f"stix={valid}/{built} dur={dur}s")

    def pct(a, b): return round(100 * a / b, 1) if b else None
    def p(vals, q):
        return round(statistics.quantiles(vals, n=100)[q - 1], 1) if len(vals) > 1 else (round(vals[0], 1) if vals else None)
    ok = [r for r in rows if "error" not in r]
    agg = {
        "samples": len(ok),
        "stix_lib_used": HAVE_STIX,
        "Q1_conversion_validity_pct": pct(tot_valid, tot_built),
        "Q1_objects": {"built": tot_built, "valid": tot_valid},
        "Q2_yield_mean": round(statistics.mean([r["yield_Q2"] for r in ok]), 1) if ok else None,
        "Q2_yield_range": [min((r["yield_Q2"] for r in ok), default=None),
                           max((r["yield_Q2"] for r in ok), default=None)],
        "Q3_attack_techniques_total_unique": len(all_techs),
        "Q3_attack_techniques_mean_per_sample": round(statistics.mean([r["attack_techniques_Q3"] for r in ok]), 1) if ok else None,
        "Q6_analysis_duration_s_p50": p(durations, 50),
        "Q6_analysis_duration_s_p95": p(durations, 95),
        "Q6_stix_transform_ms_p50": p(transforms, 50),
        "Q6_stix_transform_ms_p95": p(transforms, 95),
    }
    json.dump({"aggregate": agg, "per_sample": rows,
               "attack_techniques": sorted(all_techs)}, open(OUT, "w"), indent=2)
    print("\n=== AGGREGATE (Q1-Q3, Q6) ===")
    print(json.dumps(agg, indent=2))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
