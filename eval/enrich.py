#!/usr/bin/env python3
"""
CYBERGUARD CRITIS -- lightweight corroborating enrichment (paper Q4).

Reads CAPE report JSONs and enriches each sandbox observable against two free
abuse.ch feeds -- MalwareBazaar (file-hash -> family/tags) and ThreatFox
(IP/domain/URL -> threat label) -- then computes the *corroboration* signal the
confidence model consumes: how often a sandbox observable is independently
attested by an external source, and whether the external family label agrees
with the sandbox's own.

No LLM. No malware handling: operates only on report JSON already pulled from
the sandbox (open API) and on feed *metadata* lookups. One abuse.ch key covers
both feeds.

Usage:
  MB_AUTH_KEY=<abuse.ch key> python3 enrich.py <reports_dir> [out.json]

Output: per-report enrichment + an aggregate corroboration rate (Table 1, Q4).
"""
import json, glob, os, sys, time, urllib.request, urllib.parse, collections

KEY = os.environ.get("MB_AUTH_KEY", "")
MB  = "https://mb-api.abuse.ch/api/v1/"
TF  = "https://threatfox-api.abuse.ch/api/v1/"
_cache = {}   # dedupe identical lookups across the corpus


def _post(url, data, json_body=False):
    if json_body:
        body, ct = json.dumps(data).encode(), "application/json"
    else:
        body, ct = urllib.parse.urlencode(data).encode(), "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body,
                                 headers={"Auth-Key": KEY, "Content-Type": ct})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"query_status": f"error:{e}"}


def mb_hash(sha256):
    if not sha256:
        return None
    k = ("mb", sha256)
    if k in _cache:
        return _cache[k]
    d = _post(MB, {"query": "get_info", "hash": sha256})
    out = None
    if d.get("query_status") == "ok" and d.get("data"):
        s = d["data"][0]
        out = {"family": s.get("signature"), "tags": s.get("tags") or []}
    _cache[k] = out
    time.sleep(0.4)
    return out


def tf_ioc(ioc):
    if not ioc:
        return None
    k = ("tf", ioc)
    if k in _cache:
        return _cache[k]
    d = _post(TF, {"query": "search_ioc", "search_term": ioc}, json_body=True)
    out = None
    if d.get("query_status") == "ok" and d.get("data"):
        e = d["data"][0]
        out = {"malware": e.get("malware_printable"), "threat": e.get("threat_type")}
    _cache[k] = out
    time.sleep(0.4)
    return out


def observables(report):
    """Extract the sandbox observables the confidence model scores."""
    tf = (report.get("target") or {}).get("file") or {}
    sha = tf.get("sha256")
    net = report.get("network") or {}
    ips = [h.get("ip") if isinstance(h, dict) else h for h in (net.get("hosts") or [])]
    doms = [d.get("domain") if isinstance(d, dict) else d for d in (net.get("domains") or [])]
    # sandbox family guess: detections, else malfamily, else first signature name
    fam = report.get("detections") or report.get("malfamily") or ""
    if isinstance(fam, list):
        fam = ",".join(str(x.get("family", x) if isinstance(x, dict) else x) for x in fam)
    # ATT&CK techniques from the top-level ttps key
    techs = set()
    for e in (report.get("ttps") or []):
        for t in (e.get("ttps") or []):
            techs.add(t)
    return dict(sha256=sha, ips=[i for i in ips if i], domains=[d for d in doms if d],
                sandbox_family=str(fam), techniques=sorted(techs))


def enrich_report(path):
    try:
        r = json.load(open(path))
    except Exception as e:
        return {"file": os.path.basename(path), "error": str(e)}
    obs = observables(r)
    per = {"file": os.path.basename(path), "sha256": obs["sha256"],
           "sandbox_family": obs["sandbox_family"], "techniques": len(obs["techniques"]),
           "observables": 0, "corroborated": 0, "family_agreement": None, "hits": []}

    # file hash -> MalwareBazaar
    if obs["sha256"]:
        per["observables"] += 1
        mb = mb_hash(obs["sha256"])
        if mb and mb.get("family"):
            per["corroborated"] += 1
            per["hits"].append({"type": "file", "source": "MalwareBazaar", "label": mb["family"]})
            if obs["sandbox_family"]:
                per["family_agreement"] = (mb["family"].lower() in obs["sandbox_family"].lower()
                                           or obs["sandbox_family"].lower() in mb["family"].lower())

    # network IOCs -> ThreatFox
    for ioc in obs["ips"] + obs["domains"]:
        per["observables"] += 1
        tf = tf_ioc(ioc)
        if tf and (tf.get("malware") or tf.get("threat")):
            per["corroborated"] += 1
            per["hits"].append({"type": "network", "ioc": ioc, "source": "ThreatFox",
                                "label": tf.get("malware") or tf.get("threat")})
    per["corroboration_rate"] = round(per["corroborated"] / per["observables"], 3) if per["observables"] else None
    return per


def main():
    if not KEY:
        sys.exit("Set MB_AUTH_KEY (abuse.ch key) in the environment.")
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    reports = sorted(glob.glob(os.path.join(sys.argv[1], "*.json")))
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(sys.argv[1], "enrichment.json")

    rows, tot_obs, tot_corr, agree, agree_n = [], 0, 0, 0, 0
    for p in reports:
        row = enrich_report(p)
        rows.append(row)
        tot_obs += row.get("observables", 0)
        tot_corr += row.get("corroborated", 0)
        if row.get("family_agreement") is not None:
            agree_n += 1
            agree += 1 if row["family_agreement"] else 0
        print(f"{row['file']:>10}  obs={row.get('observables',0):>2} "
              f"corroborated={row.get('corroborated',0):>2}  fam={row.get('sandbox_family','')[:20]}")

    agg = {"reports": len(rows),
           "total_observables": tot_obs,
           "total_corroborated": tot_corr,
           "corroboration_rate_Q4": round(tot_corr / tot_obs, 3) if tot_obs else None,
           "family_agreement_rate": round(agree / agree_n, 3) if agree_n else None}
    json.dump({"aggregate": agg, "per_report": rows}, open(out_path, "w"), indent=2)
    print("\n=== AGGREGATE (paper Q4) ===")
    print(json.dumps(agg, indent=2))
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
