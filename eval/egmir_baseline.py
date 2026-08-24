#!/usr/bin/env python3
"""
RAW-LOG BASELINE for the EGMIR grounding claim (paper Sect. 7 / reviewer request).

Runs the SAME self-hosted model as EGMIR, but on a free-text rendering of the raw
sandbox output with NO structured evidence set and NO grounding instruction, then
extracts every IOC the model asserts and checks whether it actually appears anywhere
in the sandbox report. An asserted IOC absent from the report is a fabrication.

Contrast with EGMIR (structured, grounding-by-construction): fabricated references
cannot be delivered (Alg. 2 drops them). This quantifies the grounding benefit.

Env: CLONE_API_KEY (required), CLONE_BASE_URL, CLONE_MODEL, CLONE_INSECURE=1.
Usage: python3 egmir_baseline.py <reports_dir> [out.json]
Stdlib only.
"""
import json, glob, os, re, sys, ssl, time, urllib.request, urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agg_corpus import observables

BASE  = os.environ.get("CLONE_BASE_URL", "https://45.132.135.12/v1").rstrip("/")
MODEL = os.environ.get("CLONE_MODEL", "qwen2.5-14b")
KEY   = os.environ.get("CLONE_API_KEY", "")
CTX   = ssl._create_unverified_context() if os.environ.get("CLONE_INSECURE") else ssl.create_default_context()

SYSTEM = ("You are a malware-intelligence analyst. You are given raw sandbox output for one "
          "sample. Write a short threat report: first a behaviour summary, then a section "
          "headed 'IOCs:' listing every indicator of compromise you find (IPv4 addresses, "
          "domains, URLs, and file hashes), one per line.")


def undefang(s):
    return (s.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
             .replace("[:]", ":").replace("hxxp", "http"))


def raw_context(rep):
    parts = []
    tf = (rep.get("target") or {}).get("file") or {}
    parts.append(f"file: type={tf.get('type','')} md5={tf.get('md5','')} sha256={tf.get('sha256','')}")
    net = rep.get("network") or {}
    hosts = [h.get("ip") if isinstance(h, dict) else h for h in (net.get("hosts") or [])]
    doms  = [d.get("domain") if isinstance(d, dict) else d for d in (net.get("domains") or [])]
    uris  = [h.get("uri") for h in (net.get("http") or []) if isinstance(h, dict) and h.get("uri")]
    parts.append("contacted hosts: " + ", ".join(str(x) for x in hosts[:40] if x))
    parts.append("resolved domains: " + ", ".join(str(x) for x in doms[:40] if x))
    parts.append("http requests: " + ", ".join(str(x) for x in uris[:20] if x))
    parts.append("signatures: " + ", ".join(s.get("name", "") for s in (rep.get("signatures") or [])[:40]))
    beh = ((rep.get("behavior") or {}).get("summary") or {})
    for k in ("files", "mutexes", "keys", "executed_commands"):
        v = beh.get(k) or []
        if v:
            parts.append(f"{k}: " + ", ".join(str(x) for x in v[:20]))
    return "\n".join(parts)[:7000]


def chat(ctx):
    payload = {"model": MODEL, "temperature": 0.2, "max_tokens": 1200,
               "messages": [{"role": "system", "content": SYSTEM},
                            {"role": "user", "content": "Raw sandbox output:\n" + ctx}]}
    req = urllib.request.Request(BASE + "/chat/completions", data=json.dumps(payload).encode(),
                                 headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=180, context=CTX) as r:
                return json.loads(r.read().decode())["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(2 ** attempt); continue
            raise
    raise RuntimeError("rate-limited")


IPRE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
H64  = re.compile(r"\b[a-fA-F0-9]{64}\b")
H32  = re.compile(r"\b[a-fA-F0-9]{32}\b")
URL  = re.compile(r"https?://[^\s,)\"'>]+")
DOM  = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
NOT_DOMAIN_TLD = {"exe", "dll", "sys", "bat", "ps1", "vbs", "js", "dat", "tmp", "log", "bin", "png", "jpg"}


def extract_iocs(out):
    t = undefang(out)
    iocs = set()
    for m in IPRE.findall(t):
        parts = m.split(".")
        if all(0 <= int(p) <= 255 for p in parts) and m != "0.0.0.0":
            iocs.add(("ip", m.lower()))
    for m in H64.findall(t): iocs.add(("hash", m.lower()))
    for m in H32.findall(t): iocs.add(("hash", m.lower()))
    for m in URL.findall(t): iocs.add(("url", m.lower().rstrip(".,);")))
    for m in DOM.findall(t):
        d = m.lower().rstrip(".")
        if d.split(".")[-1] not in NOT_DOMAIN_TLD and not IPRE.fullmatch(d):
            iocs.add(("domain", d))
    return iocs


def main():
    if not KEY:
        sys.exit("set CLONE_API_KEY")
    rdir = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(rdir), "baseline_results.json")
    agg = {"samples": 0, "asserted": 0, "present": 0, "fabricated": 0}
    rows = []
    for p in sorted(glob.glob(os.path.join(rdir, "*.json")),
                    key=lambda x: int(os.path.basename(x)[:-5]) if os.path.basename(x)[:-5].isdigit() else 0):
        tid = os.path.basename(p)[:-5]
        if not tid.isdigit():
            continue
        report_text = undefang(open(p, errors="ignore").read().lower())
        try:
            rep = json.loads(report_text) if len(report_text) < 5_000_000 else json.load(open(p))
        except Exception:
            rep = json.load(open(p))
        ctx = raw_context(rep)
        try:
            out_text = chat(ctx)
        except Exception as e:
            print(f"error {tid}: {e}"); continue
        iocs = extract_iocs(out_text)
        present = sum(1 for _, v in iocs if v in report_text)
        fab = len(iocs) - present
        agg["samples"] += 1; agg["asserted"] += len(iocs)
        agg["present"] += present; agg["fabricated"] += fab
        rows.append({"id": tid, "asserted": len(iocs), "present": present, "fabricated": fab,
                     "fabricated_examples": [v for k, v in iocs if v not in report_text][:6]})
        print(f"task {tid}: asserted={len(iocs)} present={present} fabricated={fab}")
        time.sleep(1)
    tot = agg["asserted"] or 1
    agg["fabrication_rate_pct"] = round(100 * agg["fabricated"] / tot, 1)
    agg["present_rate_pct"] = round(100 * agg["present"] / tot, 1)
    json.dump({"aggregate": agg, "per_sample": rows}, open(out, "w"), indent=2)
    print("\n=== RAW-LOG BASELINE (no grounding) ===")
    print(json.dumps(agg, indent=2))
    print("Contrast: EGMIR (structured) delivers 0 fabricated references (Alg. 2 drops them).")
    print("wrote", out)


if __name__ == "__main__":
    main()
