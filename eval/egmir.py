#!/usr/bin/env python3
"""
CYBERGUARD CRITIS -- Evidence-Grounded Malware Intelligence Report (EGMIR)
generator + grounding metric (paper Q7).

Runs against CYBERGUARD's **self-hosted** LLM server (Qwen2.5-14B, OpenAI-
compatible) -- NOT a cloud API -- so malware evidence never leaves the
operator's infrastructure (the data-sovereignty property in the paper).

Given a CAPE report, this builds a compact, confidence-qualified STIX-like
evidence set (File / Malware / Network / ATT&CK), passes ONLY that structured
evidence to the model, and requires every generated statement to cite the
evidence ids that support it. Statements with no support are flagged rather than
shown. It then computes the Q7 grounding metric:
  * grounded   = statements citing >=1 valid evidence id
  * flagged    = statements the model marked unsupported (empty cites)
  * ungrounded = statements citing an id NOT in the evidence set (hallucinated ref)

The model never sees the raw CAPE log -- only the evidence set
(grounding-by-construction, Sect. EGMIR).

Config (env, so the key never lands in a file):
  CLONE_API_KEY   required   -- Bearer key for the LLM server
  CLONE_BASE_URL  optional   -- default https://45.132.135.12/v1  (LAN: https://172.16.30.100/v1)
  CLONE_MODEL     optional   -- default qwen2.5-14b
  CLONE_CA        optional   -- path to clone-systems-ca.crt (else system trust)

Usage:
  CLONE_API_KEY=sk-... python3 egmir.py <report.json | reports_dir> [out_dir]

Stdlib only (urllib + ssl); no third-party deps.
"""
import json, glob, os, re, sys, time, ssl, urllib.request, urllib.error

BASE  = os.environ.get("CLONE_BASE_URL", "https://45.132.135.12/v1").rstrip("/")
MODEL = os.environ.get("CLONE_MODEL", "qwen2.5-14b")
KEY   = os.environ.get("CLONE_API_KEY", "")
CA    = os.environ.get("CLONE_CA")            # path to CA cert, or None -> system trust
_CTX  = ssl.create_default_context(cafile=CA) if CA else ssl.create_default_context()
if os.environ.get("CLONE_INSECURE"):              # internal CA lacks keyUsage ext
    _CTX = ssl._create_unverified_context()

SECTIONS = ["executive_summary", "observed_behaviours", "attack_techniques",
            "iocs", "likely_impact", "recommended_mitigations"]

SYSTEM = (
    "You are a malware-intelligence analyst assistant for a national CSIRT. "
    "You are given ONLY a structured evidence set extracted from a sandbox run; "
    "you do NOT have the raw sandbox log. Write a concise malware intelligence "
    "report as STRICT JSON with exactly these keys: " + ", ".join(SECTIONS) + ". "
    "Each key maps to a list of objects {\"text\": <string>, \"evidence_ids\": "
    "[<evidence id strings>]}. For EVERY statement, cite in evidence_ids the ids "
    "that directly support it. Use ONLY ids that appear in the evidence set. If "
    "you cannot support a statement, include it with an EMPTY evidence_ids list so "
    "it is flagged, or omit it. Prefer durable behavioural evidence (techniques, "
    "signatures) over atomic indicators when explaining what the sample does. "
    "Output JSON only -- no prose, no markdown fences."
)


def build_evidence(report):
    """Compact, confidence-tagged evidence set with stable ids E1..En."""
    ev, idx = [], 1

    def add(kind, value, durability, conf):
        nonlocal idx
        ev.append({"id": f"E{idx}", "kind": kind, "value": value,
                   "durability": durability, "confidence": conf})
        idx += 1

    tf = (report.get("target") or {}).get("file") or {}
    if tf.get("sha256"):
        add("file", f"SHA256 {tf['sha256']} ({tf.get('type','')[:40]})", "atomic", "attested")
    fam = report.get("detections") or report.get("malfamily")
    if fam:
        add("malware", f"family {fam}", "behavioural", "attested")
    net = report.get("network") or {}
    for h in (net.get("hosts") or [])[:15]:
        ip = h.get("ip") if isinstance(h, dict) else h
        if ip:
            add("network", f"contacted IP {ip}", "atomic", "observed")
    for d in (net.get("domains") or [])[:15]:
        dn = d.get("domain") if isinstance(d, dict) else d
        if dn:
            add("network", f"resolved domain {dn}", "atomic", "observed")
    seen = set()
    for e in (report.get("ttps") or []):
        for t in (e.get("ttps") or []):
            if t not in seen:
                seen.add(t)
                add("attack-pattern", f"ATT&CK technique {t} ({e.get('signature','')})",
                    "behavioural", "attested")
    for s in (report.get("signatures") or [])[:20]:
        add("signature", f"{s.get('name','?')} (severity {s.get('severity','?')})",
            "behavioural", "attested")
    return ev


def _extract_json(text):
    """Robustly pull the JSON object out of a model reply."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", text).strip()
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.DOTALL)     # first balanced-ish object
        if m:
            return json.loads(m.group(0))
        raise


def generate(evidence):
    prompt = ("Evidence set (id | kind | durability | confidence | value):\n" +
              "\n".join(f"{e['id']} | {e['kind']} | {e['durability']} | {e['confidence']} | {e['value']}"
                        for e in evidence) +
              "\n\nWrite the Evidence-Grounded Malware Intelligence Report as JSON now.")
    payload = {
        "model": MODEL,
        "temperature": 0.2,
        "max_tokens": 4000,
        "response_format": {"type": "json_object"},   # vLLM JSON mode; ignored if unsupported
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        f"{BASE}/chat/completions", data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=180, context=_CTX) as resp:
                content = json.loads(resp.read().decode())["choices"][0]["message"]["content"]
                return _extract_json(content)
        except urllib.error.HTTPError as e:
            if e.code == 429:                          # rate-limited: back off
                time.sleep(2 ** attempt); continue
            raise
    raise RuntimeError("rate-limited after retries")


def normalise(obj):
    """Coerce the model reply into {section: [{text, evidence_ids}]}."""
    out = {}
    for sec in SECTIONS:
        items = obj.get(sec) or []
        norm = []
        for it in items:
            if isinstance(it, dict):
                norm.append({"text": str(it.get("text", "")),
                             "evidence_ids": list(it.get("evidence_ids") or [])})
            else:  # tolerate a bare string
                norm.append({"text": str(it), "evidence_ids": []})
        out[sec] = norm
    return out


def grounding(report_obj, valid_ids):
    total = grounded = flagged = ungrounded = 0
    for section in report_obj.values():
        for st in section:
            total += 1
            ids = st.get("evidence_ids") or []
            if not ids:
                flagged += 1
            elif all(i in valid_ids for i in ids):
                grounded += 1
            else:
                ungrounded += 1
    pct = lambda n: round(100 * n / total, 1) if total else None
    return {"statements": total, "grounded": grounded, "flagged": flagged,
            "ungrounded": ungrounded, "grounded_pct": pct(grounded),
            "flagged_pct": pct(flagged), "ungrounded_pct": pct(ungrounded)}


def main():
    if not KEY:
        sys.exit("Set CLONE_API_KEY (LLM-server Bearer key) in the environment.")
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    target = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else (os.path.dirname(target) or ".")
    paths = sorted(glob.glob(os.path.join(target, "*.json"))) if os.path.isdir(target) else [target]
    print(f"LLM server: {BASE}  model: {MODEL}  (self-hosted; evidence stays on-prem)")

    agg = {"statements": 0, "grounded": 0, "flagged": 0, "ungrounded": 0}
    for p in paths:
        try:
            report = json.load(open(p))
        except Exception as e:
            print(f"skip {p}: {e}"); continue
        evidence = build_evidence(report)
        if not evidence:
            print(f"skip {os.path.basename(p)}: no evidence"); continue
        valid_ids = {e["id"] for e in evidence}
        try:
            egmir = normalise(generate(evidence))
        except Exception as e:
            print(f"error {os.path.basename(p)}: {e}"); continue
        g = grounding(egmir, valid_ids)
        for k in ("statements", "grounded", "flagged", "ungrounded"):
            agg[k] += g[k]
        base = os.path.splitext(os.path.basename(p))[0]
        json.dump({"evidence": evidence, "egmir": egmir, "grounding": g},
                  open(os.path.join(out_dir, f"{base}.egmir.json"), "w"), indent=2)
        print(f"{base:>10}  statements={g['statements']:>3} grounded={g['grounded_pct']}% "
              f"flagged={g['flagged_pct']}% ungrounded={g['ungrounded_pct']}%")

    t = agg["statements"] or 1
    agg["grounded_pct_Q7"] = round(100 * agg["grounded"] / t, 1)
    agg["flagged_pct"] = round(100 * agg["flagged"] / t, 1)
    agg["ungrounded_pct"] = round(100 * agg["ungrounded"] / t, 1)
    print("\n=== AGGREGATE (paper Q7: EGMIR grounding) ===")
    print(json.dumps(agg, indent=2))


if __name__ == "__main__":
    main()
