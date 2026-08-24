# CG-CTI — Confidence-Qualified Threat Intelligence

Reproducibility artifact for **"From Sandbox to Enforcement: Confidence-Qualified Threat
Intelligence for Critical Infrastructure"**, CRITIS 2026.

CG-CTI converts live CAPEv2 sandbox output into STIX 2.1 in OpenCTI, attaches a per-object
**confidence status** derived from provenance, cross-source corroboration and observation
durability, and uses that status to gate automated enforcement. A self-hosted Qwen2.5-14B
then narrates the confidence-qualified evidence, with every statement required to cite a
supporting object.

Developed in the **CYBERGUARD** project (EU Digital Europe Programme, grant No. 101190251),
whose consortium includes Romania's national cyber-security directorate (DNSC).

---

## What reproduces

Every number in the paper's evaluation was regenerated from the live sandbox on
**2026-08-25**. Seven figures reproduce to the digit:

| Q | metric | paper | regenerated |
|---|---|---:|---:|
| Q1 | conversion validity | 100% | **100%** |
| Q2 | yield median / range | 5 / 1–23 | **5 / 1–23** |
| Q3 | distinct ATT&CK techniques | 39 | **39** |
| Q4 | family agreement | 30.8% | **30.8%** |
| Q6 | latency p50 | 157 s | **157 s** |
| Q6 | max registry writes | 1339 | **1339** |
| Q7 | statements generated | 437 | **437** |

Three differ, each for a stated reason:

| Q | metric | paper | regenerated | why |
|---|---|---:|---:|---|
| Q1 | STIX objects | 489 | 515 | see *Object count* below |
| Q4 | corroboration rate | 28.6% | 29.8% | abuse.ch is a **live** feed and has listed more indicators since July 2026 |
| Q7 | grounded/flagged/dropped | 27.7/60.2/12.1 | 32.0/58.4/9.6 | LLM generation is stochastic; the *statement count* is identical |

**Object count.** The paper defines Q1 as excluding the derived `Malware` object but the
results sentence lists malware among the counted types. The +26 difference is close to one
`Malware` object per sample, which is consistent with that definition mismatch rather than a
measurement difference.

**Feed-derived numbers are as-of a date.** Q4 depends on third-party feed contents at lookup
time; re-running later will not give byte-identical corroboration counts, and should not.

---

## The corpus

35 CAPEv2 analyses on `https://cape.tech-4.eu`, recorded in `eval/task_ids.txt`:

```
20 21 22 23 24 25 26 27 28 29 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56
```

Tasks 30 and 31 (`System.dll`, `nsDialogs.dll`) are side-tasks an installer dropped, not
corpus samples, and are excluded. Note the corpus counts **analyses**, not distinct files —
seven samples were detonated twice.

The report JSONs are ~620 MB and are **not** committed. Fetch them with:

```sh
mkdir -p reports_corpus
for id in $(grep -v '^#' eval/task_ids.txt); do
  curl -sS -A "Mozilla/5.0 (Macintosh)" \
    "https://cape.tech-4.eu/apiv2/tasks/get/report/$id/json/" -o "reports_corpus/$id.json"
done
```

---

## Reproducing

### Q1, Q2, Q3, Q6 — conversion, yield, coverage, latency

```sh
python3 eval/agg_corpus.py $(grep -v '^#' eval/task_ids.txt)   # writes eval/q_results.json
```

Fetches each report from CAPE. `agg_corpus.py` writes to a fixed path — redirect it if you
want to keep the committed results.

### Q4, Q5 — corroboration and the enforcement gate

```sh
export MB_AUTH_KEY=<your free abuse.ch key>     # https://auth.abuse.ch/
python3 eval/enrich.py reports_corpus eval/enrichment.json
```

No key is committed. Get your own; the two feeds share one.

### Q7 — evidence-grounded summaries and the grounding check

Needs the self-hosted LLM server (the paper's data-sovereignty property: evidence never
leaves operator infrastructure).

```sh
export CLONE_API_KEY=sk-...            # Bearer key for the LLM server
export CLONE_BASE_URL=https://<host>/v1
export CLONE_CA=/path/to/ca.crt        # server uses a private CA
python3 eval/egmir.py reports_corpus eval/egmir_out
```

> **TLS note.** The server presents only its leaf certificate, and its issuing CA
> ("Clone Systems Internal CA") is not in public trust stores, so Python fails with
> `CERTIFICATE_VERIFY_FAILED` unless `CLONE_CA` is set. Pinning to the leaf works:
> `openssl s_client -connect <host>:443 -showcerts | awk '/BEGIN CERT/,/END CERT/' > ca.pem`.
> Verifying you are talking to *your own* server is the point of the sovereignty claim, so do
> not disable verification.

---

## Layout

```
eval/
  agg_corpus.py       Q1/Q2/Q3/Q6 over CAPE reports
  agg_local.py        the same, from a local report directory
  enrich.py           Q4 corroboration against MalwareBazaar + ThreatFox
  egmir.py            Q7 evidence-grounded reports + grounding metric
  egmir_baseline.py   raw-log baseline (returns a null result; see the paper)
  q_results.json      regenerated Q1/Q2/Q3/Q6, 35 analyses
  enrichment.json     regenerated Q4
  egmir_out/          regenerated Q7, one file per analysis
  task_ids.txt        the corpus definition
run_all.sh            end-to-end driver (fetch → aggregate → enrich → EGMIR)
paper/paper.pdf       camera-ready
```

---

## Scope and limits

The paper is explicit, and so is this repo:

- CG-CTI **does not detect or classify malware**. It operates downstream of the sandbox, so
  whatever CAPE does not observe, the pipeline cannot recover. Coverage is the ceiling.
- The evaluation uses **one CAPEv2 deployment** and a single detonation profile per sample.
- Confidence thresholds are **untuned defaults**.
- The enforcement loop is evaluated **up to the decision gate**, not through to an executed
  SIEM/SOAR action.
- Q7 measures **citation validity** — that each delivered statement cites an object that
  exists — not semantic faithfulness.
- The dashboard is **pilot-grade** and lacks authentication.

## Ethics

All malware was detonated in an isolated, CYBERGUARD-controlled CAPEv2 sandbox. No samples
are distributed here; the corpus is identified by CAPE task id and hash only.

## Licence

See `LICENSE`.
