#!/usr/bin/env bash
# =============================================================================
# CYBERGUARD CRITIS -- one-shot corpus driver.
# Submits the labelled corpus to CAPE, waits for detonation, and computes the
# evaluation table (Q1-Q3, Q6). Optionally runs enrichment (Q4) and the
# self-hosted-LLM EGMIR grounding (Q7) if the relevant keys are set.
#
# RUN THIS ON YOUR END (CAPE host or a disposable VM) -- it downloads live
# malware from MalwareBazaar and detonates it in the sandbox.
#
# Usage:
#   export CAPE_CF="cf_clearance=...; __cf_bm=..."   # optional Cloudflare cookie
#   export MB_AUTH_KEY="..."                          # abuse.ch key (has a default)
#   export CLONE_API_KEY="sk-..."                     # optional -> also run Q7 EGMIR
#   bash run_all.sh
# =============================================================================
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRATCH="${SCRATCH:-/private/tmp/claude-501/-Users-nikos-Workspace-Projects-Clone-cyberguard/f83cca12-3950-4ace-864f-35ed77662051/scratchpad}"
MANIFEST="${MANIFEST:-$SCRATCH/corpus_manifest.csv}"
MAP="$(dirname "$MANIFEST")/submit_map.csv"
UA="Mozilla/5.0 (Macintosh)"
CAPE="https://cape.tech-4.eu"
CAPE_CF="${CAPE_CF:-}"
POLL_TRIES="${POLL_TRIES:-40}"          # * POLL_SLEEP seconds max wait
POLL_SLEEP="${POLL_SLEEP:-30}"
CURLCF=(); [ -n "$CAPE_CF" ] && CURLCF=(-H "Cookie: $CAPE_CF")
export CAPE_CF MB_AUTH_KEY="${MB_AUTH_KEY:?set MB_AUTH_KEY (free abuse.ch key)}"

say(){ printf '\n\033[1m== %s\033[0m\n' "$*"; }

# --- 0. preflight: is the CAPE API answering with JSON (not a Cloudflare page)? ---
say "0/4 preflight $CAPE"
probe="$(curl -sS -m 30 -A "$UA" ${CURLCF[@]+"${CURLCF[@]}"} "$CAPE/apiv2/tasks/get/report/22/json/" | head -c 40)"
case "$probe" in
  '<!DOCTYPE'*|'<html'*)
    echo "BLOCKED: CAPE returned an HTML challenge, not JSON."
    echo "Open $CAPE in your browser, copy the cf_clearance (+__cf_bm) cookie, then:"
    echo "  export CAPE_CF=\"cf_clearance=...; __cf_bm=...\"  and re-run."
    exit 2 ;;
  *) echo "OK: API is answering with JSON." ;;
esac

# --- 1. submit the corpus (download from MB + detonate) ---
say "1/4 submit corpus from $MANIFEST"
bash "$HERE/run_corpus.sh" "$MANIFEST" || { echo "submit step failed"; exit 3; }
IDS="$(tail -n +2 "$MAP" | awk -F, '$4!=""{print $4}' | paste -sd" " -)"
[ -z "$IDS" ] && { echo "no task ids in $MAP (all submissions blocked?)"; exit 4; }
echo "task ids: $IDS"

# --- 2. wait for detonation: poll until each report is populated ---
say "2/4 wait for detonation (up to $((POLL_TRIES*POLL_SLEEP/60)) min)"
for id in $IDS; do
  for ((t=1; t<=POLL_TRIES; t++)); do
    n="$(curl -sS -m 60 -A "$UA" ${CURLCF[@]+"${CURLCF[@]}"} "$CAPE/apiv2/tasks/get/report/$id/json/" | wc -c)"
    if [ "$n" -gt 2000 ]; then printf 'task %s ready (%s bytes)\n' "$id" "$n"; break; fi
    printf 'task %s not ready (try %d/%d)\r' "$id" "$t" "$POLL_TRIES"; sleep "$POLL_SLEEP"
  done
done

# --- 3. compute Q1-Q3, Q6 ---
say "3/4 compute Q1-Q3, Q6"
python3 "$HERE/eval/agg_corpus.py" $IDS

# --- 4. optional Q4 enrichment + Q7 EGMIR (only if configured) ---
say "4/4 optional enrichment (Q4) and EGMIR (Q7)"
REPORTS="$SCRATCH/reports_corpus"; mkdir -p "$REPORTS"
for id in $IDS; do
  curl -sS -m 120 -A "$UA" ${CURLCF[@]+"${CURLCF[@]}"} "$CAPE/apiv2/tasks/get/report/$id/json/" -o "$REPORTS/$id.json"
done
if [ -f "$HERE/eval/enrich.py" ]; then
  echo "-- Q4 enrichment (abuse.ch) --"; python3 "$HERE/eval/enrich.py" "$REPORTS" || echo "enrich skipped/failed"
fi
if [ -n "${CLONE_API_KEY:-}" ] && [ -f "$HERE/eval/egmir.py" ]; then
  echo "-- Q7 EGMIR (self-hosted LLM) --"; python3 "$HERE/eval/egmir.py" "$REPORTS" "$SCRATCH/egmir_out" || echo "egmir skipped/failed"
else
  echo "Q7 EGMIR skipped (set CLONE_API_KEY to run it)."
fi

say "DONE"
echo "Send me: $(dirname "$0")/eval/q_results.json  (and egmir_out/ if you ran Q7)."
