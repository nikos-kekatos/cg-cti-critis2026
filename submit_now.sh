#!/usr/bin/env bash
# =============================================================================
# CYBERGUARD CRITIS -- one-shot submission of the ALREADY-DOWNLOADED corpus.
# No MalwareBazaar, no arguments, no local extraction.
#
#   bash submit_now.sh
#
# SAFETY: submits each password-protected zip straight to CAPE with
# options=password=infected, so the raw binary is only ever unpacked INSIDE the
# sandbox -- nothing is extracted or written unencrypted on this host.
#
# Cloudflare: if the preflight is blocked, open https://cape.tech-4.eu once in a
# browser, then:  export CAPE_CF="cf_clearance=...; __cf_bm=..."  and rerun.
# =============================================================================
set -u
CAPE="https://cape.tech-4.eu"
UA="Mozilla/5.0 (Macintosh)"
SCRATCH="/private/tmp/claude-501/-Users-nikos-Workspace-Projects-Clone-cyberguard/f83cca12-3950-4ace-864f-35ed77662051/scratchpad"
SAMPLES="${1:-$SCRATCH/samples}"
MAP="$SCRATCH/submit_map.csv"
TIMEOUT_S="${CAPE_TIMEOUT:-120}"
CF="${CAPE_CF:-}"
CFARGS=(); [ -n "$CF" ] && CFARGS=(-H "Cookie: $CF")

# --- preflight: JSON, not a Cloudflare page? ---
probe="$(curl -sS -m 25 -A "$UA" ${CFARGS[@]+"${CFARGS[@]}"} "$CAPE/apiv2/tasks/view/22/" | head -c 40)"
case "$probe" in
  '<!DOCTYPE'*|'<html'*)
    echo "BLOCKED by Cloudflare. Open $CAPE in a browser, copy the cf_clearance cookie, then:"
    echo "  export CAPE_CF=\"cf_clearance=...; __cf_bm=...\"   and rerun."; exit 2 ;;
esac
echo "CAPE reachable. Submitting encrypted zips (unpacked server-side) from $SAMPLES"

echo "sha256,task_id,response" > "$MAP"
n=0; ok=0
for z in "$SAMPLES"/*.zip; do
  [ -e "$z" ] || { echo "no .zip files in $SAMPLES"; exit 1; }
  n=$((n+1)); sha="$(basename "$z" .zip)"
  resp="$(curl -sS -m 120 -A "$UA" ${CFARGS[@]+"${CFARGS[@]}"} \
          -F "file=@$z" -F "timeout=$TIMEOUT_S" -F "options=password=infected" \
          "$CAPE/apiv2/tasks/create/file/")"
  tid="$(python3 - "$resp" <<'PY'
import sys,json
try:
    d=json.loads(sys.argv[1]); dd=d.get("data")
    print((dd or {}).get("task_ids",[""])[0] if isinstance(dd,dict) else (d.get("task_id") or ""))
except Exception: print("")
PY
)"
  [ -n "$tid" ] && ok=$((ok+1))
  echo "$sha,$tid,$(printf '%s' "$resp" | tr -d '\n' | cut -c1-70)" >> "$MAP"
  echo "[$n] $sha -> task ${tid:-FAILED}"
  sleep 2
done

echo
echo "DONE: $ok/$n submitted. Task IDs:"
tail -n +2 "$MAP" | awk -F, '$2!=""{printf "%s ",$2} END{print ""}'
echo "Map: $MAP"
[ "$ok" = 0 ] && echo "All failed: inspect the response column in $MAP (CAPE may need a different archive option)."
