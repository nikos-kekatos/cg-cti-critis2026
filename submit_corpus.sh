#!/usr/bin/env bash
# =============================================================================
# CYBERGUARD CRITIS — submit already-downloaded sample zips to CAPE.
# RUN THIS IN A PROTECTED ENVIRONMENT (CAPE host or a disposable VM), not your
# daily workstation. The assistant cannot auto-run detonation.
#
# Default (ARCHIVE mode): submits the password-protected zip straight to CAPE
# with password=infected, so the raw binary is only ever unpacked INSIDE the
# sandbox — nothing is extracted on this host.
# Fallback (EXTRACT mode, set EXTRACT=1): if this CAPE build won't unpack
# archives, extract to a tmp dir, submit, then `shred` the binary immediately.
#
# After it runs, send submit_map.csv (task ids) to the assistant; it pulls the
# reports (open API) and computes the evaluation.
# =============================================================================
set -u
CAPE="https://cape.tech-4.eu"
UA="Mozilla/5.0 (Macintosh)"
CAPE_CF="${CAPE_CF:-}"; CFHDR=(); [ -n "$CAPE_CF" ] && CFHDR=(-H "Cookie: $CAPE_CF")   # optional Cloudflare cookie
SAMPLES="${1:-/private/tmp/claude-501/-Users-nikos-Workspace-Projects-Clone-cyberguard/f83cca12-3950-4ace-864f-35ed77662051/scratchpad/samples}"
MAP="$(dirname "$SAMPLES")/submit_map.csv"
TIMEOUT_S="${CAPE_TIMEOUT:-120}"
EXTRACT="${EXTRACT:-0}"

echo "sha256,task_id,mode,submit_response" > "$MAP"
for z in "$SAMPLES"/*.zip; do
  [ -e "$z" ] || { echo "no zips in $SAMPLES"; break; }
  sha="$(basename "$z" .zip)"
  if [ "$EXTRACT" = "1" ]; then
    d="$(mktemp -d)"; unzip -o -P infected "$z" -d "$d" >/dev/null 2>&1
    bin="$(ls -S "$d" 2>/dev/null | head -1)"
    [ -z "$bin" ] && { echo "$sha,,extract,UNZIP_FAIL" >> "$MAP"; rm -rf "$d"; continue; }
    resp="$(curl -sS -m 120 -A "$UA" ${CFHDR[@]+"${CFHDR[@]}"} -F "file=@$d/$bin" -F "timeout=$TIMEOUT_S" "$CAPE/apiv2/tasks/create/file/")"
    command -v shred >/dev/null && shred -u "$d/$bin" 2>/dev/null; rm -rf "$d"
    mode=extract
  else
    # ARCHIVE mode: hand CAPE the encrypted zip; it unpacks internally.
    resp="$(curl -sS -m 120 -A "$UA" ${CFHDR[@]+"${CFHDR[@]}"} -F "file=@$z" -F "timeout=$TIMEOUT_S" \
            -F "options=password=infected" "$CAPE/apiv2/tasks/create/file/")"
    mode=archive
  fi
  tid="$(python3 - "$resp" <<'PY'
import sys,json
try:
    d=json.loads(sys.argv[1]); dd=d.get("data")
    print((dd or {}).get("task_ids",[""])[0] if isinstance(dd,dict) else (d.get("task_id") or ""))
except Exception: print("")
PY
)"
  echo "$sha,$tid,$mode,$(tr -d '\n' <<<"$resp" | cut -c1-70)" >> "$MAP"
  echo "submitted $sha -> task ${tid:-?} ($mode)"
  sleep 2
done
echo; echo "DONE -> $MAP  (send this to the assistant)"
