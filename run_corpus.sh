#!/usr/bin/env bash
# =============================================================================
# CYBERGUARD CRITIS paper — corpus download + detonation driver.
# Downloads labelled malware from MalwareBazaar and submits it to the CAPE
# sandbox for analysis. RUN THIS YOURSELF (you have authorization for the
# national-CSIRT sandbox); the assistant is intentionally not allowed to
# auto-execute live-malware download+detonation.
#
# After it finishes, tell the assistant — it will poll, pull the JSON reports
# (open API, no auth), and compute the evaluation table.
#
# Handling: samples are downloaded as password-protected zips (pw "infected")
# and only SUBMITTED to the sandbox — never executed locally. Keep them in the
# scratchpad dir. Delete when done.
# =============================================================================
set -u

KEY="${MB_AUTH_KEY:?set MB_AUTH_KEY (free abuse.ch key)}"   # abuse.ch Auth-Key
CAPE="https://cape.tech-4.eu"
UA="Mozilla/5.0 (Macintosh)"
# Optional Cloudflare clearance cookie for the CAPE edge (NOT sent to MalwareBazaar).
# Get it from your browser after visiting https://cape.tech-4.eu, e.g.:
#   export CAPE_CF="cf_clearance=xxxx"   (add "; __cf_bm=yyyy" too if present)
CAPE_CF="${CAPE_CF:-}"
CFHDR=(); [ -n "$CAPE_CF" ] && CFHDR=(-H "Cookie: $CAPE_CF")
MANIFEST="${1:-/private/tmp/claude-501/-Users-nikos-Workspace-Projects-Clone-cyberguard/f83cca12-3950-4ace-864f-35ed77662051/scratchpad/corpus_manifest.csv}"
OUT="$(dirname "$MANIFEST")/samples"
MAP="$(dirname "$MANIFEST")/submit_map.csv"
TIMEOUT_S="${CAPE_TIMEOUT:-120}"     # per-sample sandbox timeout
ONLY_TYPES="exe elf"                 # directly-detonatable; set "" to allow all

mkdir -p "$OUT"
echo "family,sha256,file_type,task_id,submit_response" > "$MAP"
echo "Reading $MANIFEST ..."

tail -n +2 "$MANIFEST" | while IFS=, read -r sha family ftype fname firstseen; do
  [ -z "$sha" ] && continue
  if [ -n "$ONLY_TYPES" ] && ! grep -qw "$ftype" <<<"$ONLY_TYPES"; then
    echo "skip $family/$sha (type=$ftype)"; continue
  fi
  z="$OUT/$sha.zip"; d="$OUT/$family/$sha"; mkdir -p "$d"
  # 1) download password-protected zip from MalwareBazaar
  curl -sS -m 90 -H "Auth-Key: $KEY" --data-urlencode "query=get_file" \
       --data-urlencode "sha256_hash=$sha" "https://mb-api.abuse.ch/api/v1/" -o "$z"
  # 2) unzip (never execute)
  rm -f "$d"/*; unzip -o -P infected "$z" -d "$d" >/dev/null 2>&1
  bin="$(ls -S "$d" 2>/dev/null | head -1)"
  if [ -z "$bin" ]; then echo "$family,$sha,$ftype,,DOWNLOAD_OR_UNZIP_FAIL" >> "$MAP"; continue; fi
  # 3) submit to CAPE
  resp="$(curl -sS -m 120 -A "$UA" ${CFHDR[@]+"${CFHDR[@]}"} -F "file=@$d/$bin" -F "timeout=$TIMEOUT_S" \
          "$CAPE/apiv2/tasks/create/file/")"
  tid="$(python3 - "$resp" <<'PY'
import sys,json
try:
    d=json.loads(sys.argv[1]); dd=d.get("data")
    print((dd or {}).get("task_ids",[""])[0] if isinstance(dd,dict) else (d.get("task_id") or ""))
except Exception: print("")
PY
)"
  echo "$family,$sha,$ftype,$tid,$(tr -d '\n' <<<"$resp" | cut -c1-70)" >> "$MAP"
  echo "submitted $family/$sha -> task ${tid:-?}"
  sleep 2   # be gentle on the shared sandbox
done

echo; echo "DONE. Submission map: $MAP"
echo "Now tell the assistant to poll + pull reports and compute the table."
