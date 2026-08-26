#!/usr/bin/env bash
# ufw-sync.sh — the thin, idempotent, fail-safe applier run on each agent.
#
# Manages TWO independent rule classes, each by its own comment tag, and never
# touches ufw defaults or any untagged rule:
#   - komari-ufw-sync : trusted sources (full access) — host + docker-published
#   - komari-ufw-pub  : public ports open to Anywhere — host + docker route
#
# Inputs (environment):
#   MODE        check | apply   (default check — prints a diff, changes nothing)
#   WL_V4/WL_V6 trusted IPv4/IPv6 addrs or CIDRs (space/comma separated)
#   DDNS_V4     hostnames -> resolved locally to A records
#   DDNS_V6     hostnames -> resolved locally, masked to /64
#   PUBLIC_TCP  public tcp ports/ranges, e.g. "80,443,8000:8100"
#   PUBLIC_UDP  public udp ports/ranges
#
# Guarantees:
#   - No ufw installed      -> print SKIP, exit 0 (never auto-installs).
#   - Empty trusted set     -> skip the trusted class (never deletes it → never
#                              locks you out); public class still processed.
#   - DNS failure           -> that name skipped; others still apply.
#   - Idempotent            -> unchanged class does nothing (no churn/reload).
#   - Incremental for trusted (add-new / delete-stale, no full-rebuild window).
set -euo pipefail

TAG_TRUST="komari-ufw-sync"
TAG_PUB="komari-ufw-pub"
MODE="${MODE:-check}"
changed=0

log() { echo "[ufw-sync] $*"; }
split() { echo "$1" | tr ',' ' ' | tr -s ' ' '\n' | sed '/^$/d'; }

# Machine-readable status line the brain parses & persists. Always printed last
# so every check/apply also refreshes the stored status.
emit_status() {
  local ufwstate ufwd tcount pcount
  ufwstate=$(ufw status 2>/dev/null | head -1 | sed 's/^Status: //')
  [[ -z "$ufwstate" ]] && ufwstate=unknown
  if grep -qs "BEGIN UFW AND DOCKER" /etc/ufw/after.rules; then ufwd=yes; else ufwd=no; fi
  tcount=$(ufw status 2>/dev/null | grep -c "$TAG_TRUST" || true)
  pcount=$(ufw status 2>/dev/null | grep -F "$TAG_PUB" | grep -oE '[0-9]+(:[0-9]+)?/(tcp|udp)' | sort -u | wc -l | tr -d ' ' || true)
  echo "[ufw-sync] STATUS ufw=$ufwstate trusted=${tcount:-0} pub=${pcount:-0} ufwdocker=$ufwd"
}

if ! command -v ufw >/dev/null 2>&1; then
  log "SKIP: ufw not installed on this host"
  echo "[ufw-sync] STATUS ufw=missing trusted=0 pub=0 ufwdocker=no"
  exit 0
fi

# ===================== trusted sources (komari-ufw-sync) =====================
desired_v4=""; desired_v6=""
for ip in $(split "${WL_V4:-}"); do desired_v4+="$ip"$'\n'; done
for ip in $(split "${WL_V6:-}"); do desired_v6+="$ip"$'\n'; done
for d in ${DDNS_V4:-}; do
  ip=$(getent ahosts "$d" 2>/dev/null | awk '/STREAM/ && $1 ~ /\./ {print $1; exit}')
  if [[ -n "${ip:-}" ]]; then log "resolved $d -> $ip"; desired_v4+="$ip"$'\n'
  else log "WARN: could not resolve v4 $d"; fi
done
for d in ${DDNS_V6:-}; do
  ip=$(getent ahosts "$d" 2>/dev/null | awk '/STREAM/ && $1 ~ /:/ {print $1; exit}')
  if [[ -n "${ip:-}" ]]; then
    prefix=$(echo "$ip" | awk -F: '{print $1":"$2":"$3":"$4}')
    log "resolved $d -> $ip (/64 ${prefix}::/64)"; desired_v6+="${prefix}::/64"$'\n'
  else log "WARN: could not resolve v6 $d"; fi
done
desired_t=$(printf '%s\n%s' "$desired_v4" "$desired_v6" | sed '/^$/d' | sort -u)

if [[ -z "$desired_t" ]]; then
  log "trusted set EMPTY — skipping trusted class (not touching $TAG_TRUST rules)"
else
  current_t=$(ufw status 2>/dev/null | grep -F "$TAG_TRUST" | sed 's/#.*//' | awk '{print $NF}' | sed '/^$/d' | sort -u || true)
  add_t=$(comm -23 <(echo "$desired_t") <(echo "$current_t") || true)
  del_t=$(comm -13 <(echo "$desired_t") <(echo "$current_t") || true)
  if [[ -z "$add_t" && -z "$del_t" ]]; then
    log "trusted: no change ($(echo "$desired_t" | wc -l | tr -d ' ') sources in sync)"
  else
    changed=1
    log "trusted MODE=$MODE +add=$(echo "$add_t"|sed '/^$/d'|wc -l|tr -d ' ') -del=$(echo "$del_t"|sed '/^$/d'|wc -l|tr -d ' ')"
    [[ -n "$add_t" ]] && echo "$add_t" | sed 's/^/  + /'
    [[ -n "$del_t" ]] && echo "$del_t" | sed 's/^/  - /'
    if [[ "$MODE" == "apply" ]]; then
      while IFS= read -r src; do [[ -z "$src" ]] && continue
        ufw allow from "$src" comment "$TAG_TRUST" >/dev/null
        ufw route allow from "$src" comment "$TAG_TRUST" >/dev/null
      done <<< "$add_t"
      if [[ -n "$del_t" ]]; then
        while :; do
          line=$(ufw status numbered 2>/dev/null | grep -F "$TAG_TRUST" | while IFS= read -r l; do
            s=$(echo "$l" | sed 's/#.*//' | awk '{print $NF}')
            if grep -qxF "$s" <<< "$del_t"; then echo "$l"; break; fi
          done || true)
          [[ -z "$line" ]] && break
          num=$(echo "$line" | sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p')
          [[ -z "$num" ]] && break
          ufw --force delete "$num" >/dev/null || break
        done
      fi
    fi
  fi
fi

# ===================== public ports (komari-ufw-pub) =========================
desired_p=""
for p in $(split "${PUBLIC_TCP:-}"); do desired_p+="tcp $p"$'\n'; done
for p in $(split "${PUBLIC_UDP:-}"); do desired_p+="udp $p"$'\n'; done
desired_p=$(echo "$desired_p" | sed '/^$/d' | sort -u)

# current public set from our tagged HOST rules (e.g. "80/tcp" -> "tcp 80")
current_p=$(ufw status 2>/dev/null | grep -F "$TAG_PUB" | sed 's/#.*//' \
  | grep -oE '[0-9]+(:[0-9]+)?/(tcp|udp)' | awk -F/ '{print $2" "$1}' | sort -u || true)

if [[ "$desired_p" == "$current_p" ]]; then
  [[ -n "$desired_p" || -n "$current_p" ]] && log "public: no change ($(echo "$desired_p"|sed '/^$/d'|wc -l|tr -d ' ') ports)"
else
  changed=1
  log "public MODE=$MODE  desired=$(echo "$desired_p"|sed '/^$/d'|wc -l|tr -d ' ')"
  [[ -n "$desired_p" ]] && echo "$desired_p" | sed 's/^/  pub + /'
  if [[ "$MODE" == "apply" ]]; then
    # delete all existing pub-tagged rules (small set; host + route), then re-add
    while :; do
      num=$(ufw status numbered 2>/dev/null | grep -F "$TAG_PUB" | sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p' | sort -rn | head -1 || true)
      [[ -z "$num" ]] && break
      ufw --force delete "$num" >/dev/null || break
    done
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      proto=$(echo "$line" | awk '{print $1}'); port=$(echo "$line" | awk '{print $2}')
      ufw allow "$port/$proto" comment "$TAG_PUB" >/dev/null
      ufw route allow proto "$proto" from any to any port "$port" comment "$TAG_PUB" >/dev/null
    done <<< "$desired_p"
  fi
fi

# ===================== finalize =============================================
if [[ "$MODE" != "apply" ]]; then
  log "check mode: no changes applied"
  emit_status
  exit 0
fi
if [[ "$changed" == "1" ]]; then
  ufw reload >/dev/null
  log "applied and reloaded"
else
  log "nothing to apply"
fi
emit_status
