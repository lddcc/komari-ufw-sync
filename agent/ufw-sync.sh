#!/usr/bin/env bash
# ufw-sync.sh — the thin, idempotent, fail-safe applier run on each agent.
#
# The Komari plugin computes a per-node whitelist and invokes this script via
# admin:exec. This script manages ONLY its own tagged rules (comment below);
# it never touches ufw defaults, public-port rules, or anything untagged.
#
# Inputs (environment):
#   MODE       check | apply           (default: check — prints a diff, changes nothing)
#   WL_V4      space/comma-separated IPv4 addrs or CIDRs to fully trust
#   WL_V6      space/comma-separated IPv6 addrs or CIDRs to fully trust
#   DDNS_V4    space-separated hostnames -> resolved locally to A records
#   DDNS_V6    space-separated hostnames -> resolved locally, masked to /64
#
# Behaviour / guarantees:
#   - No ufw installed        -> print SKIP and exit 0 (never auto-installs).
#   - Empty desired set       -> ERROR, change nothing (never lock yourself out).
#   - DNS resolution failure  -> that name is skipped; others still apply.
#   - Idempotent              -> if desired == current tagged set, do nothing
#                                (no rule churn, no `ufw reload`).
#   - Each trusted source gets both `ufw allow from` (host services) and
#     `ufw route allow from` (docker-published ports via ufw-docker).
set -euo pipefail

TAG="komari-ufw-sync"
MODE="${MODE:-check}"

log() { echo "[ufw-sync] $*"; }

# ufw must be present; do not bootstrap it here.
if ! command -v ufw >/dev/null 2>&1; then
  log "SKIP: ufw not installed on this host"
  exit 0
fi

# --- normalise inputs -------------------------------------------------------
# split on comma/space
split() { echo "$1" | tr ',' ' ' | tr -s ' ' '\n' | sed '/^$/d'; }

desired_v4=""
desired_v6=""

add_v4() { desired_v4+="$1"$'\n'; }
add_v6() { desired_v6+="$1"$'\n'; }

for ip in $(split "${WL_V4:-}"); do add_v4 "$ip"; done
for ip in $(split "${WL_V6:-}"); do add_v6 "$ip"; done

# Resolve home DDNS locally (each node uses its own resolver). Fail-safe: a name
# that does not resolve is skipped, never fatal.
for d in ${DDNS_V4:-}; do
  ip=$(getent ahosts "$d" 2>/dev/null | awk '/STREAM/ && $1 ~ /\./ {print $1; exit}')
  if [[ -n "${ip:-}" ]]; then log "resolved $d -> $ip"; add_v4 "$ip"
  else log "WARN: could not resolve v4 $d"; fi
done
for d in ${DDNS_V6:-}; do
  ip=$(getent ahosts "$d" 2>/dev/null | awk '/STREAM/ && $1 ~ /:/ {print $1; exit}')
  if [[ -n "${ip:-}" ]]; then
    prefix=$(echo "$ip" | awk -F: '{print $1":"$2":"$3":"$4}')
    log "resolved $d -> $ip (/64 ${prefix}::/64)"; add_v6 "${prefix}::/64"
  else log "WARN: could not resolve v6 $d"; fi
done

desired=$(printf '%s\n%s' "$desired_v4" "$desired_v6" | sed '/^$/d' | sort -u)

# Fail-safe: never proceed with an empty desired set.
if [[ -z "$desired" ]]; then
  log "ERROR: desired whitelist is EMPTY — refusing to change anything"
  exit 2
fi

# --- current tagged sources -------------------------------------------------
current=$(ufw status 2>/dev/null | grep -F "$TAG" | sed 's/#.*//' | awk '{print $NF}' | sed '/^$/d' | sort -u || true)

# --- diff -------------------------------------------------------------------
to_add=$(comm -23 <(echo "$desired") <(echo "$current") || true)
to_del=$(comm -13 <(echo "$desired") <(echo "$current") || true)

if [[ -z "$to_add" && -z "$to_del" ]]; then
  log "no change ($(echo "$desired" | wc -l | tr -d ' ') trusted sources already in sync)"
  exit 0
fi

log "MODE=$MODE  desired=$(echo "$desired" | wc -l | tr -d ' ')  +add=$(echo "$to_add" | sed '/^$/d' | wc -l | tr -d ' ')  -del=$(echo "$to_del" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ -n "$to_add" ]] && echo "$to_add" | sed 's/^/  + /'
[[ -n "$to_del" ]] && echo "$to_del" | sed 's/^/  - /'

if [[ "$MODE" != "apply" ]]; then
  log "check mode: no changes applied"
  exit 0
fi

# --- apply (incremental) ----------------------------------------------------
# Add only the new sources, delete only the stale ones; untouched sources keep
# their rules, so there is never a window without the trusted set, and no churn.

# 1) additions first (so trust is only ever added, never briefly missing)
while IFS= read -r src; do
  [[ -z "$src" ]] && continue
  ufw allow from "$src" comment "$TAG" >/dev/null
  ufw route allow from "$src" comment "$TAG" >/dev/null
done <<< "$to_add"

# 2) delete rules whose source is in to_del, by number (descending)
if [[ -n "$to_del" ]]; then
  # shell-safe lookup set of stale sources
  is_stale() { grep -qxF "$1" <<< "$to_del"; }
  while :; do
    line=$(ufw status numbered 2>/dev/null | grep -F "$TAG" | while IFS= read -r l; do
      src=$(echo "$l" | sed 's/#.*//' | awk '{print $NF}')
      if grep -qxF "$src" <<< "$to_del"; then echo "$l"; break; fi
    done)
    [[ -z "$line" ]] && break
    num=$(echo "$line" | sed -n 's/^\[[[:space:]]*\([0-9]\+\)\].*/\1/p')
    [[ -z "$num" ]] && break
    ufw --force delete "$num" >/dev/null || break
  done
fi

ufw reload >/dev/null
log "applied: +$(echo "$to_add" | sed '/^$/d' | wc -l | tr -d ' ') -$(echo "$to_del" | sed '/^$/d' | wc -l | tr -d ' ') ($(echo "$desired" | wc -l | tr -d ' ') trusted total)"
