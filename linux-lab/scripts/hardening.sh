#!/usr/bin/env bash
# OS-30: local Ubuntu baseline audit; never sources the lab .env.
# Usage: bash scripts/hardening.sh [audit|apply] [--context user=...,host=...,addr=...,laddr=...,lport=...]
set -euo pipefail
export LC_ALL=C
MODE=audit
CONTEXT=""
FAILS=0
WARNS=0
report() {
  printf '[%s] %s: %s\n' "$1" "$2" "$3"
  case "$1" in FAIL) FAILS=$((FAILS + 1));; WARN) WARNS=$((WARNS + 1));; esac
}
trap 'printf "[FAIL] execution: unexpected error at line %s; stopped\n" "$LINENO" >&2' ERR
usage() {
  printf '%s\n' 'Usage: hardening.sh [audit|apply] [--context user=...,host=...,addr=...,laddr=...,lport=...]' \
    'audit is read-only. For plan/apply use: python3 scripts/harden_check.py --help'
}
if [[ ${1:-} == audit || ${1:-} == apply ]]; then MODE=$1; shift; fi
while (($#)); do
  case "$1" in
    --context) [[ $# -ge 2 ]] || { usage; exit 2; }; CONTEXT=$2; shift 2;;
    -h|--help) usage; exit 0;;
    *) usage >&2; exit 2;;
  esac
done
# No override for host paths: mocks replace commands, never the production root.
if [[ $(uname -s) != Linux ]] || ! grep -q '^ID=ubuntu$' /etc/os-release 2>/dev/null; then
  report SKIP platform 'Ubuntu required; no audit or application performed'; exit 2
fi
SSHD=$(command -v sshd || true)
[[ -n $SSHD ]] || { [[ ! -x /usr/sbin/sshd ]] || SSHD=/usr/sbin/sshd; }
check_setting() {
  local data=$1 key=$2 expected=$3 value
  value=$(printf '%s\n' "$data" | awk -v key="$key" '$1 == key {print $2}')
  if [[ $value == "$expected" ]]; then report PASS "ssh.$key" "$value";
  elif [[ -z $value ]]; then report WARN "ssh.$key" 'effective value unavailable';
  else report FAIL "ssh.$key" "$value (baseline: $expected)"; fi
}
# Classify only explicit parser diagnostics as configuration failures. Generic
# errors (including missing host keys) do not prove a syntax violation.
validation_failure() {
  local check=$1 diagnostic=$2
  case "$diagnostic" in
    *'Permission denied'*|*'Operation not permitted'*)
      report WARN "$check" 'insufficient privilege to validate';;
    *'syntax error'*|*'Bad configuration option'*|*'bad configuration option'*|*'Missing argument'*|*'missing argument'*)
      report FAIL "$check" 'configuration parser rejected syntax; inspect validator locally';;
    *) report WARN "$check" 'validation unavailable or inconclusive; inspect validator locally';;
  esac
}
ssh_permissions() {
  local file metadata owner mode
  for file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    # Always inspect the main file, independently of sshd availability/syntax.
    [[ $file == /etc/ssh/sshd_config || -e $file ]] || continue
    if metadata=$(stat -Lc '%u %a' "$file" 2>/dev/null); then
      read -r owner mode <<< "$metadata"
      if [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 8#022) == 0 )); then
        report PASS ssh.permissions "$file root-owned and not group/world writable"
      else report FAIL ssh.permissions "$file unsafe ownership or write permissions"; fi
    else report WARN ssh.permissions "$file cannot be inspected"; fi
  done
  report WARN ssh.includes 'permission scan covers standard config paths only; custom Include files and parent directories require manual permission review'
}
ssh_listeners() {
  local sockets direct socket_list endpoint matched=""
  if ! sockets=$(ss -H -ltnp 2>/dev/null); then
    report WARN ssh.listeners 'ss unavailable or failed'; return
  fi
  direct=$(printf '%s\n' "$sockets" | awk '/"sshd"/ {print $4}')
  if [[ -n $direct ]]; then report PASS ssh.listeners "sshd-owned TCP endpoints: $direct"; fi
  # Attribute systemd sockets only when the endpoint is explicitly listed by
  # ssh.socket; do not treat every systemd listener as SSH.
  if socket_list=$(systemctl show --property=Listen --value ssh.socket 2>/dev/null); then
    while IFS= read -r endpoint; do
      [[ -n $endpoint ]] || continue
      case " $socket_list " in *" $endpoint (Stream)"*) matched="${matched}${endpoint} ";; esac
    done < <(printf '%s\n' "$sockets" | awk '/"systemd"/ {print $4}')
  fi
  if [[ -n $matched ]]; then report PASS ssh.socket_listeners "ssh.socket/systemd endpoint match: $matched"; fi
  if [[ -z $direct && -z $matched ]]; then report WARN ssh.listeners 'no attributable SSH listener; owner visibility or socket metadata may be unavailable'; fi
  report WARN ssh.access 'local socket attribution does not verify client reachability or NAT path'
}
ssh_audit() {
  local data diagnostic
  if systemctl is-active --quiet ssh.service 2>/dev/null; then
    report PASS ssh.service active
  elif systemctl is-active --quiet ssh.socket 2>/dev/null; then
    report PASS ssh.service 'socket activated'
  else report WARN ssh.service 'inactive or service state unavailable'; fi
  ssh_permissions
  ssh_listeners
  if [[ -z $SSHD ]]; then report SKIP ssh.effective 'sshd unavailable'; return; fi
  if ! diagnostic=$("$SSHD" -t 2>&1); then
    validation_failure ssh.syntax "$diagnostic"; return
  fi
  report PASS ssh.syntax 'sshd -t succeeded'
  if [[ -n $CONTEXT ]]; then
    # sshd validates the context grammar and resolves Include/Match itself.
    if ! data=$("$SSHD" -T -C "$CONTEXT" 2>/dev/null); then
      report WARN ssh.context 'sshd rejected context or cannot read configuration'; return
    fi
    report WARN ssh.context 'explicit context evaluated; caller must verify user, host and connection addresses; other Match contexts are not covered'
  else
    if ! data=$("$SSHD" -T 2>/dev/null); then report WARN ssh.effective 'sshd -T failed'; return; fi
    report WARN ssh.context 'global settings only; Match contexts unresolved; supply --context for a known connection'
  fi
  check_setting "$data" permitrootlogin no
  check_setting "$data" passwordauthentication no
  check_setting "$data" permitemptypasswords no
  check_setting "$data" pubkeyauthentication yes
  check_setting "$data" kbdinteractiveauthentication no
  report WARN ssh.runtime 'sshd -T describes disk configuration; running daemon may use different arguments or older settings'

}
sudo_privileges() {
  local name=$1 policy rules
  if [[ $(id -u) != 0 ]] || ! command -v sudo >/dev/null 2>&1; then
    report WARN users.sudo_effective "$name: root and sudo required for noninteractive policy query"; return
  fi
  # -n prevents a password prompt; -l only lists policy, it executes no command.
  if policy=$(sudo -n -l -U "$name" 2>&1); then
    rules=$(printf '%s\n' "$policy" | awk '/^[[:space:]]*\(/ {print}')
    if [[ -n $rules ]]; then
      report WARN users.sudo_effective "$name allowed command specifications: $rules"
    else report WARN users.sudo_effective "$name: query succeeded but command specifications could not be parsed"; fi
  else
    # Do not treat a failed query as proof that no privileges exist.
    report WARN users.sudo_effective "$name: policy query denied or unavailable; no absence of privilege inferred"
  fi
}
users_audit() {
  local accounts name _password uid _gid _gecos _home shell status count=0
  if accounts=$(getent passwd 2>/dev/null); then
    while IFS=: read -r name _password uid _gid _gecos _home shell; do
      if [[ $uid == 0 && $name != root ]]; then report FAIL users.uid0 "unexpected UID 0 account: $name"; count=$((count + 1)); fi
      # /bin/sync executes a utility rather than an interactive command shell.
      # Keep unknown shells visible for review instead of assuming they are safe.
      case "$shell" in */nologin|*/false|/bin/sync|'') continue;; esac
      report WARN users.interactive "review interactive account: $name"
      sudo_privileges "$name"
      if status=$(passwd -S "$name" 2>/dev/null); then
        status=$(printf '%s\n' "$status" | awk '{print $2}')
        case "$status" in
          NP) report FAIL users.password "$name has no password";;
          L) report PASS users.password "$name password locked (keys may still work)";;
          P) report WARN users.password "$name has a usable password";;
          *) report WARN users.password "$name status unknown";;
        esac
      else report WARN users.password "$name status inaccessible"; fi
    done <<< "$accounts"
    ((count != 0)) || report PASS users.uid0 'no non-root UID 0 accounts'
  else report WARN users.inventory 'getent passwd failed'; fi
  if status=$(visudo -c 2>&1); then report PASS users.sudoers 'visudo -c succeeded';
  else validation_failure users.sudoers "$status"; fi
  if accounts=$(getent group sudo 2>/dev/null); then
    report WARN users.sudo "sudo group members: $(printf '%s\n' "$accounts" | cut -d: -f4)"
  else report WARN users.sudo 'sudo group unavailable'; fi
  report WARN users.privileges 'effective sudo queries cover interactive accounts only; review service accounts, external policy and command semantics manually'
}
updates_audit() {
  local data count security newest now
  if data=$(apt list --upgradable 2>/dev/null); then
    count=$(printf '%s\n' "$data" | awk '/\[upgradable from:/ {n++} END {print n+0}')
    security=$(printf '%s\n' "$data" | awk '/\[upgradable from:/ && /-security/ {n++} END {print n+0}')
    report WARN updates.pending "$count upgrades; $security security-labelled candidates in local cache (not a complete origin classification)"
  else report WARN updates.pending 'APT query failed or unavailable'; fi
  newest=$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*InRelease' -printf '%T@\n' 2>/dev/null | sort -nr | head -1) || newest=""
  now=$(date +%s)
  if [[ -n $newest ]]; then report WARN updates.cache "newest InRelease age: $(( (now - ${newest%%.*}) / 86400 )) days; cache not refreshed, results may be stale";
  else report WARN updates.cache 'no readable InRelease metadata; update counts may be incomplete'; fi
  if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -qx 'install ok installed'; then
    report PASS updates.unattended 'package installed'
  else report WARN updates.unattended 'package absent or package status unavailable'; fi
  if data=$(apt-config dump 2>/dev/null); then
    data=$(printf '%s\n' "$data" | awk '/^APT::Periodic::(Update-Package-Lists|Unattended-Upgrade) /')
    report WARN updates.policy "effective periodic policy (empty means unspecified): $data"
  else report WARN updates.policy 'apt-config unavailable'; fi
  if systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null; then report PASS updates.timer enabled;
  else report WARN updates.timer 'disabled or unavailable'; fi
  if systemctl is-active --quiet apt-daily-upgrade.timer 2>/dev/null; then report PASS updates.timer_runtime active;
  else report WARN updates.timer_runtime 'inactive or unavailable'; fi
  if [[ -e /var/run/reboot-required ]]; then report WARN updates.reboot 'reboot required; no reboot performed';
  else report PASS updates.reboot 'reboot-required marker absent'; fi
}
ufw_audit() {
  local data incoming outgoing
  if data=$(ufw status verbose 2>/dev/null); then
    case $'\n'"$data"$'\n' in
      *$'\nStatus: active\n'*) report PASS ufw.status "$data";;
      *$'\nStatus: inactive\n'*) report FAIL ufw.status "$data";;
      *) report WARN ufw.status "unrecognized status: $data";;
    esac
    incoming=$(printf '%s\n' "$data" | sed -n 's/^Default: \([^ ,]*\) (incoming),.*/\1/p')
    outgoing=$(printf '%s\n' "$data" | sed -n 's/^Default: .*incoming), \([^ ,]*\) (outgoing).*/\1/p')
    if [[ -z $incoming || -z $outgoing ]]; then
      report WARN ufw.policy 'effective default policies unavailable'
    elif [[ $incoming == deny && $outgoing == allow ]]; then
      report PASS ufw.policy 'baseline deny incoming / allow outgoing'
    else
      report FAIL ufw.policy "incoming=$incoming outgoing=$outgoing; expected deny/allow (stricter alternatives require explicit baseline review)"
    fi
  else report WARN ufw.status 'ufw unavailable or insufficient privilege'; fi
  if data=$(ufw show added 2>/dev/null); then report WARN ufw.rules "$data";
  else report WARN ufw.rules 'configured rules unavailable'; fi
  if [[ -r /etc/default/ufw ]]; then
    data=$(awk '/^(DEFAULT_INPUT_POLICY|DEFAULT_OUTPUT_POLICY|IPV6)=/' /etc/default/ufw)
    report WARN ufw.defaults "configured defaults: $data"
  else report WARN ufw.defaults 'defaults unreadable'; fi
  report WARN ufw.scope 'UFW alone does not establish Docker published-port isolation; no rules changed'
}
# All mutations use the Python entry point and its single approval/backup path.
if [[ $MODE == apply ]]; then
  report SKIP apply 'use python3 scripts/harden_check.py plan/apply --fix ...; Bash audit performs no mutations'
  exit 2
fi

ssh_audit
users_audit
updates_audit
ufw_audit
printf '\nSummary: %s FAIL, %s WARN\n' "$FAILS" "$WARNS"
((FAILS == 0)) || exit 1
