#!/usr/bin/env bash
#=====================================================================
#  full_setup.sh  -  FreeSWITCH Full Protection (Fail2ban + Firewall)
#
#  Ki ki kore:
#   1. Purano fail2ban FreeSWITCH/SIP jail, filter, action, script backup kore remove kore
#   2. Notun filter + jail: SIP brute force, password cracking, registration hijack,
#      scanner, ACL reject, slow brute force, toll-guard, recidive (repeat offender)
#   3. iptables rate-limit: SIP flood, RTP flood, TCP SYN flood, DDoS (host level)
#   4. ESL (port 8021) bahir theke block
#   5. Trusted IP whitelist (real client / SIP trunk jeno kokhono ban na hoy)
#   6. FreeSWITCH config audit (weak password, blind-reg, ESL exposure ...)
#
#  Run:   sudo bash full_setup.sh
#  Trusted IP shoho:
#         sudo TRUSTED_IPS="203.0.113.10 198.51.100.0/24" bash full_setup.sh
#=====================================================================
set -u
export LC_ALL=C

say()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Root hisebe chalan:  sudo bash full_setup.sh"

SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"

############################ SETTINGS ###############################
# Sob kichu environment variable diye override kora jay.
TRUSTED_IPS="${TRUSTED_IPS:-}"           # SIP trunk / office / fixed client IP (space diye)
FS_LOG="${FS_LOG:-}"                     # auto-detect hobe
FS_CONF="${FS_CONF:-}"                   # auto-detect hobe
SIP_PORTS="${SIP_PORTS:-5060 5061 5080 5081}"   # WebSocket thakle: "5060 5061 5080 5081 5066 7443"
ESL_PORT="${ESL_PORT:-8021}"
ESL_PROTECT="${ESL_PROTECT:-yes}"        # yes = 8021 bahir theke block
ESL_ALLOW="${ESL_ALLOW:-}"               # onno server theke ESL lagle ekhane IP din
RTP_START="${RTP_START:-16384}"
RTP_END="${RTP_END:-32768}"
WHITELIST_PRIVATE="${WHITELIST_PRIVATE:-yes}"      # 10.x 172.16.x 192.168.x trusted
WHITELIST_REGISTERED="${WHITELIST_REGISTERED:-no}" # ekhon registered IP gulo trusted
CLEAN_OLD="${CLEAN_OLD:-yes}"
PATCH_FS_LOG_AUTH="${PATCH_FS_LOG_AUTH:-yes}"      # sofia profile e log-auth-failures=true

# Fail2ban (seconds). Real client er wrong-password retry safe rakhar jonno lenient.
AUTH_MAXRETRY="${AUTH_MAXRETRY:-8}";  AUTH_FINDTIME="${AUTH_FINDTIME:-300}";   AUTH_BANTIME="${AUTH_BANTIME:-7200}"
SCAN_MAXRETRY="${SCAN_MAXRETRY:-8}";  SCAN_FINDTIME="${SCAN_FINDTIME:-600}";   SCAN_BANTIME="${SCAN_BANTIME:-21600}"
ACL_MAXRETRY="${ACL_MAXRETRY:-10}";   ACL_FINDTIME="${ACL_FINDTIME:-600}";     ACL_BANTIME="${ACL_BANTIME:-21600}"
SLOW_MAXRETRY="${SLOW_MAXRETRY:-60}"; SLOW_FINDTIME="${SLOW_FINDTIME:-86400}"; SLOW_BANTIME="${SLOW_BANTIME:-86400}"
TOLL_MAXRETRY="${TOLL_MAXRETRY:-5}";  TOLL_FINDTIME="${TOLL_FINDTIME:-600}";   TOLL_BANTIME="${TOLL_BANTIME:-21600}"

# Firewall rate limit (per source IP)
SIP_PPS="${SIP_PPS:-100}";   SIP_BURST="${SIP_BURST:-300}"     # SIP packets/sec
SYN_PPS="${SYN_PPS:-30}";    SYN_BURST="${SYN_BURST:-60}"      # new TCP conn/sec
CONN_MAX="${CONN_MAX:-100}"                                    # max parallel TCP conn
RTP_PPS="${RTP_PPS:-3000}";  RTP_BURST="${RTP_BURST:-6000}"    # RTP packets/sec (~60 call)
#####################################################################

BK="/root/fs-protect-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BK"
say "Backup folder: $BK"

#--------------------------- detect FreeSWITCH -----------------------
if [ -z "$FS_LOG" ]; then
  for p in /var/log/freeswitch/freeswitch.log /usr/local/freeswitch/log/freeswitch.log /opt/freeswitch/log/freeswitch.log; do
    [ -f "$p" ] && FS_LOG="$p" && break
  done
fi
[ -n "$FS_LOG" ] && [ -f "$FS_LOG" ] || die "freeswitch.log pawa jai nai. Chalan: FS_LOG=/path/freeswitch.log bash full_setup.sh"
if [ -z "$FS_CONF" ]; then
  for d in /etc/freeswitch /usr/local/freeswitch/conf /opt/freeswitch/conf; do
    [ -f "$d/freeswitch.xml" ] && FS_CONF="$d" && break
  done
fi
say "FreeSWITCH log : $FS_LOG"
say "FreeSWITCH conf: ${FS_CONF:-not found}"

#--------------------------- trusted list ----------------------------
mkdir -p /etc/fs-protect
TL=/etc/fs-protect/trusted.list
[ -f "$TL" ] || cat > "$TL" <<'TL_EOF'
# Trusted IP / CIDR (ek line e ekta). Ekhane thaka IP kokhono fail2ban/rate-limit e ban hobe na.
# SIP trunk provider, office, fixed IP er real client ekhane din.
# Example:
# 203.0.113.10
# 198.51.100.0/24
TL_EOF
add_trusted() { [ -n "$1" ] && { grep -qxF "$1" "$TL" 2>/dev/null || echo "$1" >> "$TL"; }; }

# Purano fail2ban ignoreip theke import (cleaning er ageh)
grep -rhE '^\s*ignoreip\s*=' /etc/fail2ban/jail.local /etc/fail2ban/jail.d --exclude=fs-protect-ignoreip.local 2>/dev/null \
  | sed 's/^[^=]*=//' | tr ' ,' '\n\n' | grep -E '^[0-9a-fA-F:.]+(/[0-9]+)?$' \
  | grep -vE '^(127\.0\.0\.1(/8)?|::1)$' | while read -r ip; do add_trusted "$ip"; done

if [ -z "$TRUSTED_IPS" ] && [ -t 0 ]; then
  echo
  echo "Trusted IP din (SIP trunk provider, office, fixed IP er client). Space diye likhun, na thakle Enter:"
  read -r TRUSTED_IPS
fi
for ip in $TRUSTED_IPS; do add_trusted "$ip"; done
[ -n "${SSH_CLIENT:-}" ] && add_trusted "${SSH_CLIENT%% *}"   # nijeke lockout theke bachano

if [ "$WHITELIST_REGISTERED" = yes ] && command -v fs_cli >/dev/null 2>&1; then
  say "Ekhon registered IP gulo trusted e add hocche..."
  fs_cli -x 'show registrations' 2>/dev/null | awk -F, 'NR==1{for(i=1;i<=NF;i++) if($i=="network_ip") c=i; next} c && $c!=""{print $c}' \
    | sort -u | while read -r ip; do add_trusted "$ip"; done
fi

#--------------------------- packages --------------------------------
say "Package install (fail2ban, iptables, ipset)..."
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1
  apt-get install -y fail2ban iptables ipset >/dev/null || die "apt install fail korse"
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y epel-release >/dev/null 2>&1
  dnf install -y fail2ban ipset iptables-nft >/dev/null 2>&1 || dnf install -y fail2ban ipset iptables >/dev/null || die "dnf install fail korse"
elif command -v yum >/dev/null 2>&1; then
  yum install -y epel-release >/dev/null 2>&1
  yum install -y fail2ban ipset iptables >/dev/null || die "yum install fail korse"
else
  die "Supported package manager pawa jai nai (apt/dnf/yum)"
fi
command -v fail2ban-client >/dev/null 2>&1 || die "fail2ban install hoy nai"
command -v iptables >/dev/null 2>&1 || die "iptables install hoy nai"

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'Status: active'; then
  warn "UFW active - ok, kaj korbe. Tobe SIP/RTP port UFW te allow thaka dorkar."
fi
if systemctl is-active --quiet firewalld 2>/dev/null; then
  warn "firewalld active - fail2ban iptables-allports use korbe. Conflict hole firewalld bondho kore iptables use korun."
fi

#--------------------------- cleanup old setup -----------------------
if [ "$CLEAN_OLD" = yes ]; then
  say "Purano setup clean kora hocche (sob backup e jacche)..."
  systemctl stop fail2ban >/dev/null 2>&1
  cp -a /etc/fail2ban "$BK/fail2ban-etc" 2>/dev/null
  iptables-save > "$BK/iptables.before" 2>/dev/null
  mkdir -p "$BK/removed"

  PAT='(freeswitch|sip|fs-|fs_|esl|voip|toll|rtp)'
  for d in jail.d filter.d action.d; do
    for f in /etc/fail2ban/$d/*; do
      [ -f "$f" ] || continue
      b="${f##*/}"
      case "$b" in defaults-*|fs-protect-*) continue;; esac
      hit=0
      [[ "$b" =~ $PAT ]] && hit=1
      if [ "$d" = jail.d ] && grep -qiE '^\[[^]]*(freeswitch|sip|esl|voip)[^]]*\]' "$f" 2>/dev/null; then hit=1; fi
      if [ "$hit" = 1 ]; then mkdir -p "$BK/removed/$d"; mv "$f" "$BK/removed/$d/"; echo "   removed: $f"; fi
    done
  done

  # jail.local theke freeswitch/sip section remove (baki section thakbe)
  if [ -f /etc/fail2ban/jail.local ]; then
    awk '/^\[/{ s=tolower($0); skip = (s ~ /freeswitch|sip|esl|voip|toll|rtp|fs-/) } !skip{print}' \
      /etc/fail2ban/jail.local > /etc/fail2ban/jail.local.new && mv /etc/fail2ban/jail.local.new /etc/fail2ban/jail.local
  fi

  # Purano custom ban script (shebang + iptables/fail2ban/ipset thakle) backup e soriye dei
  for dir in /usr/local/bin /usr/local/sbin /etc/cron.d /etc/cron.hourly /etc/cron.daily /root /opt; do
    [ -d "$dir" ] || continue
    find "$dir" -maxdepth 1 -type f \( -iname '*f2b*' -o -iname '*fail2ban*' -o -iname '*freeswitch*' \
        -o -iname '*fs*ban*' -o -iname '*sip*' -o -iname '*antiflood*' -o -iname '*ddos*' -o -iname '*block*' \) 2>/dev/null |
    while read -r f; do
      [ "$(readlink -f "$f")" = "$SELF" ] && continue
      case "$f" in */fs-protect|*/fs-protect-*|*/fs_cli|*/freeswitch) continue;; esac
      [ "$(head -c2 "$f" 2>/dev/null)" = '#!' ] || continue
      grep -qIiE 'iptables|fail2ban|ipset|nft ' "$f" 2>/dev/null || continue
      mkdir -p "$BK/removed/scripts"; mv "$f" "$BK/removed/scripts/"; echo "   old script moved: $f"
    done
  done

  if crontab -l 2>/dev/null | grep -qiE 'fail2ban|iptables|f2b|freeswitch'; then
    warn "Crontab e ei line gula ache, ekbar check korun (crontab -e):"
    crontab -l 2>/dev/null | grep -iE 'fail2ban|iptables|f2b|freeswitch' | sed 's/^/     /'
  fi
  if iptables -S 2>/dev/null | grep -E -- '--dport (5060|5061|5080|5081|8021)' | grep -v 'FS-PROTECT' | grep -q .; then
    warn "iptables e purano manual SIP/ESL rule ache (ami chhuyi nai). Check korun: iptables -S | grep -E '5060|5080|8021'"
  fi
fi

#--------------------------- fs-protect CLI --------------------------
say "Config + helper command (fs-protect) install hocche..."
cat > /etc/fs-protect/fs-protect.conf <<CONF_EOF
SIP_PORTS="$SIP_PORTS"
ESL_PORT="$ESL_PORT"
ESL_PROTECT="$ESL_PROTECT"
ESL_ALLOW="$ESL_ALLOW"
RTP_START="$RTP_START"
RTP_END="$RTP_END"
WHITELIST_PRIVATE="$WHITELIST_PRIVATE"
SIP_PPS="$SIP_PPS"
SIP_BURST="$SIP_BURST"
SYN_PPS="$SYN_PPS"
SYN_BURST="$SYN_BURST"
CONN_MAX="$CONN_MAX"
RTP_PPS="$RTP_PPS"
RTP_BURST="$RTP_BURST"
CONF_EOF

cat > /usr/local/sbin/fs-protect <<'CLI_EOF'
#!/usr/bin/env bash
# fs-protect : FreeSWITCH protection helper
export LC_ALL=C
CONF=/etc/fs-protect/fs-protect.conf
TRUSTED=/etc/fs-protect/trusted.list
IGN=/etc/fail2ban/jail.d/fs-protect-ignoreip.local
[ -r "$CONF" ] && . "$CONF"
SIP_PORTS=${SIP_PORTS:-"5060 5061 5080 5081"}; ESL_PORT=${ESL_PORT:-8021}
ESL_PROTECT=${ESL_PROTECT:-yes}; ESL_ALLOW=${ESL_ALLOW:-}
RTP_START=${RTP_START:-16384}; RTP_END=${RTP_END:-32768}
SIP_PPS=${SIP_PPS:-100}; SIP_BURST=${SIP_BURST:-300}
SYN_PPS=${SYN_PPS:-30}; SYN_BURST=${SYN_BURST:-60}; CONN_MAX=${CONN_MAX:-100}
RTP_PPS=${RTP_PPS:-3000}; RTP_BURST=${RTP_BURST:-6000}

all_trusted() {
  {
    echo 127.0.0.0/8; echo ::1
    hostname -I 2>/dev/null | tr ' ' '\n'
    if [ "${WHITELIST_PRIVATE:-yes}" = yes ]; then
      printf '%s\n' 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fe80::/10 fc00::/7
    fi
    grep -vE '^\s*(#|$)' "$TRUSTED" 2>/dev/null | awk '{print $1}'
  } | sed '/^$/d' | sort -u
}

gen_ignore() {
  { echo "# generated by fs-protect - edit /etc/fs-protect/trusted.list"
    echo "[DEFAULT]"
    echo "ignoreip = $(all_trusted | tr '\n' ' ')"; } > "$IGN"
}

fw_build() {   # $1=iptables cmd  $2=4|6
  local ipt=$1 fam=$2 ip s sipcsv mask
  command -v "$ipt" >/dev/null 2>&1 || return 0
  sipcsv=$(echo $SIP_PORTS | tr ' ' ',')
  mask=32; [ "$fam" = 6 ] && mask=128

  $ipt -w -N FS-PROTECT 2>/dev/null || $ipt -w -F FS-PROTECT
  while $ipt -w -D INPUT -j FS-PROTECT 2>/dev/null; do :; done

  $ipt -w -A FS-PROTECT -i lo -j RETURN

  # ESL: sudhu localhost (+ ESL_ALLOW)
  if [ "$ESL_PROTECT" = yes ]; then
    for ip in $ESL_ALLOW; do
      case $ip in *:*) [ "$fam" = 6 ] || continue;; *) [ "$fam" = 4 ] || continue;; esac
      $ipt -w -A FS-PROTECT -p tcp --dport "$ESL_PORT" -s "$ip" -j RETURN
    done
    $ipt -w -A FS-PROTECT -p tcp --dport "$ESL_PORT" -j DROP
  fi

  # Trusted IP: rate-limit bypass
  for ip in $(all_trusted); do
    case $ip in *:*) [ "$fam" = 6 ] || continue;; *) [ "$fam" = 4 ] || continue;; esac
    $ipt -w -A FS-PROTECT -s "$ip" -j RETURN
  done

  # Known SIP scanner user-agent
  for s in friendly-scanner sipvicious sipcli sip-scan iWar sundayddr VaxSIPUserAgent; do
    $ipt -w -A FS-PROTECT -p udp -m multiport --dports "$sipcsv" -m string --algo bm --string "$s" -j DROP 2>/dev/null
    $ipt -w -A FS-PROTECT -p tcp -m multiport --dports "$sipcsv" -m string --algo bm --string "$s" -j DROP 2>/dev/null
  done

  # SIP UDP flood (per source IP)
  $ipt -w -A FS-PROTECT -p udp -m multiport --dports "$sipcsv" -m hashlimit \
       --hashlimit-name fs_sip$fam --hashlimit-mode srcip --hashlimit-above "${SIP_PPS}/second" \
       --hashlimit-burst "$SIP_BURST" -j DROP
  # SIP TCP/TLS: SYN flood + connection limit
  $ipt -w -A FS-PROTECT -p tcp -m multiport --dports "$sipcsv" --syn -m hashlimit \
       --hashlimit-name fs_syn$fam --hashlimit-mode srcip --hashlimit-above "${SYN_PPS}/second" \
       --hashlimit-burst "$SYN_BURST" -j DROP
  $ipt -w -A FS-PROTECT -p tcp -m multiport --dports "$sipcsv" -m connlimit \
       --connlimit-above "$CONN_MAX" --connlimit-mask $mask -j REJECT --reject-with tcp-reset
  # RTP flood (per source IP)
  $ipt -w -A FS-PROTECT -p udp --dport "${RTP_START}:${RTP_END}" -m hashlimit \
       --hashlimit-name fs_rtp$fam --hashlimit-mode srcip --hashlimit-above "${RTP_PPS}/second" \
       --hashlimit-burst "$RTP_BURST" -j DROP

  $ipt -w -A FS-PROTECT -j RETURN
  $ipt -w -I INPUT 1 -j FS-PROTECT
}

fw_off() {
  for ipt in iptables ip6tables; do
    command -v $ipt >/dev/null 2>&1 || continue
    while $ipt -w -D INPUT -j FS-PROTECT 2>/dev/null; do :; done
    $ipt -w -F FS-PROTECT 2>/dev/null; $ipt -w -X FS-PROTECT 2>/dev/null
  done
}
fw_on() { fw_build iptables 4; fw_build ip6tables 6; }
jails() { fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ','; }

case "${1:-}" in
  firewall)      fw_on ;;
  firewall-off)  fw_off ;;
  gen-ignore)    gen_ignore ;;
  apply)         gen_ignore; fail2ban-client reload >/dev/null 2>&1; fw_on; echo "applied" ;;
  trust)
    ip=${2:-}
    [[ $ip =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || { echo "Usage: fs-protect trust <IP|CIDR>"; exit 1; }
    grep -qxF "$ip" "$TRUSTED" 2>/dev/null || echo "$ip" >> "$TRUSTED"
    fail2ban-client unban "$ip" >/dev/null 2>&1
    gen_ignore; fail2ban-client reload >/dev/null 2>&1; fw_on
    echo "trusted: $ip" ;;
  untrust)
    ip=${2:-}; [ -n "$ip" ] || { echo "Usage: fs-protect untrust <IP|CIDR>"; exit 1; }
    sed -i "\|^${ip}\$|d" "$TRUSTED"
    gen_ignore; fail2ban-client reload >/dev/null 2>&1; fw_on
    echo "removed from trusted: $ip" ;;
  unban)
    ip=${2:-}; [ -n "$ip" ] || { echo "Usage: fs-protect unban <IP>"; exit 1; }
    fail2ban-client unban "$ip" 2>/dev/null || for j in $(jails); do fail2ban-client set "$j" unbanip "$ip" >/dev/null 2>&1; done
    echo "unbanned: $ip (jodi banned thake)" ;;
  status)
    echo "=== Fail2ban jails ==="
    for j in $(jails); do
      echo "--- $j"; fail2ban-client status "$j" | sed -n '/Currently banned/p;/Total banned/p;/Banned IP list/p'
    done
    echo; echo "=== Firewall FS-PROTECT (dropped packets) ==="
    iptables -w -L FS-PROTECT -n -v 2>/dev/null | grep -E 'DROP|REJECT' | awk '$1!=0 {print}' | head -20
    echo; echo "=== Trusted ==="; all_trusted | tr '\n' ' '; echo ;;
  uninstall)
    systemctl disable --now fs-protect-firewall >/dev/null 2>&1
    fw_off
    rm -f /etc/fail2ban/jail.d/fs-protect-*.local /etc/fail2ban/filter.d/freeswitch-*.conf \
          /etc/systemd/system/fs-protect-firewall.service /etc/sysctl.d/99-fs-protect.conf
    systemctl daemon-reload; fail2ban-client reload >/dev/null 2>&1
    echo "Removed. (/etc/fs-protect config rakha hoyeche; chaile muchun)" ;;
  *)
    echo "fs-protect {status|apply|trust IP|untrust IP|unban IP|firewall|firewall-off|uninstall}" ;;
esac
CLI_EOF
chmod 755 /usr/local/sbin/fs-protect

#--------------------------- fail2ban filters ------------------------
say "Fail2ban filter likha hocche..."
F=/etc/fail2ban/filter.d

cat > $F/freeswitch-auth.conf <<'F_EOF'
# SIP auth failure (REGISTER/INVITE/...) : brute force, password cracking, registration hijack
# NOTE: "challenge" match kora hoy na - karon real client er prottek register e challenge ashe.
[Definition]
failregex = \[WARNING\] sofia_reg\.c:\d+ SIP auth failure \(\w+\) on sofia/\S+ from ip <HOST>
ignoreregex =
F_EOF

cat > $F/freeswitch-scan.conf <<'F_EOF'
# Unknown user / extension scanning (SIPVicious type scan, gateway abuse try)
[Definition]
failregex = \[WARNING\] \S+\.c:\d+ Can't find user \[[^\]]*\] from <HOST>
ignoreregex =
F_EOF

cat > $F/freeswitch-acl.conf <<'F_EOF'
# ACL reject (SIP + ESL). "Falling back to Digest auth" holo normal ar real client er jonno, ota ignore.
[Definition]
failregex = \[WARNING\] \S+\.c:\d+ IP <HOST> Rejected by acl
ignoreregex = Falling back to Digest auth
F_EOF

cat > $F/freeswitch-tollguard.conf <<'F_EOF'
# Dialplan toll-guard log line (/etc/fs-protect/toll-guard-dialplan.xml.example dekhun)
[Definition]
failregex = TOLL-GUARD blocked \S+ from <HOST>
ignoreregex =
F_EOF

#--------------------------- fail2ban jails --------------------------
say "Fail2ban jail likha hocche..."
mkjail() { # name filter maxretry findtime bantime
cat <<JAIL_EOF
[$1]
enabled   = true
filter    = $2
logpath   = $FS_LOG
backend   = auto
maxretry  = $3
findtime  = $4
bantime   = $5
banaction = iptables-allports
protocol  = all

JAIL_EOF
}
{
  echo "# Generated by full_setup.sh on $(date)"
  mkjail freeswitch-auth       freeswitch-auth       "$AUTH_MAXRETRY" "$AUTH_FINDTIME" "$AUTH_BANTIME"
  mkjail freeswitch-slowbrute  freeswitch-auth       "$SLOW_MAXRETRY" "$SLOW_FINDTIME" "$SLOW_BANTIME"
  mkjail freeswitch-scan       freeswitch-scan       "$SCAN_MAXRETRY" "$SCAN_FINDTIME" "$SCAN_BANTIME"
  mkjail freeswitch-acl        freeswitch-acl        "$ACL_MAXRETRY"  "$ACL_FINDTIME"  "$ACL_BANTIME"
  mkjail freeswitch-tollguard  freeswitch-tollguard  "$TOLL_MAXRETRY" "$TOLL_FINDTIME" "$TOLL_BANTIME"
  cat <<REC_EOF
# Repeat offender: onno jail e 3 bar ban hole 1 soptaho ban
[recidive]
enabled   = true
filter    = recidive
logpath   = /var/log/fail2ban.log
backend   = auto
maxretry  = 3
findtime  = 86400
bantime   = 604800
banaction = iptables-allports
protocol  = all
REC_EOF
} > /etc/fail2ban/jail.d/fs-protect-jails.local

touch /var/log/fail2ban.log
[ -f /etc/fail2ban/fail2ban.local ] || printf '[Definition]\nlogtarget = /var/log/fail2ban.log\n' > /etc/fail2ban/fail2ban.local

/usr/local/sbin/fs-protect gen-ignore

#--------------------------- toll guard example ----------------------
cat > /etc/fs-protect/toll-guard-dialplan.xml.example <<'DP_EOF'
<!--
  TOLL FRAUD GUARD (optional) - ei extension gulo dialplan e SOBAR AGE boshan
  (e.g. dialplan/default.xml / public.xml er shuru te), tarpor FreeSWITCH reload korun.
  "BLOCKED|PREFIXES" er jaygay je country/premium prefix apni kokhono call koren na segulo din.
-->
<extension name="toll-guard-blocked-prefix" continue="false">
  <condition field="destination_number" expression="^(\+|00|011)?(BLOCKED|PREFIXES)">
    <action application="log" data="WARNING TOLL-GUARD blocked ${destination_number} from ${network_addr}"/>
    <action application="respond" data="403"/>
  </condition>
</extension>

<!-- Ek user/extension er max concurrent outbound call (ekhane 5) -->
<extension name="toll-guard-concurrency" continue="true">
  <condition field="destination_number" expression="^(\+|00|011)\d+$">
    <action application="limit" data="hash outbound ${caller_id_number} 5 !NORMAL_TEMPORARY_FAILURE"/>
  </condition>
</extension>
DP_EOF

#--------------------------- patch FS profiles -----------------------
PATCHED=0
if [ "$PATCH_FS_LOG_AUTH" = yes ] && [ -n "$FS_CONF" ]; then
  mkdir -p "$BK/freeswitch-conf"
  for f in "$FS_CONF"/sip_profiles/*.xml; do
    [ -f "$f" ] || continue
    if grep -qE '^\s*<param name="log-auth-failures"' "$f"; then
      if grep -qE '^\s*<param name="log-auth-failures" value="false"' "$f"; then
        cp -a "$f" "$BK/freeswitch-conf/"
        sed -i -E 's/(<param name="log-auth-failures" value=")false/\1true/' "$f"; PATCHED=1
        say "log-auth-failures=true set: $f"
      fi
    elif grep -q '<settings>' "$f"; then
      cp -a "$f" "$BK/freeswitch-conf/"
      sed -i '0,/<settings>/s//<settings>\n    <param name="log-auth-failures" value="true"\/>/' "$f"; PATCHED=1
      say "log-auth-failures=true added: $f"
    fi
  done
fi

#--------------------------- sysctl + firewall service ---------------
cat > /etc/sysctl.d/99-fs-protect.conf <<'SYS_EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
SYS_EOF
sysctl --system >/dev/null 2>&1

cat > /etc/systemd/system/fs-protect-firewall.service <<'UNIT_EOF'
[Unit]
Description=FreeSWITCH firewall protection (rate limits, ESL block)
After=network-online.target
Wants=network-online.target
Before=fail2ban.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/fs-protect firewall
ExecReload=/usr/local/sbin/fs-protect firewall
ExecStop=/usr/local/sbin/fs-protect firewall-off

[Install]
WantedBy=multi-user.target
UNIT_EOF
systemctl daemon-reload
systemctl enable fs-protect-firewall >/dev/null 2>&1
systemctl restart fs-protect-firewall || warn "fs-protect-firewall start hoy nai: journalctl -u fs-protect-firewall"

#--------------------------- test + start fail2ban -------------------
say "Fail2ban config test..."
if ! fail2ban-client -t >/tmp/fs-protect-f2b-test.txt 2>&1; then
  cat /tmp/fs-protect-f2b-test.txt
  die "Fail2ban config e error. Backup: $BK"
fi

say "Filter regex self-test..."
t() { printf '%s\n' "$2" > /tmp/fs-protect-test.log
      printf '   %-22s %s\n' "$1" "$(fail2ban-regex /tmp/fs-protect-test.log "$F/$1.conf" 2>/dev/null | grep -E '^Lines:')"; }
t freeswitch-auth  '2026-11-20 10:00:00.123456 [WARNING] sofia_reg.c:1661 SIP auth failure (REGISTER) on sofia/internal/1000@example.com from ip 203.0.113.5'
t freeswitch-scan  '2026-11-20 10:00:00.123456 [WARNING] sofia_reg.c:1892 Can'"'"'t find user [100@203.0.113.9] from 203.0.113.5'
t freeswitch-acl   '2026-11-20 10:00:00.123456 [WARNING] sofia.c:1234 IP 203.0.113.5 Rejected by acl "domains"'
t freeswitch-acl   '2026-11-20 10:00:00.123456 [WARNING] sofia_reg.c:1234 IP 203.0.113.5 Rejected by acl "domains". Falling back to Digest auth.'
echo "   (upore acl er 2nd line ignored hoye 0 matched howa uchit)"
rm -f /tmp/fs-protect-test.log

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban || die "fail2ban start hoy nai: journalctl -u fail2ban"
sleep 2

#--------------------------- FreeSWITCH audit ------------------------
echo
echo "================ FreeSWITCH config audit ================"
if [ -n "$FS_CONF" ]; then
  dp=$(grep -hoE 'default_password=[^"]*' "$FS_CONF/vars.xml" 2>/dev/null | head -1 | cut -d= -f2)
  [ "$dp" = "1234" ] && warn "vars.xml: default_password=1234 - ekhoni change korun (toll fraud er #1 karon)"

  ev="$FS_CONF/autoload_configs/event_socket.conf.xml"
  if [ -f "$ev" ]; then
    lip=$(grep -hoE 'name="listen-ip" value="[^"]*"' "$ev" | head -1 | sed 's/.*value="//;s/"//')
    case "$lip" in 127.0.0.1|::1) : ;; *) warn "ESL listen-ip=$lip - 127.0.0.1 kore din (firewall ekhon bahir theke block rakhche)";; esac
    grep -q 'name="password" value="ClueCon"' "$ev" && warn "ESL password ekhono default ClueCon - change korun"
  fi

  bl=$(grep -lE '<param name="accept-blind-(reg|auth)" value="true"' "$FS_CONF"/sip_profiles/*.xml "$FS_CONF"/sip_profiles/*/*.xml 2>/dev/null)
  [ -n "$bl" ] && warn "accept-blind-reg/auth=true ache (khub dangerous): $bl"

  weak=$(grep -rhoE 'name="password" value="[^"]*"' "$FS_CONF/directory" 2>/dev/null | sed 's/.*value="//;s/"$//' \
         | awk 'length($0)<8 || $0 ~ /^[0-9]+$/' | wc -l)
  [ "$weak" -gt 0 ] && warn "$weak ta user password dur-bol (8 char er kom ba sudhu number). 16+ random password din."
else
  warn "FS conf dir pawa jai nai, audit skip."
fi
if ss -ltn 2>/dev/null | grep -E ":${ESL_PORT}\b" | grep -vE '127\.0\.0\.1|\[::1\]' | grep -q .; then
  warn "ESL port $ESL_PORT sob interface e listen kortese - firewall block rakhche, tobuo 127.0.0.1 e restrict korun."
fi

#--------------------------- summary ---------------------------------
echo
echo "================ DONE ================"
fail2ban-client status 2>/dev/null | sed 's/^/   /'
echo
echo "Trusted list : /etc/fs-protect/trusted.list   ($(grep -cvE '^\s*(#|$)' "$TL") ta entry)"
echo "Backup       : $BK"
echo
echo "Daily commands:"
echo "   fs-protect status            # ke banned, koto packet drop"
echo "   fs-protect trust  1.2.3.4    # real client/trunk ke permanent whitelist"
echo "   fs-protect unban  1.2.3.4    # ban khule dewa"
echo "   fail2ban-client status freeswitch-auth"
echo
if [ "$PATCHED" = 1 ]; then
  warn "FreeSWITCH profile e log-auth-failures set kora hoyeche. Effect nite profile restart lagbe"
  warn "(kichhukkhon registration drop hoy, kom busy somoye korun):"
  warn "   fs_cli -x 'sofia profile internal restart'; fs_cli -x 'sofia profile external restart'"
fi
echo "Optional toll-guard dialplan: /etc/fs-protect/toll-guard-dialplan.xml.example"
echo "ESL onno server theke lagle:  ESL_ALLOW=\"x.x.x.x\" bash full_setup.sh"
