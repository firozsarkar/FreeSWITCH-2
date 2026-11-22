#!/usr/bin/env bash
#=====================================================================
#  full_setup.sh (v2 - AUTO)  FreeSWITCH Full Protection
#  Kono IP list dite hobe na. Shob auto shikhe nibe.
#
#  Auto-trust (kokhono ban/rate-limit hobe na):
#    - ekhon FreeSWITCH e registered shob client IP   (10 sec por por refresh)
#    - active call er IP (IP-auth carrier shoho)
#    - gateway/trunk config er proxy/realm (DNS resolve kore)
#    - acl.conf.xml er allow CIDR
#    - current SSH session (nijeke lockout theke bachano)
#    - server er nijer IP, localhost, private LAN
#    - remote ESL client (jara ekhon 8021 e connected)
#
#  Protection:
#    SIP brute force, password cracking, registration hijack attempt, SIP scan,
#    gateway abuse, toll-fraud guard, SIP flood, RTP flood, SYN flood/DDoS (host level),
#    ESL attack, repeat offender (1 week ban)
#
#  Run:  sudo bash full_setup.sh
#=====================================================================
set -u
export LC_ALL=C

say()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Root hisebe chalan:  sudo bash full_setup.sh"
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"

############ OPTIONAL SETTINGS (kichu na dilew cholbe) ##############
FS_LOG="${FS_LOG:-}"
FS_CONF="${FS_CONF:-}"
TRUSTED_IPS="${TRUSTED_IPS:-}"                   # optional extra
SIP_PORTS="${SIP_PORTS:-5060 5061 5080 5081}"    # WebSocket thakle 5066 7443 jog korun
ESL_PORT="${ESL_PORT:-8021}"
ESL_PROTECT="${ESL_PROTECT:-yes}"
ESL_ALLOW="${ESL_ALLOW:-}"
RTP_START="${RTP_START:-16384}"
RTP_END="${RTP_END:-32768}"
WHITELIST_PRIVATE="${WHITELIST_PRIVATE:-yes}"
TRUST_ACTIVE_CALLS="${TRUST_ACTIVE_CALLS:-yes}"
CLEAN_OLD="${CLEAN_OLD:-yes}"
PATCH_FS_LOG_AUTH="${PATCH_FS_LOG_AUTH:-yes}"

# Fail2ban (seconds)
AUTH_MAXRETRY="${AUTH_MAXRETRY:-10}"; AUTH_FINDTIME="${AUTH_FINDTIME:-300}";   AUTH_BANTIME="${AUTH_BANTIME:-7200}"
SCAN_MAXRETRY="${SCAN_MAXRETRY:-8}";  SCAN_FINDTIME="${SCAN_FINDTIME:-600}";   SCAN_BANTIME="${SCAN_BANTIME:-21600}"
ACL_MAXRETRY="${ACL_MAXRETRY:-10}";   ACL_FINDTIME="${ACL_FINDTIME:-600}";     ACL_BANTIME="${ACL_BANTIME:-21600}"
SLOW_MAXRETRY="${SLOW_MAXRETRY:-60}"; SLOW_FINDTIME="${SLOW_FINDTIME:-86400}"; SLOW_BANTIME="${SLOW_BANTIME:-86400}"
TOLL_MAXRETRY="${TOLL_MAXRETRY:-5}";  TOLL_FINDTIME="${TOLL_FINDTIME:-600}";   TOLL_BANTIME="${TOLL_BANTIME:-21600}"

# Firewall limit - sudhu ONJANA IP er jonno (learned/trusted IP bypass kore)
SIP_PPS="${SIP_PPS:-100}";   SIP_BURST="${SIP_BURST:-300}"
SYN_PPS="${SYN_PPS:-30}";    SYN_BURST="${SYN_BURST:-60}"
CONN_MAX="${CONN_MAX:-100}"
RTP_PPS="${RTP_PPS:-1500}";  RTP_BURST="${RTP_BURST:-3000}"
#####################################################################

BK="/root/fs-protect-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BK" /etc/fs-protect /var/lib/fs-protect
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
FS_CLI="$(command -v fs_cli 2>/dev/null)"
if [ -z "$FS_CLI" ]; then
  for p in /usr/local/freeswitch/bin/fs_cli /opt/freeswitch/bin/fs_cli /usr/bin/fs_cli; do
    [ -x "$p" ] && FS_CLI="$p" && break
  done
fi
FS_ESL_PASS="ClueCon"
if [ -n "$FS_CONF" ] && [ -f "$FS_CONF/autoload_configs/event_socket.conf.xml" ]; then
  pw=$(grep -hoE 'name="password" value="[^"]*"' "$FS_CONF/autoload_configs/event_socket.conf.xml" | head -1 | sed 's/.*value="//;s/"$//')
  [ -n "$pw" ] && [[ "$pw" != *'$'* ]] && FS_ESL_PASS="$pw"
fi
say "FreeSWITCH log : $FS_LOG"
say "FreeSWITCH conf: ${FS_CONF:-not found}"
say "fs_cli         : ${FS_CLI:-not found}"

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
command -v ipset >/dev/null 2>&1 || die "ipset install hoy nai"
ipset create -exist fs_probe hash:ip 2>/dev/null && ipset destroy fs_probe 2>/dev/null || die "Kernel e ipset kaj korche na (container/VPS restriction?)"

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'Status: active'; then
  warn "UFW active - ok. SIP/RTP port UFW te allow thaka dorkar."
fi
systemctl is-active --quiet firewalld 2>/dev/null && warn "firewalld active - conflict hole firewalld bondho kore iptables use korun."

# Purano fs-protect (v1) thakle bondho
systemctl stop fs-protect-learn fs-protect-firewall >/dev/null 2>&1

#--------------------------- trusted.list (optional manual) ----------
TL=/etc/fs-protect/trusted.list
[ -f "$TL" ] || cat > "$TL" <<'TL_EOF'
# OPTIONAL manual trusted IP/CIDR (ek line e ekta). Auto-learn er pore eta dorkar nei,
# tobe kono fixed IP sobsomoy trusted rakhte chaile ekhane likhun.
TL_EOF
add_trusted() { [ -n "$1" ] && { grep -qxF "$1" "$TL" 2>/dev/null || echo "$1" >> "$TL"; }; }

# Purano fail2ban ignoreip theke import (cleaning er ageh)
grep -rhE '^\s*ignoreip\s*=' /etc/fail2ban/jail.local /etc/fail2ban/jail.d --exclude=fs-protect-ignoreip.local 2>/dev/null \
  | sed 's/^[^=]*=//' | tr ' ,' '\n\n' | grep -E '^[0-9a-fA-F:.]+(/[0-9]+)?$' \
  | grep -vE '^(127\.0\.0\.1(/8)?|::1)$' | while read -r ip; do add_trusted "$ip"; done
for ip in $TRUSTED_IPS; do add_trusted "$ip"; done
[ -n "${SSH_CLIENT:-}" ] && add_trusted "${SSH_CLIENT%% *}"

#--------------------------- ESL remote client auto-detect -----------
if [ "$ESL_PROTECT" = yes ]; then
  own=" $(hostname -I 2>/dev/null) "
  for p in $(ss -Htn state established "( sport = :$ESL_PORT )" 2>/dev/null | awk '{print $4}' | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' | sort -u); do
    case "$p" in 127.*|::1|"") continue;; esac
    case "$own" in *" $p "*) continue;; esac
    ESL_ALLOW="$ESL_ALLOW $p"
    say "Remote ESL client pawa gese, allow kora hoyeche: $p"
  done
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

  if [ -f /etc/fail2ban/jail.local ]; then
    awk '/^\[/{ s=tolower($0); skip = (s ~ /freeswitch|sip|esl|voip|toll|rtp|fs-/) } !skip{print}' \
      /etc/fail2ban/jail.local > /etc/fail2ban/jail.local.new && mv /etc/fail2ban/jail.local.new /etc/fail2ban/jail.local
  fi

  for dir in /usr/local/bin /usr/local/sbin /etc/cron.d /etc/cron.hourly /etc/cron.daily /root /opt; do
    [ -d "$dir" ] || continue
    find "$dir" -maxdepth 1 -type f \( -iname '*f2b*' -o -iname '*fail2ban*' -o -iname '*freeswitch*' \
        -o -iname '*fs*ban*' -o -iname '*sip*' -o -iname '*antiflood*' -o -iname '*ddos*' -o -iname '*block*' \) 2>/dev/null |
    while read -r f; do
      [ "$(readlink -f "$f")" = "$SELF" ] && continue
      case "$f" in */fs-protect|*/fs-protect-*|*/fs-is-trusted|*/fs_cli|*/freeswitch) continue;; esac
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
    warn "iptables e purano manual SIP/ESL rule ache (ami chhuyi nai). Check: iptables -S | grep -E '5060|5080|8021'"
  fi
fi

#--------------------------- config file -----------------------------
{
  echo "SIP_PORTS=\"$SIP_PORTS\""
  echo "ESL_PORT=\"$ESL_PORT\""
  echo "ESL_PROTECT=\"$ESL_PROTECT\""
  echo "ESL_ALLOW=\"$ESL_ALLOW\""
  echo "RTP_START=\"$RTP_START\""
  echo "RTP_END=\"$RTP_END\""
  echo "WHITELIST_PRIVATE=\"$WHITELIST_PRIVATE\""
  echo "TRUST_ACTIVE_CALLS=\"$TRUST_ACTIVE_CALLS\""
  echo "SIP_PPS=\"$SIP_PPS\""; echo "SIP_BURST=\"$SIP_BURST\""
  echo "SYN_PPS=\"$SYN_PPS\""; echo "SYN_BURST=\"$SYN_BURST\""
  echo "CONN_MAX=\"$CONN_MAX\""
  echo "RTP_PPS=\"$RTP_PPS\""; echo "RTP_BURST=\"$RTP_BURST\""
  echo "FS_CONF=\"$FS_CONF\""
  echo "FS_CLI=\"$FS_CLI\""
  printf 'FS_ESL_PASS=%q\n' "$FS_ESL_PASS"
} > /etc/fs-protect/fs-protect.conf
chmod 600 /etc/fs-protect/fs-protect.conf

#--------------------------- fs-is-trusted (fail2ban ignorecommand) --
cat > /usr/local/sbin/fs-is-trusted <<'ISTR_EOF'
#!/bin/sh
# exit 0 = trusted (fail2ban ei IP ke kokhono ban korbe na)
ip="$1"
case "$ip" in *:*) s=fs_trusted6;; *) s=fs_trusted;; esac
ipset test "$s" "$ip" >/dev/null 2>&1
ISTR_EOF
chmod 755 /usr/local/sbin/fs-is-trusted

#--------------------------- fs-protect CLI --------------------------
say "fs-protect (auto-learn + firewall helper) install hocche..."
cat > /usr/local/sbin/fs-protect <<'CLI_EOF'
#!/usr/bin/env bash
# fs-protect : FreeSWITCH auto protection helper
export LC_ALL=C
CONF=/etc/fs-protect/fs-protect.conf
TRUSTED=/etc/fs-protect/trusted.list
STATE=/var/lib/fs-protect
IGN=/etc/fail2ban/jail.d/fs-protect-ignoreip.local
[ -r "$CONF" ] && . "$CONF"
SIP_PORTS=${SIP_PORTS:-"5060 5061 5080 5081"}; ESL_PORT=${ESL_PORT:-8021}
ESL_PROTECT=${ESL_PROTECT:-yes}; ESL_ALLOW=${ESL_ALLOW:-}
RTP_START=${RTP_START:-16384}; RTP_END=${RTP_END:-32768}
SIP_PPS=${SIP_PPS:-100}; SIP_BURST=${SIP_BURST:-300}
SYN_PPS=${SYN_PPS:-30}; SYN_BURST=${SYN_BURST:-60}; CONN_MAX=${CONN_MAX:-100}
RTP_PPS=${RTP_PPS:-1500}; RTP_BURST=${RTP_BURST:-3000}
TRUST_ACTIVE_CALLS=${TRUST_ACTIVE_CALLS:-yes}
FS_CONF=${FS_CONF:-}; FS_CLI=${FS_CLI:-}; FS_ESL_PASS=${FS_ESL_PASS:-ClueCon}
mkdir -p "$STATE"

#---------------- ipset ----------------
ipset_init() {
  ipset create -exist fs_trusted  hash:net timeout 86400 maxelem 262144 2>/dev/null
  ipset create -exist fs_trusted6 hash:net family inet6 timeout 86400 maxelem 65536 2>/dev/null
}
ipset_save() {
  { ipset save fs_trusted; ipset save fs_trusted6; } > "$STATE/trusted.ipset.tmp" 2>/dev/null \
    && mv "$STATE/trusted.ipset.tmp" "$STATE/trusted.ipset"
}
ipset_restore() { [ -s "$STATE/trusted.ipset" ] && ipset restore -exist < "$STATE/trusted.ipset" 2>/dev/null; return 0; }

ok_net() {
  local n=$1 p
  [[ $n =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || return 1
  case $n in *.*|*:*) ;; *) return 1;; esac
  case $n in 0.0.0.0*|::|::/*|255.*) return 1;; esac
  if [[ $n == */* ]]; then
    p=${n#*/}
    case $n in *:*) [ "$p" -ge 32 ] || return 1;; *) [ "$p" -ge 8 ] || return 1;; esac
  fi
  return 0
}
trust_add() {  # $1=ip/cidr  $2=timeout seconds
  local s=fs_trusted
  ok_net "$1" || return 1
  case $1 in *:*) s=fs_trusted6;; esac
  ipset add -exist "$s" "$1" timeout "${2:-86400}" 2>/dev/null
}

#---------------- learn ----------------
fscli() { [ -n "$FS_CLI" ] && [ -x "$FS_CLI" ] && timeout 6 "$FS_CLI" -H 127.0.0.1 -P "$ESL_PORT" -p "$FS_ESL_PASS" -x "$1" 2>/dev/null; }

strip_xml() {
  awk '{ s=$0; out="";
         while (1) {
           if (c) { i=index(s,"-->"); if (!i) { s=""; break } s=substr(s,i+3); c=0 }
           else   { i=index(s,"<!--"); if (!i) { out=out s; break } out=out substr(s,1,i-1); s=substr(s,i+4); c=1 }
         }
         print out }' "$@"
}

learn_fast() {   # every ~10s
  local ip sshp
  # 1) Registered client
  fscli 'show registrations as json' | tr '}' '\n' \
    | sed -nE 's/.*"network_ip": *"([^"]*)".*/\1/p' | sort -u \
    | while read -r ip; do trust_add "$ip" 86400; done
  # 2) Active (answered) call - IP-auth carrier ke cover kore
  if [ "$TRUST_ACTIVE_CALLS" = yes ]; then
    fscli 'show channels as json' | tr '}' '\n' | grep -E '"callstate": *"ACTIVE"' \
      | sed -nE 's/.*"ip_addr": *"([^"]*)".*/\1/p' | sort -u \
      | while read -r ip; do trust_add "$ip" 3600; done
  fi
  # 3) Current SSH session
  sshp=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}'); sshp=${sshp:-22}
  ss -Htn state established "( sport = :$sshp )" 2>/dev/null | awk '{print $4}' \
    | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' | sort -u \
    | while read -r ip; do trust_add "$ip" 86400; done
}

learn_slow() {   # every ~15 min
  local h ip hosts
  [ -n "$FS_CONF" ] && [ -d "$FS_CONF" ] || return 0
  # 4) Gateway / trunk proxy + realm
  hosts=$(find "$FS_CONF/sip_profiles" -name '*.xml' -exec cat {} + 2>/dev/null | strip_xml \
    | grep -oE 'name="(proxy|register-proxy|outbound-proxy|realm)" value="[^"]+"' \
    | sed -E 's/.*value="([^"]*)"/\1/' \
    | sed -E 's#^sips?:##; s#^[^@]*@##; s#:[0-9]+$##' \
    | grep -E '^[A-Za-z0-9._-]+$' | sort -u)
  for h in $hosts; do
    if [[ $h =~ ^[0-9.]+$ ]]; then trust_add "$h" 21600
    else getent ahosts "$h" 2>/dev/null | awk '{print $1}' | sort -u | while read -r ip; do trust_add "$ip" 21600; done
    fi
  done
  # 5) ACL allow CIDR (admin ne nijei allow korse)
  if [ -f "$FS_CONF/autoload_configs/acl.conf.xml" ]; then
    strip_xml "$FS_CONF/autoload_configs/acl.conf.xml" | grep -oE 'type="allow"[^>]*cidr="[^"]+"|cidr="[^"]+"[^>]*type="allow"' \
      | grep -oE 'cidr="[^"]+"' | sed 's/cidr="//;s/"//' | tr ',' '\n' | sed 's/ //g' \
      | while read -r ip; do [ -n "$ip" ] && trust_add "$ip" 21600; done
  fi
}

learn_once() { ipset_init; learn_fast; learn_slow; ipset_save; }

daemon() {
  ipset_init; ipset_restore
  trap 'ipset_save; exit 0' TERM INT
  local n=0
  while :; do
    learn_fast
    [ $((n % 90)) -eq 0 ] && learn_slow
    [ $((n % 6))  -eq 0 ] && ipset_save
    n=$((n+1))
    sleep 10 & wait $!
  done
}

#---------------- static trusted ----------------
all_static() {
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
  { echo "# generated by fs-protect (static). Dynamic trust: fs-is-trusted (ipset)"
    echo "[DEFAULT]"
    echo "ignoreip = $(all_static | tr '\n' ' ')"; } > "$IGN"
}

#---------------- firewall ----------------
fw_build() {   # $1=iptables cmd  $2=4|6
  local ipt=$1 fam=$2 ip s sipcsv mask setn=fs_trusted
  command -v "$ipt" >/dev/null 2>&1 || return 0
  sipcsv=$(echo $SIP_PORTS | tr ' ' ',')
  mask=32; [ "$fam" = 6 ] && { mask=128; setn=fs_trusted6; }

  $ipt -w -N FS-PROTECT 2>/dev/null || $ipt -w -F FS-PROTECT
  while $ipt -w -D INPUT -j FS-PROTECT 2>/dev/null; do :; done

  $ipt -w -A FS-PROTECT -i lo -j RETURN

  if [ "$ESL_PROTECT" = yes ]; then
    for ip in $ESL_ALLOW; do
      case $ip in *:*) [ "$fam" = 6 ] || continue;; *) [ "$fam" = 4 ] || continue;; esac
      $ipt -w -A FS-PROTECT -p tcp --dport "$ESL_PORT" -s "$ip" -j RETURN
    done
    $ipt -w -A FS-PROTECT -p tcp --dport "$ESL_PORT" -j DROP
  fi

  # Auto-learned trusted (registered client, trunk, active call ...)
  $ipt -w -A FS-PROTECT -m set --match-set "$setn" src -j RETURN 2>/dev/null
  # Static trusted (own IP, LAN, manual list)
  for ip in $(all_static); do
    case $ip in *:*) [ "$fam" = 6 ] || continue;; *) [ "$fam" = 4 ] || continue;; esac
    $ipt -w -A FS-PROTECT -s "$ip" -j RETURN
  done

  for s in friendly-scanner sipvicious sipcli sip-scan iWar sundayddr VaxSIPUserAgent; do
    $ipt -w -A FS-PROTECT -p udp -m multiport --dports "$sipcsv" -m string --algo bm --string "$s" -j DROP 2>/dev/null
    $ipt -w -A FS-PROTECT -p tcp -m multiport --dports "$sipcsv" -m string --algo bm --string "$s" -j DROP 2>/dev/null
  done

  $ipt -w -A FS-PROTECT -p udp -m multiport --dports "$sipcsv" -m hashlimit \
       --hashlimit-name fs_sip$fam --hashlimit-mode srcip --hashlimit-above "${SIP_PPS}/second" \
       --hashlimit-burst "$SIP_BURST" -j DROP
  $ipt -w -A FS-PROTECT -p tcp -m multiport --dports "$sipcsv" --syn -m hashlimit \
       --hashlimit-name fs_syn$fam --hashlimit-mode srcip --hashlimit-above "${SYN_PPS}/second" \
       --hashlimit-burst "$SYN_BURST" -j DROP
  $ipt -w -A FS-PROTECT -p tcp -m multiport --dports "$sipcsv" -m connlimit \
       --connlimit-above "$CONN_MAX" --connlimit-mask $mask -j REJECT --reject-with tcp-reset
  $ipt -w -A FS-PROTECT -p udp --dport "${RTP_START}:${RTP_END}" -m hashlimit \
       --hashlimit-name fs_rtp$fam --hashlimit-mode srcip --hashlimit-above "${RTP_PPS}/second" \
       --hashlimit-burst "$RTP_BURST" -j DROP

  $ipt -w -A FS-PROTECT -j RETURN
  $ipt -w -I INPUT 1 -j FS-PROTECT
}
fw_off() {
  local ipt
  for ipt in iptables ip6tables; do
    command -v $ipt >/dev/null 2>&1 || continue
    while $ipt -w -D INPUT -j FS-PROTECT 2>/dev/null; do :; done
    $ipt -w -F FS-PROTECT 2>/dev/null; $ipt -w -X FS-PROTECT 2>/dev/null
  done
}
fw_on() { ipset_init; ipset_restore; fw_build iptables 4; fw_build ip6tables 6; }
jails() { fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ','; }

case "${1:-}" in
  firewall)      fw_on ;;
  firewall-off)  fw_off ;;
  gen-ignore)    gen_ignore ;;
  learn)         learn_once; echo "learned: v4=$(ipset list fs_trusted 2>/dev/null | sed -n 's/^Number of entries: //p') v6=$(ipset list fs_trusted6 2>/dev/null | sed -n 's/^Number of entries: //p')" ;;
  daemon)        daemon ;;
  apply)         gen_ignore; fail2ban-client reload >/dev/null 2>&1; fw_on; echo "applied" ;;
  trust)
    ip=${2:-}; ok_net "$ip" || { echo "Usage: fs-protect trust <IP|CIDR>"; exit 1; }
    grep -qxF "$ip" "$TRUSTED" 2>/dev/null || echo "$ip" >> "$TRUSTED"
    fail2ban-client unban "$ip" >/dev/null 2>&1
    gen_ignore; fail2ban-client reload >/dev/null 2>&1; fw_on
    echo "trusted (permanent): $ip" ;;
  untrust)
    ip=${2:-}; [ -n "$ip" ] || { echo "Usage: fs-protect untrust <IP|CIDR>"; exit 1; }
    sed -i "\|^${ip}\$|d" "$TRUSTED"
    case $ip in *:*) ipset del fs_trusted6 "$ip" 2>/dev/null;; *) ipset del fs_trusted "$ip" 2>/dev/null;; esac
    gen_ignore; fail2ban-client reload >/dev/null 2>&1; fw_on
    echo "removed from trusted: $ip" ;;
  unban)
    ip=${2:-}; [ -n "$ip" ] || { echo "Usage: fs-protect unban <IP>"; exit 1; }
    fail2ban-client unban "$ip" 2>/dev/null || for j in $(jails); do fail2ban-client set "$j" unbanip "$ip" >/dev/null 2>&1; done
    echo "unbanned: $ip (jodi banned thake)" ;;
  trusted)
    echo "--- auto-learned (v4)"; ipset list fs_trusted 2>/dev/null | sed -n '/^Members:/,$p' | tail -n +2
    echo "--- auto-learned (v6)"; ipset list fs_trusted6 2>/dev/null | sed -n '/^Members:/,$p' | tail -n +2
    echo "--- static"; all_static ;;
  status)
    echo "=== Fail2ban jails ==="
    for j in $(jails); do
      echo "--- $j"; fail2ban-client status "$j" | sed -n '/Currently banned/p;/Total banned/p;/Banned IP list/p'
    done
    echo; echo "=== Firewall FS-PROTECT (dropped packets) ==="
    iptables -w -L FS-PROTECT -n -v 2>/dev/null | grep -E 'DROP|REJECT' | awk '$1!=0 {print}' | head -20
    echo; echo "=== Auto-learned trusted ==="
    echo "v4: $(ipset list fs_trusted 2>/dev/null | sed -n 's/^Number of entries: //p')   v6: $(ipset list fs_trusted6 2>/dev/null | sed -n 's/^Number of entries: //p')   (list: fs-protect trusted)" ;;
  uninstall)
    systemctl disable --now fs-protect-learn fs-protect-firewall >/dev/null 2>&1
    fw_off
    ipset destroy fs_trusted 2>/dev/null; ipset destroy fs_trusted6 2>/dev/null
    rm -f /etc/fail2ban/jail.d/fs-protect-*.local /etc/fail2ban/filter.d/freeswitch-*.conf \
          /etc/systemd/system/fs-protect-firewall.service /etc/systemd/system/fs-protect-learn.service \
          /etc/sysctl.d/99-fs-protect.conf /usr/local/sbin/fs-is-trusted
    systemctl daemon-reload; fail2ban-client reload >/dev/null 2>&1
    echo "Removed. (/etc/fs-protect rakha hoyeche; chaile muchun)" ;;
  *)
    echo "fs-protect {status|trusted|learn|trust IP|untrust IP|unban IP|apply|firewall|firewall-off|uninstall}" ;;
esac
CLI_EOF
chmod 755 /usr/local/sbin/fs-protect

#--------------------------- fail2ban filters ------------------------
say "Fail2ban filter likha hocche..."
F=/etc/fail2ban/filter.d

cat > $F/freeswitch-auth.conf <<'F_EOF'
# SIP auth failure (REGISTER/INVITE/...) : brute force, password cracking, registration hijack
# "challenge" match kora hoy na - karon real client er prottek register e challenge ashe.
[Definition]
failregex = \[WARNING\] sofia_reg\.c:\d+ SIP auth failure \(\w+\) on sofia/\S+ from ip <HOST>
ignoreregex =
F_EOF

cat > $F/freeswitch-scan.conf <<'F_EOF'
# Unknown user / extension scanning, gateway abuse try
[Definition]
failregex = \[WARNING\] \S+\.c:\d+ Can't find user \[[^\]]*\] from <HOST>
ignoreregex =
F_EOF

cat > $F/freeswitch-acl.conf <<'F_EOF'
# ACL reject (SIP + ESL). "Falling back to Digest auth" normal, ota ignore.
[Definition]
failregex = \[WARNING\] \S+\.c:\d+ IP <HOST> Rejected by acl
ignoreregex = Falling back to Digest auth
F_EOF

cat > $F/freeswitch-tollguard.conf <<'F_EOF'
# Dialplan toll-guard log line (/etc/fs-protect/toll-guard-dialplan.xml.example)
[Definition]
failregex = TOLL-GUARD blocked \S+ from <HOST>
ignoreregex =
F_EOF

#--------------------------- fail2ban jails --------------------------
say "Fail2ban jail likha hocche..."
mkjail() { # name filter maxretry findtime bantime
cat <<JAIL_EOF
[$1]
enabled       = true
filter        = $2
logpath       = $FS_LOG
backend       = auto
maxretry      = $3
findtime      = $4
bantime       = $5
banaction     = iptables-allports
protocol      = all
ignorecommand = /usr/local/sbin/fs-is-trusted <ip>
ignorecache   = key="<ip>", max-count=5000, max-time=1m

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
enabled       = true
filter        = recidive
logpath       = /var/log/fail2ban.log
backend       = auto
maxretry      = 3
findtime      = 86400
bantime       = 604800
banaction     = iptables-allports
protocol      = all
ignorecommand = /usr/local/sbin/fs-is-trusted <ip>
REC_EOF
} > /etc/fail2ban/jail.d/fs-protect-jails.local

touch /var/log/fail2ban.log
[ -f /etc/fail2ban/fail2ban.local ] || printf '[Definition]\nlogtarget = /var/log/fail2ban.log\n' > /etc/fail2ban/fail2ban.local

#--------------------------- toll guard example ----------------------
cat > /etc/fs-protect/toll-guard-dialplan.xml.example <<'DP_EOF'
<!--
  TOLL FRAUD GUARD (optional) - dialplan er SOBAR AGE boshan, tarpor FreeSWITCH reload korun.
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

#--------------------------- sysctl + services -----------------------
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

cat > /etc/systemd/system/fs-protect-learn.service <<'UNIT_EOF'
[Unit]
Description=FreeSWITCH auto-learn trusted IPs (registered clients, trunks, active calls)
After=fs-protect-firewall.service network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/fs-protect daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT_EOF
systemctl daemon-reload

#--------------------------- FIRST LEARN (firewall er AGE) -----------
say "Ekhon shob real client/trunk IP shikha hocche..."
/usr/local/sbin/fs-protect gen-ignore
if [ -n "$FS_CLI" ]; then
  if timeout 6 "$FS_CLI" -H 127.0.0.1 -P "$ESL_PORT" -p "$FS_ESL_PASS" -x status 2>/dev/null | grep -qi 'UP'; then
    say "FreeSWITCH ESL connect OK"
  else
    warn "fs_cli diye FreeSWITCH e connect hoy nai (FreeSWITCH bondho? ESL password alada?)."
    warn "Registered client auto-learn kaj korbe na jotokkhon na fs_cli kaj kore: $FS_CLI -x status"
  fi
else
  warn "fs_cli pawa jai nai - registered client auto-learn hobe na!"
fi
/usr/local/sbin/fs-protect learn

#--------------------------- test + start ----------------------------
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
echo "   (acl er 2nd line ignored hoye 0 matched howa uchit)"
rm -f /tmp/fs-protect-test.log

systemctl enable fs-protect-firewall fs-protect-learn fail2ban >/dev/null 2>&1
systemctl restart fs-protect-firewall || warn "fs-protect-firewall start hoy nai: journalctl -u fs-protect-firewall"
systemctl restart fs-protect-learn    || warn "fs-protect-learn start hoy nai: journalctl -u fs-protect-learn"
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
    grep -q 'name="password" value="ClueCon"' "$ev" && warn "ESL password ekhono default ClueCon - change korun (change korle fs-protect conf e FS_ESL_PASS update korben: /etc/fs-protect/fs-protect.conf)"
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
echo "Auto-learned trusted: v4=$(ipset list fs_trusted 2>/dev/null | sed -n 's/^Number of entries: //p')  v6=$(ipset list fs_trusted6 2>/dev/null | sed -n 's/^Number of entries: //p')"
echo "Backup : $BK"
echo
echo "Daily commands:"
echo "   fs-protect status            # ke banned, koto packet drop, koto IP learned"
echo "   fs-protect trusted           # auto-learned IP er list"
echo "   fs-protect trust  1.2.3.4    # kono IP permanent whitelist"
echo "   fs-protect unban  1.2.3.4    # ban khule dewa"
echo
if [ "$PATCHED" = 1 ]; then
  warn "FreeSWITCH profile e log-auth-failures set hoyeche. Effect nite profile restart lagbe"
  warn "(kichhukkhon registration drop hoy, kom busy somoye korun):"
  warn "   fs_cli -x 'sofia profile internal restart'; fs_cli -x 'sofia profile external restart'"
fi
echo "Optional toll-guard dialplan: /etc/fs-protect/toll-guard-dialplan.xml.example"
