#!/bin/bash
# ==============================================================================
# sip-shield.sh — FreeSWITCH SIP সুরক্ষা (সব স্ক্রিপ্টের একত্র সংস্করণ)
#   ১) সঠিক fail2ban ফিল্টার (escaped regex)
#   ২) ban হলে conntrack flush (পুরনো connection-ও কেটে যায়)
#   ৩) ipset দিয়ে দ্রুত ব্যান (হাজার IP হলেও ধীর হয় না)
#   ৪) প্রতি-IP rate limit, রিবুটের পরেও থাকে (systemd)
#   ৫) নিজের/বিশ্বস্ত IP কখনো ব্যান হবে না
# বারবার চালানো নিরাপদ।
# ==============================================================================
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "❌ root দিয়ে চালান"; exit 1; }

# ---- আপনার সার্ভার ও বিশ্বস্ত IP (স্পেস দিয়ে আলাদা করুন) ----
SERVER_IP="38.60.235.146"
TRUSTED_IPS="${TRUSTED_IPS:-}"          # যেমন: TRUSTED_IPS="1.2.3.4 5.6.7.8" ./sip-shield.sh
SIP_PORTS="5060 5061 5080"
FS_LOG="/var/log/freeswitch/freeswitch.log"

# আপনার SSH IP স্বয়ংক্রিয়ভাবে বিশ্বস্ত (নিজেকে লক আউট থেকে বাঁচাতে)
SSH_IP="${SSH_CLIENT%% *}"
IGNORE="127.0.0.1/8 ::1 $SERVER_IP $TRUSTED_IPS ${SSH_IP:-}"

echo "📦 প্যাকেজ ইনস্টল..."
DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban conntrack ipset iptables >/dev/null

# ---- ব্যান পদ্ধতি বাছাই ----
BANACTION="iptables-allports"
if modprobe ip_set 2>/dev/null && ipset list >/dev/null 2>&1; then
    BANACTION="iptables-ipset-proto6-allports"
fi
echo "🔥 ban action: $BANACTION"

systemctl stop fail2ban 2>/dev/null || true
rm -f /var/run/fail2ban/fail2ban.sock
mkdir -p /var/run/fail2ban

# ---- পুরনো ভুল কনফিগ পরিষ্কার ----
rm -f /etc/fail2ban/action.d/iptables-nuke.conf /etc/fail2ban/action.d/ufw-block.conf

# ---- লগ পারমিশন ----
[[ -f $FS_LOG ]] && chmod 644 "$FS_LOG"

# ---- ফিল্টার (প্রতি ব্যর্থ চেষ্টায় ঠিক ১টি ম্যাচ) ----
cat > /etc/fail2ban/filter.d/freeswitch.conf << 'EOF'
[Definition]
failregex = \[WARNING\] sofia_reg\.c:\d+ SIP auth (failure|challenge) \((REGISTER|INVITE)\) on sofia profile '[^']+' for \[[^\]]+\] from ip <HOST>
            \[WARNING\] sofia\.c:\d+ IP <HOST> Rejected by acl
ignoreregex =
EOF

# ---- conntrack flush অ্যাকশন ----
cat > /etc/fail2ban/action.d/conntrack-flush.conf << 'EOF'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = conntrack -D -s <ip> >/dev/null 2>&1 || true
actionunban =
EOF

# ---- jail.local ----
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = $IGNORE
banaction = $BANACTION
banaction_allports = $BANACTION
backend = auto
EOF

# ---- freeswitch jail ----
cat > /etc/fail2ban/jail.d/freeswitch.local << EOF
[freeswitch]
enabled  = true
filter   = freeswitch
logpath  = $FS_LOG
backend  = polling
maxretry = 5
findtime = 60
bantime  = -1
action   = $BANACTION[name=freeswitch]
           conntrack-flush
EOF

# ---- recidive (বারবার আসা আক্রমণকারী: ৩০ দিন) ----
cat > /etc/fail2ban/jail.d/recidive.local << EOF
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = $BANACTION
bantime  = -1
findtime = 86400
maxretry = 3
EOF

# ---- প্রতি-IP rate limit (রিবুটের পরেও) ----
cat > /usr/local/sbin/sip-ratelimit.sh << EOF
#!/bin/bash
for proto in udp tcp; do
  for port in $SIP_PORTS; do
    rule="-p \$proto --dport \$port -m hashlimit --hashlimit-above 30/sec --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name sip_\${proto}_\${port} -j DROP"
    iptables -C INPUT \$rule 2>/dev/null || iptables -I INPUT 1 \$rule
  done
done
EOF
chmod +x /usr/local/sbin/sip-ratelimit.sh

cat > /etc/systemd/system/sip-ratelimit.service << 'EOF'
[Unit]
Description=SIP per-IP rate limit
After=network-online.target ufw.service fail2ban.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/sip-ratelimit.sh

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sip-ratelimit.service

# ---- যাচাই ও চালু ----
echo "🔍 ফিল্টার টেস্ট (আসল লগের বিরুদ্ধে)..."
if [[ -f $FS_LOG ]]; then
    fail2ban-regex "$FS_LOG" /etc/fail2ban/filter.d/freeswitch.conf 2>&1 | grep -E "Lines:|Failregex" || true
fi
fail2ban-client -t
systemctl restart fail2ban
for i in {1..15}; do fail2ban-client status &>/dev/null && break; sleep 1; done

# ---- লগে থাকা বর্তমান আক্রমণকারী ব্যান (১০+ ব্যর্থ চেষ্টা) ----
if [[ -f $FS_LOG ]]; then
    echo "🔨 বর্তমান আক্রমণকারী ব্যান..."
    tail -n 20000 "$FS_LOG" | grep -oP 'SIP auth failure.*from ip \K[0-9.]+' \
      | sort | uniq -c | awk '$1>10{print $2}' | while read -r ip; do
        [[ " $IGNORE " == *" $ip "* ]] && continue
        fail2ban-client set freeswitch banip "$ip" &>/dev/null && echo "   🔒 $ip"
    done
fi

echo ""
fail2ban-client status freeswitch || true
echo ""
echo "✅ সম্পূর্ণ। ৩০ সেকেন্ড পর চালান: fail2ban-client status freeswitch"
echo "   'Total failed' এখন বাড়তে থাকা উচিত।"
echo "   লগ কমাতে fs_cli তে চালান:  /log 6"
