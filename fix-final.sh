#!/bin/bash
# ==============================================================================
# Script Name: fix-final.sh
# Description: Fail2Ban + FreeSWITCH SIP Protection Ultimate Fix
#              - polling backend নিশ্চিত করা (যাতে লাইভ লগ মিস না হয়)
#              - সঠিক banaction এবং filter সেটআপ
#              - লগ পারমিশন ফিক্স
#              - বর্তমান আক্রমণকারী আইপিগুলো তৎক্ষণাৎ raw/INPUT ড্রপ ও ব্যান করা
# ==============================================================================

set -euo pipefail

[[ $EUID -ne 0 ]] && { echo "❌ এই স্ক্রিপ্ট root/sudo দিয়ে চালাতে হবে।"; exit 1; }

echo "=========================================================="
echo "🔧 Fail2Ban + FreeSWITCH চূড়ান্ত ফিক্স শুরু হচ্ছে..."
echo "=========================================================="

# ১. Fail2Ban সার্ভিস সাময়িকভাবে থামানো ও সকেট পরিষ্কার করা
echo "🧹 Fail2Ban সার্ভিস রিসেট করা হচ্ছে..."
systemctl stop fail2ban 2>/dev/null || true
rm -f /var/run/fail2ban/fail2ban.sock 2>/dev/null || true

# ২. FreeSWITCH লগ ফাইলের পারমিশন ও ওনারশিপ ঠিক করা
echo "📁 FreeSWITCH লগ পারমিশন ঠিক করা হচ্ছে..."
if [[ -f /var/log/freeswitch/freeswitch.log ]]; then
    chmod 644 /var/log/freeswitch/freeswitch.log
    chown freeswitch:freeswitch /var/log/freeswitch/freeswitch.log 2>/dev/null || true
fi

# ৩. নিখুঁত ফিল্টার নিশ্চিত করা (/etc/fail2ban/filter.d/freeswitch.conf)
echo "🛡️ Fail2Ban ফিল্টার আপডেট করা হচ্ছে..."
cat > /etc/fail2ban/filter.d/freeswitch.conf << 'EOF'
[Definition]
failregex = [WARNING] sofia_reg\.c:\d+ SIP auth (failure|challenge) \((REGISTER|INVITE)\) on sofia profile '[^']+' for \[[^\]]+\] from ip <HOST>
            [WARNING] sofia_reg\.c:\d+ Can't find user \[[^\]]+\] from <HOST>
            [WARNING] sofia\.c:\d+ IP <HOST> Rejected by acl

ignoreregex =
EOF

# ৪. সঠিক jail.local তৈরি (Polling backend সহ)
echo "⚙️ jail.local কনফিগার করা হচ্ছে..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
banaction = iptables-multiport
banaction_allports = iptables-allports
backend = polling
EOF

# ৫. FreeSWITCH জেল কনফিগার করা (/etc/fail2ban/jail.d/freeswitch.local)
echo "🔧 FreeSWITCH জেল কনফিগার করা হচ্ছে..."
cat > /etc/fail2ban/jail.d/freeswitch.local << 'EOF'
[freeswitch]
enabled  = true
filter   = freeswitch
logpath  = /var/log/freeswitch/freeswitch.log
maxretry = 3
findtime = 600
bantime  = 86400
backend  = polling
action   = %(banaction_allports)s[name=freeswitch]
EOF

# ৬. Fail2Ban কনফিগারেশন টেস্ট ও স্টার্ট
echo "🚀 Fail2Ban চালু করা হচ্ছে..."
fail2ban-client -t
systemctl restart fail2ban
sleep 3

# ৭. বর্তমান লগ থেকে সব আক্রমণকারী আইপি শনাক্ত করে তৎক্ষণাৎ ড্রপ ও ব্যান করা
echo "🔨 বর্তমান আক্রমণকারী আইপিগুলো ফায়ারওয়ালে ড্রপ ও ব্যান করা হচ্ছে..."
if [[ -f /var/log/freeswitch/freeswitch.log ]]; then
    # গত ৫০০০ লাইন থেকে আইপি বের করে iptables raw & INPUT এ ড্রপ দেওয়া এবং fail2ban এ ব্যান করা
    for ip in $(tail -n 5000 /var/log/freeswitch/freeswitch.log | grep -oP 'from ip \K[0-9.]+' | sort -u); do
        [[ -z "$ip" ]] && continue
        # Raw PREROUTING এ ড্রপ
        iptables -t raw -C PREROUTING -s "$ip" -j DROP 2>/dev/null || iptables -t raw -I PREROUTING 1 -s "$ip" -j DROP
        # INPUT এ ড্রপ
        iptables -C INPUT -s "$ip" -j DROP 2>/dev/null || iptables -I INPUT 1 -s "$ip" -j DROP
        # Conntrack ফ্লাশ
        conntrack -D -s "$ip" 2>/dev/null || true
        # Fail2Ban এ রেজিস্টার করা
        fail2ban-client set freeswitch banip "$ip" &>/dev/null || true
        echo "   🔒 ব্লকড ও ব্যানড: $ip"
    done
else
    echo "   ⚠️ FreeSWITCH লগ ফাইল পাওয়া যায়নি।"
fi

echo ""
echo "=========================================================="
echo "✅ সফলভাবে সব ঠিক করা হয়েছে!"
echo "=========================================================="
echo "📊 বর্তমান জেল স্ট্যাটাস দেখতে নিচের কমান্ড দিন:"
echo "   fail2ban-client status freeswitch"
echo "=========================================================="
