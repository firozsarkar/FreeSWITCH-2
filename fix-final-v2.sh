#!/bin/bash
# ==============================================================================
# Script Name: fix-final-v2.sh
# Description: Fail2Ban + FreeSWITCH SIP Protection Ultimate Fix (Fixed Version)
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
            [NOTICE] sofia\.c:\d+ Hangup sofia/internal/.* \[WRONG_CALL_STATE\] from ip <HOST>

ignoreregex =
EOF

# ৪. সঠিক jail.local তৈরি (Auto-detect banaction)
echo "⚙️ jail.local কনফিগার করা হচ্ছে..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
banaction = iptables-allports
banaction_allports = iptables-allports
backend = auto
EOF

# ৫. FreeSWITCH জেল কনফিগার করা (/etc/fail2ban/jail.d/freeswitch.local)
echo "🔧 FreeSWITCH জেল কনফিগার করা হচ্ছে..."
cat > /etc/fail2ban/jail.d/freeswitch.local << 'EOF'
[freeswitch]
enabled  = true
filter   = freeswitch
logpath  = /var/log/freeswitch/freeswitch.log
maxretry = 2
findtime = 600
bantime  = 86400
backend  = auto
action   = iptables-allports[name=freeswitch]
EOF

# ৬. Fail2Ban কনফিগারেশন টেস্ট ও স্টার্ট
echo "🚀 Fail2Ban চালু করা হচ্ছে..."
fail2ban-client -t
systemctl restart fail2ban
sleep 3

# ৭. বর্তমান লগ থেকে সব আক্রমণকারী আইপি নিখুঁতভাবে শনাক্ত করে ড্রপ ও ব্যান করা
echo "🔨 বর্তমান আক্রমণকারী আইপিগুলো ফায়ারওয়ালে ড্রপ ও ব্যান করা হচ্ছে..."
if [[ -f /var/log/freeswitch/freeswitch.log ]]; then
    # আরও নিখুঁতভাবে সব সম্ভাব্য আইপি এক্সট্রাক্ট করা (grep -oP দিয়ে)
    for ip in $(tail -n 5000 /var/log/freeswitch/freeswitch.log | grep -oP '(from ip \K[0-9.]+|from \K[0-9.]+(?=:)|IP \K[0-9.]+)' | grep -vE '^(127\.|38\.60\.235\.)' | sort -u); do
        [[ -z "$ip" ]] && continue
        
        # INPUT এ ড্রপ দেওয়া
        iptables -C INPUT -s "$ip" -j DROP 2>/dev/null || iptables -I INPUT 1 -s "$ip" -j DROP
        
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
