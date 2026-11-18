#!/bin/bash
# ==============================================================================
# Script Name: fix-final-v2.sh (Ultimate SIP Protection v3)
# Description: Fail2Ban + FreeSWITCH SIP Protection & Dynamic IP Blocker
# ==============================================================================

set -euo pipefail

[[ $EUID -ne 0 ]] && { echo "❌ এই স্ক্রিপ্ট root/sudo দিয়ে চালাতে হবে।"; exit 1; }

echo "=========================================================="
echo "🔧 FreeSWITCH আল্টিমেট ফায়ারওয়াল ও Fail2Ban প্রটেকশন শুরু হচ্ছে..."
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

# ৩. নিখুঁত ফিল্টার তৈরি করা (/etc/fail2ban/filter.d/freeswitch.conf)
# এটি ইনভাইট স্ক্যান, উইং কল, ভুয়া ইউজার এবং ভুল স্টেট লগগুলো ধরবে
echo "🛡️ Fail2Ban ফিল্টার কনফিগার করা হচ্ছে..."
cat > /etc/fail2ban/filter.d/freeswitch.conf << 'EOF'
[Definition]
failregex = [WARNING] sofia_reg\.c:\d+ SIP auth (failure|challenge) \((REGISTER|INVITE)\) on sofia profile '[^']+' for \[[^\]]+\] from ip <HOST>
            [WARNING] sofia_reg\.c:\d+ Can't find user \[[^\]]+\] from <HOST>
            [WARNING] sofia\.c:\d+ IP <HOST> Rejected by acl
            [NOTICE] sofia\.c:\d+ Hangup sofia/internal/.* \[WRONG_CALL_STATE\] from ip <HOST>
            [INFO] sofia\.c:\d+ sofia/internal/.* receiving invite from <HOST>:\d+

ignoreregex =
EOF

# ৪. jail.local কনফিগারেশন
echo "⚙️ jail.local কনফিগার করা হচ্ছে..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 38.60.235.146
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

# ৭. বর্তমান লগ ফাইল থেকে সব আক্রমণকারী ও স্ক্যানার আইপি বের করে তৎক্ষণাৎ ড্রপ করা
echo "🔨 বর্তমান লগ স্ক্যান করে সব স্ক্যানার ও আক্রমণকারী আইপি ফায়ারওয়ালে ব্লক করা হচ্ছে..."
if [[ -f /var/log/freeswitch/freeswitch.log ]]; then
    # লগ থেকে সমস্ত আইপি (from ip X, from X, receiving invite from X) এক্সট্রাক্ট করা
    # নিজস্ব সার্ভার আইপি (যেমন 38.60.235.146) এবং লোকালআইপি ফিল্টার আউট করা হবে
    for ip in $(tail -n 10000 /var/log/freeswitch/freeswitch.log | grep -oP '(from ip \K[0-9.]+|from \K[0-9.]+(?=:)|IP \K[0-9.]+|receiving invite from \K[0-9.]+)' | grep -vE '^(127\.|38\.60\.235\.)' | sort -u); do
        [[ -z "$ip" ]] && continue
        
        # ফায়ারওয়ালের INPUT চেইনে ড্রপ রুল ইনসার্ট করা
        iptables -C INPUT -s "$ip" -j DROP 2>/dev/null || iptables -I INPUT 1 -s "$ip" -j DROP
        
        # Fail2Ban এ পার্মানেন্টলি ব্যান লিস্টে তোলা
        fail2ban-client set freeswitch banip "$ip" &>/dev/null || true
        echo "   🔒 ফায়ারওয়ালে ড্রপ ও ব্যান করা হলো: $ip"
    done
else
    echo "   ⚠️ FreeSWITCH লগ ফাইল পাওয়া যায়নি।"
fi

echo ""
echo "=========================================================="
echo "✅ সফলভাবে স্ক্রিপ্ট রান সম্পন্ন হয়েছে!"
echo "=========================================================="
echo "📊 वर्तमान Fail2Ban স্ট্যাটাস দেখতে নিচের কমান্ড দিন:"
echo "   fail2ban-client status freeswitch"
echo "=========================================================="
