#!/bin/bash
# ==============================================================================
# Script Name: fail2ban-fix.sh
# Description: স্বয়ংক্রিয়ভাবে Debian 12-এ Fail2Ban-এর সব সাধারণ সমস্যা ঠিক করে
#              (systemd backend, ডুপ্লিকেট sshd jail, nftables/iptables,
#               FreeSWITCH log-auth-failures, পারমিশন, সকেট ক্লিনআপ)
# Supported OS: Debian 12 (Bookworm)
# ==============================================================================

set -euo pipefail

# ==========================================
# ০. Root চেক
# ==========================================
if [[ $EUID -ne 0 ]]; then
   echo "❌ এই স্ক্রিপ্ট root/sudo দিয়ে চালাতে হবে।"
   exit 1
fi

# ==========================================
# ১. প্রয়োজনীয় প্যাকেজ নিশ্চিত করা (rsyslog + nftables)
# ==========================================
echo "📦 প্রয়োজনীয় প্যাকেজ যাচাই করা হচ্ছে..."
for pkg in fail2ban rsyslog nftables; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        echo "   -> $pkg ইনস্টল করা হচ্ছে..."
        apt-get install -y "$pkg"
    fi
done

# rsyslog চালু করা (auth.log নিশ্চিত করতে)
systemctl enable --now rsyslog &>/dev/null || true

# ==========================================
# ২. Fail2Ban পরিষ্কারভাবে বন্ধ করা ও স্টেল সকেট মুছে ফেলা
# ==========================================
echo "🧹 Fail2Ban পরিষ্কার করা হচ্ছে..."
systemctl stop fail2ban &>/dev/null || true
rm -f /var/run/fail2ban/fail2ban.sock 2>/dev/null || true
mkdir -p /var/run/fail2ban

# ==========================================
# ৩. FreeSWITCH-এ log-auth-failures সক্রিয় করা
# ==========================================
echo "🔧 FreeSWITCH-এ log-auth-failures সক্রিয় করা হচ্ছে..."

for xml_file in /etc/freeswitch/sip_profiles/internal.xml /etc/freeswitch/sip_profiles/external.xml; do
    if [[ -f "$xml_file" ]]; then
        # ব্যাকআপ তৈরি
        cp "$xml_file" "${xml_file}.bak.$(date +%Y%m%d%H%M%S)"
        # প্যারামিটার যোগ বা আপডেট
        if grep -q 'name="log-auth-failures"' "$xml_file"; then
            sed -i 's/name="log-auth-failures" value="[^"]*"/name="log-auth-failures" value="true"/' "$xml_file"
        else
            sed -i '/<\/settings>/i \    <param name="log-auth-failures" value="true"/>' "$xml_file"
        fi
        echo "   ✅ $xml_file আপডেট হয়েছে।"
    else
        echo "   ⚠️ $xml_file পাওয়া যায়নি, বাদ দেওয়া হচ্ছে।"
    fi
done

# ==========================================
# ৪. ডুপ্লিকেট sshd জেল নিষ্ক্রিয় করা
#    (Debian-এর defaults-debian.conf-এ sshd আগে থেকেই থাকে)
# ==========================================
echo "🧹 ডুপ্লিকেট sshd জেল নিষ্ক্রিয় করা হচ্ছে..."

# defaults-debian.conf-এ sshd ব্লকটি নিষ্ক্রিয় করা
if [[ -f /etc/fail2ban/jail.d/defaults-debian.conf ]]; then
    sed -i '/^\[sshd\]/,/^\[/ s/^enabled *=.*/enabled = false/' /etc/fail2ban/jail.d/defaults-debian.conf
    echo "   ✅ defaults-debian.conf-এ sshd নিষ্ক্রিয় করা হয়েছে।"
fi

# পুরনো কনফ্লিক্টিং ফাইল থাকলে সরানো
rm -f /etc/fail2ban/jail.d/10-sshd-file.conf 2>/dev/null || true
rm -f /etc/fail2ban/jail.d/10-sshd-systemd.conf 2>/dev/null || true

# ==========================================
# ৫. sshd.local তৈরি/আপডেট (systemd backend সহ)
# ==========================================
echo "🔧 sshd জেল কনফিগার করা হচ্ছে..."

cat > /etc/fail2ban/jail.d/sshd.local << 'EOF'
[sshd]
enabled  = true
backend  = systemd
maxretry = 5
findtime = 600
bantime  = 3600
EOF
echo "   ✅ sshd.local (systemd backend) তৈরি হয়েছে।"

# ==========================================
# ৬. Fail2Ban ফিল্টার তৈরি (FreeSWITCH SIP Brute-Force Detection)
# ==========================================
echo "🛡️ FreeSWITCH ফিল্টার তৈরি করা হচ্ছে..."

cat > /etc/fail2ban/filter.d/freeswitch.conf << 'EOF'
[Definition]
failregex = ^\.\d+ \[WARNING\] sofia_reg\.c:\d+ SIP auth (failure|challenge) \((REGISTER|INVITE)\) on sofia profile \'[^']+\' for \[.*\] from ip <HOST>$
            ^.*Can't find user \[.*\] from <HOST>.*$
            ^.*invalid password.*from <HOST>.*$
            ^.*authentication failed for <HOST>.*$
            ^.*AUTH FAILURE.*<HOST>.*$
            ^.*wrong password.*from <HOST>.*$
ignoreregex =
EOF
echo "   ✅ ফিল্টার তৈরি হয়েছে।"

# ==========================================
# ৭. ফায়ারওয়াল অ্যাকশন ঠিক করা (nftables, কারণ Debian 12-এ iptables নেই)
# ==========================================
echo "🔥 ফায়ারওয়াল অ্যাকশন nftables-এ সেট করা হচ্ছে..."

# [DEFAULT] সেকশনে nftables সেট করা
# (এটি FreeSWITCH জেলের জন্যও প্রযোজ্য হবে)
if ! grep -q '^banaction = nftables' /etc/fail2ban/jail.local 2>/dev/null; then
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
ignoreip = 127.0.0.1/8 ::1
EOF
else
    # যদি jail.local আগে থেকেই থাকে, তবে শুধু banaction লাইনগুলো আপডেট করা
    sed -i 's/^banaction *=.*/banaction = nftables-multiport/' /etc/fail2ban/jail.local
    sed -i 's/^banaction_allports *=.*/banaction_allports = nftables-allports/' /etc/fail2ban/jail.local
fi
echo "   ✅ nftables অ্যাকশন সেট হয়েছে।"

# ==========================================
# ৮. FreeSWITCH জেল তৈরি করা
# ==========================================
echo "🔧 FreeSWITCH জেল তৈরি করা হচ্ছে..."

# লগ ফাইলের পারমিশন নিশ্চিত করা
if [[ -f /var/log/freeswitch/freeswitch.log ]]; then
    chmod 644 /var/log/freeswitch/freeswitch.log
    echo "   ✅ FreeSWITCH লগ পারমিশন ঠিক করা হয়েছে।"
else
    echo "   ⚠️ /var/log/freeswitch/freeswitch.log পাওয়া যায়নি। FreeSWITCH চলছে কিনা যাচাই করুন।"
fi

cat > /etc/fail2ban/jail.d/freeswitch.local << 'EOF'
[freeswitch]
enabled  = true
filter   = freeswitch
logpath  = /var/log/freeswitch/freeswitch.log
maxretry = 20
findtime = 300
bantime  = 86400
backend  = polling
action   = nftables-allports[name=freeswitch]
EOF
echo "   ✅ FreeSWITCH জেল তৈরি হয়েছে।"

# ==========================================
# ৯. Recidive জেল সক্রিয় করা (পুনরায় আক্রমণকারীদের জন্য)
# ==========================================
echo "🔧 Recidive জেল সক্রিয় করা হচ্ছে..."

cat > /etc/fail2ban/jail.d/recidive.local << 'EOF'
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = nftables-allports
bantime  = 2592000
findtime = 86400
maxretry = 5
EOF
echo "   ✅ Recidive জেল তৈরি হয়েছে।"

# ==========================================
# ১০. কনফিগারেশন ভ্যালিডেট করা
# ==========================================
echo "🔍 কনফিগারেশন ভ্যালিডেট করা হচ্ছে..."
if fail2ban-client -t; then
    echo "   ✅ কনফিগারেশন টেস্ট সফল হয়েছে।"
else
    echo "   ❌ কনফিগারেশন টেস্ট ব্যর্থ হয়েছে! উপরের এরর মেসেজ দেখুন।"
    exit 1
fi

# ==========================================
# ১১. FreeSWITCH রিস্টার্ট (log-auth-failures কার্যকর করতে)
# ==========================================
if systemctl is-active --quiet freeswitch; then
    echo "🔄 FreeSWITCH রিস্টার্ট করা হচ্ছে..."
    systemctl restart freeswitch
    sleep 2
fi

# ==========================================
# ১২. Fail2Ban চালু করা ও স্ট্যাটাস যাচাই
# ==========================================
echo "🚀 Fail2Ban চালু করা হচ্ছে..."
systemctl start fail2ban

# সকেট তৈরি হওয়ার জন্য অপেক্ষা
for i in {1..10}; do
    if fail2ban-client status &>/dev/null; then
        break
    fi
    sleep 1
done

echo ""
echo "=========================================================="
echo "✅ Fail2Ban ফিক্স সম্পূর্ণ হয়েছে!"
echo "=========================================================="
echo ""
echo "📊 জেল স্ট্যাটাস:"
fail2ban-client status
echo ""
echo "📊 FreeSWITCH জেল স্ট্যাটাস:"
fail2ban-client status freeswitch
echo ""
echo "🔒 ব্লকড IP (যদি থাকে):"
fail2ban-client get freeswitch banip 2>/dev/null || echo "   (কোনো IP এখনও ব্লক হয়নি)"
echo ""
echo "📝 লগ মনিটর: tail -f /var/log/fail2ban.log"
echo "=========================================================="
