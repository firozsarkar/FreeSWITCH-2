#!/bin/bash
# ==============================================================================
# Script Name: fail2ban-fix.sh
# Description: Fail2Ban + FreeSWITCH (SIP Brute-Force Protection) অটো-ফিক্স
#              Debian 12 (Bookworm)-এর জন্য সম্পূর্ণ স্বয়ংক্রিয় সমাধান।
#              - systemd backend (auth.log সমস্যা)
#              - ডুপ্লিকেট [sshd] ব্লক অপসারণ (awk দিয়ে)
#              - iptables-allports ব্যাকএন্ড (Debian 12-এ nft-এর উপরেই কাজ করে)
#              - log-auth-failures সক্রিয় করা
#              - সাম্প্রতিক আক্রমণকারীদের স্বয়ংক্রিয় ব্যান
# Idempotent: যতবার খুশি চালানো নিরাপদ।
# ==============================================================================

set -euo pipefail

# ==========================================
# ০. Root চেক
# ==========================================
if [[ $EUID -ne 0 ]]; then
    echo "❌ এই স্ক্রিপ্ট root/sudo দিয়ে চালাতে হবে।"
    exit 1
fi

echo ""
echo "🚀 Fail2Ban + FreeSWITCH অটো-ফিক্স শুরু হচ্ছে..."
echo ""

# ==========================================
# ১. প্রয়োজনীয় প্যাকেজ নিশ্চিত করা
# ==========================================
echo "📦 প্রয়োজনীয় প্যাকেজ যাচাই করা হচ্ছে..."

PKGS="fail2ban rsyslog iptables"
for pkg in $PKGS; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        echo "   -> $pkg ইনস্টল করা হচ্ছে..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
    else
        echo "   ✓ $pkg আগে থেকেই আছে"
    fi
done

# rsyslog চালু করা (auth.log নিশ্চিত করতে)
systemctl enable --now rsyslog &>/dev/null || true
echo ""

# ==========================================
# ২. ব্যাকএন্ড নির্ধারণ (iptables-allports প্রমাণিত, Debian 12-এ nft-এর উপরেই কাজ করে)
# ==========================================
BANACTION="iptables-allports"
echo "🔥 ব্যাকএন্ড: $BANACTION"
echo ""

# ==========================================
# ৩. Fail2Ban পরিষ্কারভাবে বন্ধ করা + স্টেল সকেট মুছে ফেলা
# ==========================================
echo "🧹 Fail2Ban পরিষ্কার করা হচ্ছে..."
systemctl stop fail2ban 2>/dev/null || true
rm -f /var/run/fail2ban/fail2ban.sock 2>/dev/null || true
mkdir -p /var/run/fail2ban
echo ""

# ==========================================
# ৪. FreeSWITCH-এ log-auth-failures সক্রিয় করা
# ==========================================
echo "🔧 FreeSWITCH-এ log-auth-failures সক্রিয় করা হচ্ছে..."

for xml_file in /etc/freeswitch/sip_profiles/internal.xml \
                /etc/freeswitch/sip_profiles/external.xml; do
    if [[ -f "$xml_file" ]]; then
        # শুধুমাত্র ব্যাকআপ তৈরি করুন যদি না থাকে (বারবার চালানোর জন্য নিরাপদ)
        if [[ ! -f "${xml_file}.bak" ]]; then
            cp "$xml_file" "${xml_file}.bak"
        fi

        if grep -q 'name="log-auth-failures"' "$xml_file"; then
            sed -i 's/name="log-auth-failures" value="[^"]*"/name="log-auth-failures" value="true"/' "$xml_file"
        else
            # settings সেকশনের শেষে যোগ করা
            sed -i '0,/<\/settings>/s//    <param name="log-auth-failures" value="true"\/>\n<\/settings>/' "$xml_file"
        fi
        echo "   ✅ $xml_file"
    else
        echo "   ⚠️  $xml_file পাওয়া যায়নি"
    fi
done
echo ""

# ==========================================
# ৫. defaults-debian.conf থেকে [sshd] ব্লক সম্পূর্ণ অপসারণ (awk)
#    (sed ডুপ্লিকেট enabled তৈরি করত, তাই awk ব্যবহার)
# ==========================================
echo "🧹 defaults-debian.conf থেকে ডুপ্লিকেট [sshd] ব্লক অপসারণ..."

DEFAULTS_FILE="/etc/fail2ban/jail.d/defaults-debian.conf"
if [[ -f "$DEFAULTS_FILE" ]]; then
    # ব্যাকআপ
    if [[ ! -f "${DEFAULTS_FILE}.bak" ]]; then
        cp "$DEFAULTS_FILE" "${DEFAULTS_FILE}.bak"
    fi

    # [sshd] সেকশন সম্পূর্ণ বাদ দিয়ে নতুন ফাইল তৈরি
    awk '
        /^\[sshd\]/ { skip=1; next }
        /^\[/       { skip=0 }
        !skip
    ' "$DEFAULTS_FILE" > "${DEFAULTS_FILE}.new"

    mv "${DEFAULTS_FILE}.new" "$DEFAULTS_FILE"
    echo "   ✅ [sshd] ব্লক অপসারিত"
else
    echo "   ⚠️  $DEFAULTS_FILE পাওয়া যায়নি (সমস্যা নেই)"
fi
echo ""

# ==========================================
# ৬. sshd.local তৈরি (systemd backend সহ)
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
echo "   ✅ /etc/fail2ban/jail.d/sshd.local"
echo ""

# ==========================================
# ৭. FreeSWITCH ফিল্টার তৈরি (SIP Brute-Force Detection)
# ==========================================
echo "🛡️  FreeSWITCH ফিল্টার তৈরি করা হচ্ছে..."

cat > /etc/fail2ban/filter.d/freeswitch.conf << 'EOF'
[Definition]
# FreeSWITCH 1.11.x লগ ফরম্যাটের জন্য (log-auth-failures=true হলে):
#   2026-11-13 19:00:06.814142 93.20% [WARNING] sofia_reg.c:1787 SIP auth failure (REGISTER) on sofia profile 'internal' for [773@38.60.235.146] from ip 163.172.126.31
failregex = \[WARNING\] sofia_reg\.c:\d+ SIP auth (failure|challenge) \((REGISTER|INVITE)\) on sofia profile '[^']+' for \[[^\]]+\] from ip <HOST>
            \[WARNING\] sofia_reg\.c:\d+ Can't find user \[[^\]]+\] from <HOST>
            \[WARNING\] sofia\.c:\d+ IP <HOST> Rejected by acl

ignoreregex =
EOF
echo "   ✅ /etc/fail2ban/filter.d/freeswitch.conf"
echo ""

# ==========================================
# ৮. jail.local-এ ব্যাকএন্ড অ্যাকশন সেট করা
# ==========================================
echo "🔥 ব্যাকএন্ড অ্যাকশন সেট করা হচ্ছে..."

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# লোকালহোস্ট বাদ — আপনার বিশ্বস্ত IP এখানে যোগ করুন
ignoreip = 127.0.0.1/8 ::1

# Debian 12-এ প্রমাণিত: iptables-allports (iptables-nft-এর মাধ্যমে nftables-এ কাজ করে)
banaction = iptables-multiport
banaction_allports = iptables-allports

backend = auto
EOF
echo "   ✅ /etc/fail2ban/jail.local"
echo ""

# ==========================================
# ৯. FreeSWITCH জেল তৈরি
# ==========================================
echo "🔧 FreeSWITCH জেল তৈরি করা হচ্ছে..."

# লগ ফাইলের পারমিশন নিশ্চিত করা
if [[ -f /var/log/freeswitch/freeswitch.log ]]; then
    chmod 644 /var/log/freeswitch/freeswitch.log
    chown freeswitch:freeswitch /var/log/freeswitch/freeswitch.log 2>/dev/null || true
    echo "   ✅ লগ পারমিশন ঠিক আছে"
else
    echo "   ⚠️  /var/log/freeswitch/freeswitch.log এখনো তৈরি হয়নি (FreeSWITCH চালু হলে তৈরি হবে)"
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
action   = %(banaction_allports)s[name=freeswitch]
EOF
echo "   ✅ /etc/fail2ban/jail.d/freeswitch.local"
echo ""

# ==========================================
# ১০. Recidive জেল (পুনরায় আক্রমণকারীদের জন্য)
# ==========================================
echo "🔧 Recidive জেল তৈরি করা হচ্ছে..."

cat > /etc/fail2ban/jail.d/recidive.local << 'EOF'
[recidive]
enabled   = true
logpath   = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime   = 2592000
findtime  = 86400
maxretry  = 5
EOF
echo "   ✅ /etc/fail2ban/jail.d/recidive.local"
echo ""

# ==========================================
# ১১. কনফিগারেশন ভ্যালিডেট করা
# ==========================================
echo "🔍 কনফিগারেশন ভ্যালিডেট করা হচ্ছে..."
if ! fail2ban-client -t 2>&1; then
    echo ""
    echo "❌ কনফিগারেশন টেস্ট ব্যর্থ! উপরের এরর দেখুন।"
    exit 1
fi
echo ""

# ==========================================
# ১২. FreeSWITCH রিস্টার্ট (log-auth-failures কার্যকর করতে)
# ==========================================
if systemctl is-active --quiet freeswitch; then
    echo "🔄 FreeSWITCH রিস্টার্ট করা হচ্ছে..."
    systemctl restart freeswitch
    sleep 3
fi

# ==========================================
# ১৩. Fail2Ban চালু করা + সকেটের জন্য অপেক্ষা
# ==========================================
echo "🚀 Fail2Ban চালু করা হচ্ছে..."
systemctl start fail2ban

# সকেট তৈরি হওয়ার জন্য অপেক্ষা করুন (সর্বোচ্চ 15 সেকেন্ড)
for i in {1..15}; do
    if fail2ban-client status &>/dev/null; then
        break
    fi
    sleep 1
done

# ==========================================
# ১৪. সাম্প্রতিক আক্রমণকারীদের স্বয়ংক্রিয় ব্যান
#     (শুধু ১০টির বেশি ফেইল করা IP-গুলোকে ব্যান করা হয়,
#     যাতে বৈধ ব্যবহারকারী ভুল করে ব্যান না হয়)
# ==========================================
echo ""
echo "🔒 সাম্প্রতিক আক্রমণকারীদের শনাক্ত ও ব্যান করা হচ্ছে..."

FS_LOG="/var/log/freeswitch/freeswitch.log"
if [[ -f "$FS_LOG" ]]; then
    # শেষ ১০,০০০ লাইন থেকে ফেইল হওয়া IP গোনা
    ATTACKER_LIST=$(tail -n 10000 "$FS_LOG" 2>/dev/null | \
        grep -oP 'SIP auth (failure|challenge).*from ip \K[0-9.]+' 2>/dev/null | \
        sort | uniq -c | sort -rn | \
        awk '$1 > 10 {print $2, $1}' || true)

    if [[ -n "$ATTACKER_LIST" ]]; then
        while read -r ip count; do
            [[ -z "$ip" ]] && continue
            if fail2ban-client set freeswitch banip "$ip" &>/dev/null; then
                echo "   🔒 $ip ব্যানড (ফেইল: $count)"
            fi
        done <<< "$ATTACKER_LIST"
    else
        echo "   ✓ উল্লেখযোগ্য কোনো আক্রমণকারী পাওয়া যায়নি"
    fi
else
    echo "   ⚠️  FreeSWITCH লগ এখনো নেই"
fi
echo ""

# ==========================================
# ১৫. চূড়ান্ত সামারি
# ==========================================
echo "=========================================================="
echo "✅ Fail2Ban ফিক্স সম্পূর্ণ!"
echo "=========================================================="
echo ""

# Fail2Ban সামগ্রিক স্ট্যাটাস
if fail2ban-client status &>/dev/null; then
    echo "📊 জেল স্ট্যাটাস:"
    fail2ban-client status
    echo ""
    echo "📊 FreeSWITCH জেল:"
    fail2ban-client status freeswitch
    echo ""
    BANNED=$(fail2ban-client get freeswitch banip 2>/dev/null || echo "")
    if [[ -n "$BANNED" ]]; then
        echo "🔒 ব্লকড IP তালিকা:"
        echo "$BANNED" | sed 's/^/   /'
    else
        echo "🔒 ব্লকড IP: (কোনোটি নেই)"
    fi
else
    echo "❌ Fail2Ban স্ট্যাটাস পাওয়া যায়নি!"
    systemctl status fail2ban --no-pager
    exit 1
fi

echo ""
echo "📝 দরকারি কমান্ড:"
echo "   fail2ban-client status freeswitch     # জেল স্ট্যাটাস"
echo "   fail2ban-client get freeswitch banip  # ব্লকড IP তালিকা"
echo "   fail2ban-client set freeswitch unbanip <IP>  # আনব্যান"
echo "   tail -f /var/log/fail2ban.log         # লাইভ লগ"
echo ""
echo "⚙️  আপনার বিশ্বস্ত IP যোগ করুন:"
echo "   /etc/fail2ban/jail.local → ignoreip লাইনে"
echo ""
echo "=========================================================="
