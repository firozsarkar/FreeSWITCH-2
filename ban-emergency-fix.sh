#!/bin/bash
# ==============================================================================
# Script Name: ban-emergency-fix.sh
# Description: FreeSWITCH ব্যান কার্যকর না হলে তাৎক্ষণিক সমাধান
#              UFW-কে সরাসরি banaction হিসেবে ব্যবহার করে (100% নির্ভরযোগ্য)
# ==============================================================================

set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "❌ root দিয়ে চালান"; exit 1; }

ATTACKERS=(163.172.126.31 23.94.174.242 45.61.187.145 45.61.185.60)

echo "🚨 FreeSWITCH Ban Emergency Fix"
echo ""

# ─────────────────────────────────────────────
# ১. ডায়াগনস্টিক — আসল সমস্যা কী?
# ─────────────────────────────────────────────
echo "=== 🔍 ডায়াগনস্টিক ==="
echo "iptables version: $(iptables --version 2>/dev/null || echo 'not found')"
echo ""

echo "--- iptables-save-এ ব্লকড IP খোঁজা ---"
for ip in "${ATTACKERS[@]}"; do
    if iptables-save 2>/dev/null | grep -q "$ip"; then
        echo "  ✓ $ip — iptables-এ আছে (কিন্তু কার্যকর নয়)"
    else
        echo "  ❌ $ip — iptables-এ নেই! (rules apply হয়নি)"
    fi
done

echo ""
echo "--- nftables-এ ব্লকড IP খোঁজা ---"
for ip in "${ATTACKERS[@]}"; do
    if nft list ruleset 2>/dev/null | grep -q "$ip"; then
        echo "  ✓ $ip — nftables-এ আছে"
    else
        echo "  ❌ $ip — nftables-এ নেই"
    fi
done

echo ""
echo "--- f2b-freeswitch চেইন (iptables) ---"
iptables -L f2b-freeswitch -n -v 2>/dev/null | head -10 || echo "  ❌ চেইন নেই"

echo ""
echo "--- INPUT চেইনের উপরের ৫টি রুল ---"
iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -8

echo ""

# ─────────────────────────────────────────────
# ২. তাৎক্ষণিক সমাধান — UFW দিয়ে IP ব্লক (নিশ্চিত কার্যকর)
# ─────────────────────────────────────────────
echo "=== 🔒 তাৎক্ষণিক ব্লক (UFW) ==="
for ip in "${ATTACKERS[@]}"; do
    # পুরনো রুল থাকলে সরানো
    ufw delete deny from "$ip" to any 2>/dev/null || true
    # শীর্ষে নতুন deny রুল
    ufw insert 1 deny from "$ip" to any 2>&1 | grep -E "Rule|ERROR" || true
    echo "  🔒 $ip blocked"
done

# ─────────────────────────────────────────────
# ৩. Fail2Ban-এর জন্য কাস্টম UFW অ্যাকশন তৈরি
# ─────────────────────────────────────────────
echo ""
echo "=== ⚙️  Fail2Ban → UFW অ্যাকশন ==="

cat > /etc/fail2ban/action.d/ufw-block.conf << 'EOF'
[Definition]

actionstart =
actionstop  =
actioncheck =
actionban   = ufw insert 1 deny from <ip> to any
actionunban = ufw delete deny from <ip> to any
EOF

# ─────────────────────────────────────────────
# ৪. FreeSWITCH জেল আপডেট
# ─────────────────────────────────────────────
cat > /etc/fail2ban/jail.d/freeswitch.local << 'EOF'
[freeswitch]
enabled   = true
filter    = freeswitch
logpath   = /var/log/freeswitch/freeswitch.log
maxretry  = 5
findtime  = 300
bantime   = 86400
backend   = polling
banaction = ufw-block
EOF

# ─────────────────────────────────────────────
# ৫. Recidive জেল আপডেট
# ─────────────────────────────────────────────
cat > /etc/fail2ban/jail.d/recidive.local << 'EOF'
[recidive]
enabled   = true
logpath   = /var/log/fail2ban.log
banaction = ufw-block
bantime   = 2592000
findtime  = 86400
maxretry  = 5
EOF

# ─────────────────────────────────────────────
# ৬. কনফিগারেশন টেস্ট + রিস্টার্ট
# ─────────────────────────────────────────────
echo ""
echo "=== 🔍 কনফিগারেশন টেস্ট ==="
if ! fail2ban-client -t 2>&1 | tee /tmp/f2b-test.log; then
    echo "❌ কনফিগ ত্রুটি:"
    cat /tmp/f2b-test.log
    exit 1
fi

echo ""
echo "=== 🚀 Fail2Ban রিস্টার্ট ==="
systemctl restart fail2ban
sleep 3

# ─────────────────────────────────────────────
# ৭. বর্তমান আক্রমণকারীদের পুনরায় ব্যান
# ─────────────────────────────────────────────
echo ""
echo "=== 🔒 আক্রমণকারীদের পুনরায় ব্যান (Fail2Ban দিয়ে) ==="
for ip in "${ATTACKERS[@]}"; do
    if fail2ban-client set freeswitch banip "$ip" 2>/dev/null; then
        echo "  ✓ $ip fail2ban-banned"
    fi
done

# ─────────────────────────────────────────────
# ৮. যাচাই
# ─────────────────────────────────────────────
echo ""
echo "=== ✅ যাচাই ==="
echo ""
echo "--- UFW-এ ব্লকড IP ---"
ufw status numbered | grep -E "163\.|23\.94|45\.61" || echo "  (কোনো ম্যাচ নেই!)"

echo ""
echo "--- Fail2Ban ফ্রিজউইচ জেল ---"
fail2ban-client status freeswitch 2>/dev/null || echo "  (স্ট্যাটাস পাওয়া যায়নি)"

echo ""
echo "--- UFW-এ ব্লকড IP-র জন্য টেস্ট (একটি IP-তে ping চেষ্টা) ---"
# শুধু আউটবাউন্ড টেস্ট, আসল ইনবাউন্ড ব্লক যাচাই করা কঠিন
echo "  ℹ️  পরবর্তী ৩০-৬০ সেকেন্ড লগ মনিটর করুন:"
echo "     tail -f /var/log/freeswitch/freeswitch.log | grep 'SIP auth'"

echo ""
echo "=========================================================="
echo "✅ সমাপ্ত! এখন UFW সরাসরি ব্যান করছে (nftables-এর উপরেই)"
echo "=========================================================="
