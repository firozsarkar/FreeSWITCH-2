#!/bin/bash
# ==============================================================================
# Script Name: sip-nuke.sh
# Description: conntrack bypass সহ SIP brute-force সম্পূর্ণ বন্ধ
#              - conntrack flush
#              - raw PREROUTING DROP (conntrack-এর আগেই)
#              - INPUT position 1 DROP (ufw chain-এর আগেই)
#              - SIP rate limit (defense-in-depth)
#              - fail2ban action আপডেট
# ==============================================================================

set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "❌ root দিয়ে চালান"; exit 1; }

ATTACKERS=(163.172.126.31 23.94.174.242 45.61.185.60 45.61.187.145)

# ─────────────────────────────────────────────
# ০. conntrack প্যাকেজ নিশ্চিত
# ─────────────────────────────────────────────
if ! command -v conntrack >/dev/null; then
    echo "📦 conntrack-tools ইনস্টল করা হচ্ছে..."
    apt-get install -y conntrack >/dev/null
fi

echo "🚨 SIP Nuke — আক্রমণকারীদের সম্পূর্ণ বন্ধ করা হচ্ছে"
echo ""

# ─────────────────────────────────────────────
# ১. ডায়াগনস্টিক — conntrack-এ কত entries?
# ─────────────────────────────────────────────
echo "=== 🔍 ডায়াগনস্টিক ==="
echo ""
echo "--- conntrack-এ আক্রমণকারী IP-র entries ---"
for ip in "${ATTACKERS[@]}"; do
    cnt=$(conntrack -L -s "$ip" 2>/dev/null | wc -l || echo 0)
    echo "  $ip → $cnt conntrack entries"
done

echo ""
echo "--- ufw-before-input-এর প্রথম ৫টি রুল ---"
iptables -L ufw-before-input -n --line-numbers 2>/dev/null | head -8

echo ""

# ─────────────────────────────────────────────
# ২. পুরনো ভুল ব্যান পরিষ্কার
# ─────────────────────────────────────────────
echo "=== 🧹 পুরনো রুল পরিষ্কার ==="
for ip in "${ATTACKERS[@]}"; do
    # UFW DENY সরানো
    ufw delete deny from "$ip" to any 2>/dev/null || true
done
echo "   ✅ UFW DENY রুল সরানো হয়েছে (আবার সঠিকভাবে বসাবো)"
echo ""

# ─────────────────────────────────────────────
# ৩. conntrack flush (সবচেয়ে গুরুত্বপূর্ণ!)
# ─────────────────────────────────────────────
echo "=== 💥 conntrack flush (এটি ছাড়া কিছুই কাজ করবে না) ==="
for ip in "${ATTACKERS[@]}"; do
    deleted=$(conntrack -D -s "$ip" 2>&1 | grep -c "flow" || echo 0)
    echo "  💥 $ip → $deleted flows মুছে ফেলা হয়েছে"
done
echo ""

# ─────────────────────────────────────────────
# ৪. raw PREROUTING DROP — conntrack-এর আগেই (সর্বোচ্চ অগ্রাধিকার)
# ─────────────────────────────────────────────
echo "=== 🔨 raw PREROUTING DROP (conntrack-এর আগেই) ==="
for ip in "${ATTACKERS[@]}"; do
    # ডুপ্লিকেট এড়াতে -C দিয়ে চেক
    if ! iptables -t raw -C PREROUTING -s "$ip" -j DROP 2>/dev/null; then
        iptables -t raw -I PREROUTING 1 -s "$ip" -j DROP
    fi
    echo "  ✓ $ip → raw/PREROUTING DROP"
done
echo ""

# ─────────────────────────────────────────────
# ৫. INPUT position 1-এ DROP (ufw chain-এর আগেই)
# ─────────────────────────────────────────────
echo "=== 🔨 INPUT position 1-এ DROP ==="
for ip in "${ATTACKERS[@]}"; do
    if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        iptables -I INPUT 1 -s "$ip" -j DROP
    fi
    echo "  ✓ $ip → INPUT[1] DROP"
done
echo ""

# ─────────────────────────────────────────────
# ৬. SIP rate limit — ভবিষ্যতের অজানা আক্রমণকারীদের জন্য
# ─────────────────────────────────────────────
echo "=== ⚡ SIP rate limit (hashlimit) ==="

# UDP 5060-এ প্রতি IP সর্বোচ্চ 50 pkt/sec (burst 100)
if ! iptables -C INPUT -p udp --dport 5060 \
    -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 \
    --hashlimit-mode srcip --hashlimit-name sip_flood -j DROP 2>/dev/null; then
    iptables -I INPUT 2 -p udp --dport 5060 \
        -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 \
        --hashlimit-mode srcip --hashlimit-name sip_flood -j DROP
    echo "  ✅ UDP 5060 rate limit: 50/sec per IP"
fi

# TCP 5060
if ! iptables -C INPUT -p tcp --dport 5060 \
    -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 \
    --hashlimit-mode srcip --hashlimit-name sip_flood_tcp -j DROP 2>/dev/null; then
    iptables -I INPUT 2 -p tcp --dport 5060 \
        -m hashlimit --hashlimit-above 50/sec --hashlimit-burst 100 \
        --hashlimit-mode srcip --hashlimit-name sip_flood_tcp -j DROP
    echo "  ✅ TCP 5060 rate limit: 50/sec per IP"
fi
echo ""

# ─────────────────────────────────────────────
# ৭. fail2ban অ্যাকশন আপডেট — ভবিষ্যতের ব্যানও conntrack-safe
# ─────────────────────────────────────────────
echo "=== ⚙️  fail2ban → conntrack-aware action ==="

cat > /etc/fail2ban/action.d/iptables-nuke.conf << 'EOF'
[Definition]

actionstart =

actionstop =

actioncheck =

# conntrack flush + raw PREROUTING + INPUT এ DROP
actionban = conntrack -D -s <ip> 2>/dev/null || true
            iptables -t raw -I PREROUTING 1 -s <ip> -j DROP
            iptables -I INPUT 1 -s <ip> -j DROP

actionunban = iptables -t raw -D PREROUTING -s <ip> -j DROP 2>/dev/null || true
              iptables -D INPUT -s <ip> -j DROP 2>/dev/null || true
EOF

cat > /etc/fail2ban/jail.d/freeswitch.local << 'EOF'
[freeswitch]
enabled   = true
filter    = freeswitch
logpath   = /var/log/freeswitch/freeswitch.log
maxretry  = 5
findtime  = 300
bantime   = 86400
backend   = polling
banaction = iptables-nuke
EOF

cat > /etc/fail2ban/jail.d/recidive.local << 'EOF'
[recidive]
enabled   = true
logpath   = /var/log/fail2ban.log
banaction = iptables-nuke
bantime   = 2592000
findtime  = 86400
maxretry  = 5
EOF

echo "  ✅ fail2ban action: iptables-nuke (conntrack + raw + INPUT)"
echo ""

# ─────────────────────────────────────────────
# ৮. fail2ban রিস্টার্ট
# ─────────────────────────────────────────────
echo "=== 🔄 fail2ban রিস্টার্ট ==="
if ! fail2ban-client -t 2>&1 | grep -q "OK"; then
    echo "❌ কনফিগ এরর, পুনরায় চেষ্টা..."
    fail2ban-client -t
    exit 1
fi
systemctl restart fail2ban
sleep 3

# ─────────────────────────────────────────────
# ৯. যাচাই
# ─────────────────────────────────────────────
echo ""
echo "=== ✅ যাচাই ==="
echo ""
echo "--- raw PREROUTING-এ DROP রুল ---"
iptables -t raw -L PREROUTING -n -v | grep -E "DROP|Chain" | head -10

echo ""
echo "--- INPUT[1-3] রুল ---"
iptables -L INPUT -n -v --line-numbers | head -6

echo ""
echo "--- conntrack-এ এখন কত entries? ---"
for ip in "${ATTACKERS[@]}"; do
    cnt=$(conntrack -L -s "$ip" 2>/dev/null | wc -l || echo 0)
    echo "  $ip → $cnt entries"
done

echo ""
echo "--- fail2ban ব্যান লিস্ট ---"
fail2ban-client status freeswitch 2>/dev/null | grep -E "Banned IP|Currently banned" || true

echo ""
echo "=========================================================="
echo "✅ সম্পূর্ণ! conntrack flush + raw PREROUTING DROP প্রয়োগ হয়েছে"
echo ""
echo "📊 ৩০ সেকেন্ড পর যাচাই করুন:"
echo "   tail -f /var/log/freeswitch/freeswitch.log | grep 'SIP auth'"
echo "   → নতুন SIP auth failure আর আসা উচিত নয়"
echo "=========================================================="
