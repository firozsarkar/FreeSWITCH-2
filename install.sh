#!/bin/bash
# ==============================================================================
# Script Name: install_freeswitch_fail2ban_debian12.sh
# Description: FreeSWITCH + Fail2Ban (SIP Brute-Force Protection) + UFW
# Supported OS: Debian 12 (Bookworm)
# ==============================================================================

set -euo pipefail  # কোনো কমান্ড ফেইল করলে বা আনডিফাইনড ভেরিয়েবল ব্যবহারে স্ক্রিপ্ট থেমে যাবে

# ==========================================
# ০. Root চেক
# ==========================================
if [[ $EUID -ne 0 ]]; then
   echo "❌ এই স্ক্রিপ্ট root/sudo দিয়ে চালাতে হবে।"
   exit 1
fi

# ==========================================
# ১. সিস্টেম আপডেট এবং প্রয়োজনীয় ডিপেন্ডেন্সি
# ==========================================
echo "🔄 সিস্টেম আপডেট করা হচ্ছে..."
apt update && apt upgrade -y

echo "📦 প্রয়োজনীয় প্যাকেজ ইনস্টল করা হচ্ছে..."
apt install -y curl wget git lsb-release gnupg2 ca-certificates apt-transport-https \
               ufw fail2ban nftables iptables net-tools apache2 php8.2 libapache2-mod-php8.2 \
               php8.2-cli php8.2-common php8.2-curl php8.2-xml php8.2-mbstring

# ==========================================
# ২. SignalWire Token চেক
# ==========================================
if [[ -z "${TOKEN:-}" ]]; then
    echo "❌ Error: TOKEN পাওয়া যায়নি!"
    echo "এভাবে রান করুন:"
    echo "TOKEN=swpat_9glS9Rz5XWsVIe5BBom0dwtz4fSpfA81naos $0"
    exit 1
fi
echo "✅ SignalWire Token গৃহীত হয়েছে।"

# ==========================================
# ৩. FreeSWITCH ইনস্টলেশন (SignalWire Official Repo)
# ==========================================
echo "📦 FreeSWITCH ইনস্টল করা হচ্ছে..."
curl -sSL https://freeswitch.org/fsget | bash -s "$TOKEN" release install

# সার্ভিস এনাবল ও শুরু
systemctl enable freeswitch
systemctl start freeswitch

# ==========================================
# ৪. FreeSWITCH-এ SIP Auth Failure লগিং সক্রিয় করা
#    (Fail2Ban-এর জন্য অত্যন্ত জরুরি)
# ==========================================
echo "🔧 FreeSWITCH-এ SIP auth failure লগিং সক্রিয় করা হচ্ছে..."

# internal প্রোফাইল
INTERNAL_XML="/etc/freeswitch/sip_profiles/internal.xml"
EXTERNAL_XML="/etc/freeswitch/sip_profiles/external.xml"

for xml_file in "$INTERNAL_XML" "$EXTERNAL_XML"; do
    if [[ -f "$xml_file" ]]; then
        # ব্যাকআপ তৈরি
        cp "$xml_file" "${xml_file}.bak.$(date +%Y%m%d%H%M%S)"
        
        # log-auth-failures প্যারামিটার না থাকলে যোগ করা, থাকলে true করা
        if grep -q 'name="log-auth-failures"' "$xml_file"; then
            sed -i 's/name="log-auth-failures" value="[^"]*"/name="log-auth-failures" value="true"/' "$xml_file"
        else
            sed -i '/<\/settings>/i \    <param name="log-auth-failures" value="true"/>' "$xml_file"
        fi
        echo "✅ $xml_file আপডেট করা হয়েছে (log-auth-failures = true)"
    else
        echo "⚠️ $xml_file পাওয়া যায়নি, বাদ দেওয়া হচ্ছে।"
    fi
done

# FreeSWITCH রিস্টার্ট যাতে কনফিগারেশন কার্যকর হয়
systemctl restart freeswitch
sleep 2

# ==========================================
# ৫. Fail2Ban ফিল্টার তৈরি (SIP Brute-Force Detection)
# ==========================================
echo "🛡️ Fail2Ban ফিল্টার তৈরি করা হচ্ছে..."

cat > /etc/fail2ban/filter.d/freeswitch.conf << 'EOF'
[Definition]
# SIP auth failure এবং challenge উভয়ই ক্যাচ করা হচ্ছে
# Pattern 1: Credential brute-force (auth failure)
# Pattern 2: Unauthenticated INVITE floods (auth challenge)
failregex = ^.*\[WARNING\] sofia_reg\.c:\d+ SIP auth failure \(REGISTER\) on sofia profile '[^']+' for \[.*\] from ip <HOST>.*$
            ^.*\[WARNING\] sofia_reg\.c:\d+ SIP auth failure \(INVITE\) on sofia profile '[^']+' for \[.*\] from ip <HOST>.*$
            ^.*\[WARNING\] sofia_reg\.c:\d+ SIP auth challenge \(REGISTER\) on sofia profile '[^']+' for \[.*\] from ip <HOST>.*$
            ^.*\[WARNING\] sofia_reg\.c:\d+ SIP auth challenge \(INVITE\) on sofia profile '[^']+' for \[.*\] from ip <HOST>.*$
            ^.*\[WARNING\] sofia_reg\.c:\d+ Can't find user \[.*\] from <HOST>.*$
            ^.*\[WARNING\] sofia\.c:\d+ IP <HOST> Rejected by acl.*$
            ^.*invalid password.*from <HOST>.*$
            ^.*authentication failed for <HOST>.*$
            ^.*AUTH FAILURE.*<HOST>.*$
            ^.*wrong password.*from <HOST>.*$

ignoreregex =
EOF

echo "✅ ফিল্টার ফাইল তৈরি হয়েছে: /etc/fail2ban/filter.d/freeswitch.conf"

# ==========================================
# ৬. Fail2Ban জেল কনফিগারেশন
# ==========================================
echo "🛡️ Fail2Ban জেল কনফিগার করা হচ্ছে..."

# ডিফল্ট ignoreip সেট করা (লোকালহোস্ট বাদ)
# এবং FreeSWITCH-এর জন্য একটি সমন্বিত জেল তৈরি করা
cat > /etc/fail2ban/jail.d/freeswitch.local << 'EOF'
[DEFAULT]
# লোকালহোস্ট এবং আপনার বিশ্বস্ত নেটওয়ার্ক যোগ করুন
ignoreip = 127.0.0.1/8 ::1

# ডিফল্ট ব্যান অ্যাকশন (Debian 12-এ nftables/iptables উভয়ই কাজ করে)
banaction = iptables-allports

# ==========================================
# FreeSWITCH Jail (SIP Brute-Force Protection)
# ==========================================
[freeswitch]
enabled  = true
filter   = freeswitch
logpath  = /var/log/freeswitch/freeswitch.log
maxretry = 20
findtime = 300
bantime  = 86400
# নিচের লাইনটি নিশ্চিত করে যে সমস্ত পোর্ট ব্লক করা হয়
action   = iptables-allports[name=freeswitch, protocol=all]
backend  = polling

# ==========================================
# Recidive Jail (পুনরায় আক্রমণকারীদের জন্য দীর্ঘমেয়াদী ব্যান)
# ==========================================
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = iptables-allports
bantime  = 2592000
findtime = 86400
maxretry = 5
EOF

# SSH ব্রুট-ফোর্স প্রতিরোধের জন্য ডিফল্ট SSH জেল সক্রিয় রাখা
cat > /etc/fail2ban/jail.d/sshd.local << 'EOF'
[sshd]
enabled  = true
maxretry = 5
findtime = 600
bantime  = 3600
EOF

# Fail2Ban রিস্টার্ট এবং এনাবল
systemctl enable fail2ban
systemctl restart fail2ban

echo "✅ Fail2Ban সেটআপ সম্পন্ন হয়েছে (SIP Brute-Force Protection সক্রিয়)।"

# ==========================================
# ৭. UFW ফায়ারওয়াল কনফিগারেশন
# ==========================================
echo "🔥 UFW ফায়ারওয়াল কনফিগার করা হচ্ছে..."

ufw default deny incoming
ufw default allow outgoing

# SSH
ufw allow OpenSSH

# HTTP/HTTPS (যদি ওয়েলকাম পেজ ব্যবহার করেন)
ufw allow 80/tcp
ufw allow 443/tcp

# SIP সিগন্যালিং (UDP এবং TCP)
ufw allow 5060/udp
ufw allow 5060/tcp
ufw allow 5061/udp
ufw allow 5061/tcp
ufw allow 5080/udp
ufw allow 5080/tcp
ufw allow 5081/udp
ufw allow 5081/tcp

# RTP মিডিয়া পোর্ট রেঞ্জ
ufw allow 16384:32768/udp

ufw --force enable
echo "✅ UFW ফায়ারওয়াল চালু হয়েছে।"

# ==========================================
# ৮. সাধারণ Welcome Page (ঐচ্ছিক, যাচাইয়ের জন্য)
# ==========================================
echo "🌐 Web Welcome Page তৈরি করা হচ্ছে..."

# PHP ইনফো ফাইল (যাচাইয়ের জন্য)
echo "<?php phpinfo(); ?>" > /var/www/html/info.php
chown www-data:www-data /var/www/html/info.php

# মূল ইনডেক্স পেজ (সাদামাটা)
cat > /var/www/html/index.php << 'EOF'
<?php
$fs_status = trim(shell_exec("systemctl is-active freeswitch 2>/dev/null") ?: 'unknown');
$f2b_status = trim(shell_exec("systemctl is-active fail2ban 2>/dev/null") ?: 'unknown');
?>
<!DOCTYPE html>
<html lang="bn">
<head>
    <meta charset="UTF-8">
    <title>FreeSWITCH Server</title>
    <style>
        body { font-family: sans-serif; background: #0f0f1a; color: #eee; text-align: center; padding: 50px; }
        .card { background: #1e1e2e; padding: 30px; border-radius: 20px; display: inline-block; }
        .active { color: #00e676; }
        .inactive { color: #ff6b6b; }
    </style>
</head>
<body>
    <div class="card">
        <h1>📞 FreeSWITCH Server</h1>
        <p>FreeSWITCH: <strong class="<?= $fs_status === 'active' ? 'active' : 'inactive' ?>"><?= $fs_status ?></strong></p>
        <p>Fail2Ban: <strong class="<?= $f2b_status === 'active' ? 'active' : 'inactive' ?>"><?= $f2b_status ?></strong></p>
    </div>
</body>
</html>
EOF
chown www-data:www-data /var/www/html/index.php

# Apache রিস্টার্ট
systemctl restart apache2

# ==========================================
# ৯. চূড়ান্ত সারাংশ
# ==========================================
SERVER_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "YOUR_SERVER_IP")

echo ""
echo "=========================================================="
echo "🎉 FreeSWITCH + Fail2Ban (SIP Brute-Force Protection) ইনস্টলেশন সম্পূর্ণ!"
echo "=========================================================="
echo ""
echo "🌐 ওয়েব ড্যাশবোর্ড: http://$SERVER_IP"
echo "🔧 PHP ইনফো: http://$SERVER_IP/info.php"
echo ""
echo "🛡️ Fail2Ban স্ট্যাটাস চেক:"
echo "   fail2ban-client status freeswitch"
echo "   fail2ban-client status recidive"
echo ""
echo "🔥 UFW স্ট্যাটাস: ufw status verbose"
echo ""
echo "📞 FreeSWITCH CLI: fs_cli -rRS"
echo ""
echo "📝 লগ মনিটর:"
echo "   tail -f /var/log/freeswitch/freeswitch.log"
echo "   tail -f /var/log/fail2ban.log"
echo ""
echo "⚠️ গুরুত্বপূর্ণ:"
echo "   - FreeSWITCH-এর ডিফল্ট পাসওয়ার্ড (1234, ClueCon) পরিবর্তন করুন।"
echo "   - /etc/fail2ban/jail.d/freeswitch.local ফাইলে আপনার বিশ্বস্ত IP যোগ করুন।"
echo "=========================================================="
