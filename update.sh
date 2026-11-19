#!/bin/bash

# Strict mode: ত্রুটি হলে স্ক্রিপ্ট থামিয়ে দেবে
set -euo pipefail

# Root বা sudo অনুমতি আছে কি না তা যাচাই
if [ "$EUID" -ne 0 ]; then
    echo "❌ অনুগ্রহ করে স্ক্রিপ্টটি sudo বা root হিসেবে চালান: sudo ./update.sh"
    exit 1
fi

# Non-interactive মোড যাতে আপডেটের সময় কোনো প্রম্পটে আটকে না যায়
export DEBIAN_FRONTEND=noninteractive

LOG_FILE="/var/log/debian12-update-$(date +%F).log"
echo "📋 লগ সংরক্ষিত হচ্ছে: $LOG_FILE"

{
    echo "=========================================="
    echo "🚀 Debian 12 Full Update শুরু: $(date)"
    echo "=========================================="

    echo "🔄 ১. প্যাকেজ ইনডেক্স আপডেট করা হচ্ছে (apt update)..."
    apt-get update -y

    echo "⬆️ ২. সব প্যাকেজ ফুল আপগ্রেড করা হচ্ছে (apt full-upgrade)..."
    apt-get full-upgrade -y

    echo "🧹 ৩. অপ্রয়োজনীয় প্যাকেজ ও ডিপেন্ডেন্সি মুছে ফেলা হচ্ছে (autoremove)..."
    apt-get autoremove --purge -y

    echo "🗑️ ৪. পুরনো ডাউনলোড করা প্যাকেজ ক্যাশ পরিষ্কার করা হচ্ছে (autoclean)..."
    apt-get autoclean -y

    echo "🔍 ৫. সিস্টেম রিবুট প্রয়োজন কি না তা যাচাই করা হচ্ছে..."
    if [ -f /var/run/reboot-required ]; then
        echo "⚠️ সতর্কতা: কার্নেল বা মূল সিস্টেম প্যাকেজ আপডেট হয়েছে। সিস্টেম রিবুট করা জরুরি!"
        if [ -f /var/run/reboot-required.pkgs ]; then
            echo "রিবুটের কারণ থাকা প্যাকেজসমূহ:"
            cat /var/run/reboot-required.pkgs
        fi
    else
        echo "✅ এই মুহূর্তে রিবুট প্রয়োজন নেই।"
    fi

    echo "=========================================="
    echo "🎉 Debian 12 Full Update সফলভাবে সম্পন্ন হয়েছে: $(date)"
    echo "=========================================="
} 2>&1 | tee -a "$LOG_FILE"
