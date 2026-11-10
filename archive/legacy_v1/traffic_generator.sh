#!/bin/sh
# Minimal RAM traffic simulator for Alpine Linux containers

CLIENT_NAME=${1:-"client"}
TARGET_IP=${2:-"10.10.0.5"}

echo "[$CLIENT_NAME] Starting lightweight traffic simulation targeting $TARGET_IP..."

while true; do
    # 1. Simulate DNS queries (resolving random public / internal hosts)
    for domain in google.com cloudflare.com internal.login.portal auth.local; do
        nslookup "$domain" "$TARGET_IP" > /dev/null 2>&1 || true
    done

    # 2. Simulate HTTP connection attempts
    curl -s --connect-timeout 2 "http://$TARGET_IP:8080/portal" > /dev/null 2>&1 || true

    # 3. Random ICMP probe
    ping -c 2 -W 1 "$TARGET_IP" > /dev/null 2>&1 || true

    # Random jitter delay to mimic realistic client activity (5 to 15 seconds)
    SLEEP_SEC=$(( (RANDOM % 10) + 5 ))
    sleep "$SLEEP_SEC"
done
