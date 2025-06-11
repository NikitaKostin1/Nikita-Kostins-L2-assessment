#!/bin/bash

LOG_FILE="${1:-nginx_access.log}"
THRESHOLD_REQ_PER_MIN=70
THRESHOLD_ERRORS=100
THRESHOLD_ENDPOINT=100
SUSPICIOUS_PATTERNS=("/")

echo "=== Suspicious Activity Report ==="
echo "Log File: $LOG_FILE"
echo

# Top IPs with more than $THRESHOLD_REQ_PER_MIN requests per minute
echo "[!] IPs with high request rate per minutes (possible DoS):"
awk '{print $1, substr($4, 2, 17)}' "$LOG_FILE" | cut -d: -f1,2 | sort | uniq -c | awk -v threshold="$THRESHOLD_REQ_PER_MIN" '$1 >= threshold {printf "Count: %s | Ip: %s,   Minute : %s\n", $1, $2, $3}' | sort -nr
echo

# IPs with excessive error codes
echo "[!] IPs with excessive 4xx/5xx error responses:"
awk '{print $1, $10}' "$LOG_FILE" | sort | uniq -c | awk -v threshold="$THRESHOLD_ERRORS" '$1 > threshold && ($3 ~ /^[45][0-9][0-9]$/) {printf "Count: %s | Ip: %s,   Status: %s\n", $1, $2, $3}' | sort -nr
echo

# Suspicious URL access patterns
echo "[!] Top 10 requests to suspicious URLs:"
for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
    echo "Pattern: $pattern"
    grep "$pattern" "$LOG_FILE" | awk '{print $1, $8}' | sort | uniq -c | sort -nr | awk -v threshold="$THRESHOLD_ENDPOINT" '$1 > threshold {printf "Count: %s | Ip: %s,   Endpoint: %s\n", $1, $2, $3}'
    echo
done

# Summary of top offending IPs
echo "[!] Top 10 most active IPs:"
awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr | head -10 | awk '$1 > threshold {printf "Count: %s | Ip: %s\n", $1, $2}' | sort -nr
echo
