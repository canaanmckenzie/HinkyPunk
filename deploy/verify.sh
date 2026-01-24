#!/bin/bash
#
# HinkyPunk VPN Verification Script
# ==================================
#
# Runs basic verification tests to ensure the VPN is built correctly.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPN_BIN="${SCRIPT_DIR}/../bin/vpn"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASSED=0
FAILED=0

test_result() {
    if [[ $1 -eq 0 ]]; then
        echo -e "  ${GREEN}PASS${NC}: $2"
        ((PASSED++))
    else
        echo -e "  ${RED}FAIL${NC}: $2"
        ((FAILED++))
    fi
}

echo "HinkyPunk VPN Verification"
echo "=========================="
echo ""

# Test 1: Binary exists
echo "1. Binary verification"
if [[ -x "$VPN_BIN" ]]; then
    test_result 0 "VPN binary exists and is executable"
else
    test_result 1 "VPN binary not found at $VPN_BIN"
    echo "   Run 'make' to build the VPN first"
    exit 1
fi

# Test 2: Help output
"$VPN_BIN" -h > /dev/null 2>&1
test_result $? "Help command works"

# Test 3: Key generation
KEY=$("$VPN_BIN" genkey 2>/dev/null)
if [[ ${#KEY} -eq 44 ]] && [[ "$KEY" == *"="* ]]; then
    test_result 0 "Key generation produces valid base64"
else
    test_result 1 "Key generation failed"
fi

# Test 4: Public key derivation
PUBKEY=$(echo "$KEY" | "$VPN_BIN" pubkey 2>/dev/null)
if [[ ${#PUBKEY} -eq 44 ]] && [[ "$PUBKEY" == *"="* ]]; then
    test_result 0 "Public key derivation works"
else
    test_result 1 "Public key derivation failed"
fi

# Test 5: Keys are different
if [[ "$KEY" != "$PUBKEY" ]]; then
    test_result 0 "Private and public keys are different"
else
    test_result 1 "Private and public keys are the same (CRITICAL)"
fi

# Test 6: Deterministic public key
PUBKEY2=$(echo "$KEY" | "$VPN_BIN" pubkey 2>/dev/null)
if [[ "$PUBKEY" == "$PUBKEY2" ]]; then
    test_result 0 "Public key derivation is deterministic"
else
    test_result 1 "Public key derivation is not deterministic"
fi

# Test 7: Different private keys produce different public keys
KEY2=$("$VPN_BIN" genkey 2>/dev/null)
PUBKEY3=$(echo "$KEY2" | "$VPN_BIN" pubkey 2>/dev/null)
if [[ "$PUBKEY" != "$PUBKEY3" ]]; then
    test_result 0 "Different private keys produce different public keys"
else
    test_result 1 "Key generation entropy problem"
fi

echo ""
echo "=========================="
echo "Results: ${PASSED} passed, ${FAILED} failed"
echo ""

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}All verification tests passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run: ./deploy/setup.sh server 10.0.0.1 <your-ip>"
    echo "  2. On client: ./deploy/setup.sh client 10.0.0.2 <server-ip>"
    exit 0
else
    echo -e "${RED}Some tests failed. Check the output above.${NC}"
    exit 1
fi
