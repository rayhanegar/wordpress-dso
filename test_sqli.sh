#!/bin/bash

# SQL Injection Testing Script for My Calendar Plugin
# Educational Purpose Only - Use in controlled lab environment
# DevSecOps Training Exercise

set -e

echo "=========================================="
echo "My Calendar SQLi Testing Script"
echo "For DevSecOps Educational Training"
echo "=========================================="
echo ""

# Configuration
BASE_URL="${BASE_URL:-http://localhost:8080}"
TEST_RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to test endpoint
test_endpoint() {
    local test_name="$1"
    local from_param="$2"
    local to_param="${3:-2025-01-31}"
    local expected_block="${4:-false}"
    
    echo -n "Testing: ${test_name}... "
    
    # Make request
    response=$(curl -s -o /tmp/response.txt -w "%{http_code}" \
        "${BASE_URL}/?rest_route=/my-calendar/v1/events&from=${from_param}&to=${to_param}" 2>&1)
    
    http_code=$?
    
    if [ "$expected_block" = "true" ]; then
        # We expect this to be blocked (400 or 403)
        if [[ "$response" == "400" || "$response" == "403" ]]; then
            echo -e "${GREEN}✓ PASS${NC} - Properly blocked (HTTP $response)"
            PASS_COUNT=$((PASS_COUNT + 1))
            TEST_RESULTS+=("PASS: ${test_name}")
        else
            echo -e "${RED}✗ FAIL${NC} - Should be blocked but got HTTP $response"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            TEST_RESULTS+=("FAIL: ${test_name} - HTTP $response")
        fi
    else
        # We expect this to work (200)
        if [[ "$response" == "200" ]]; then
            echo -e "${GREEN}✓ PASS${NC} - Valid request accepted (HTTP $response)"
            PASS_COUNT=$((PASS_COUNT + 1))
            TEST_RESULTS+=("PASS: ${test_name}")
        else
            echo -e "${RED}✗ FAIL${NC} - Valid request failed with HTTP $response"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            TEST_RESULTS+=("FAIL: ${test_name} - HTTP $response")
        fi
    fi
}

# Check if WordPress is running
echo "Checking if WordPress is accessible at ${BASE_URL}..."
if ! curl -s -f -o /dev/null "${BASE_URL}"; then
    echo -e "${RED}ERROR: Cannot connect to ${BASE_URL}${NC}"
    echo "Make sure your WordPress Docker container is running:"
    echo "  docker-compose up -d"
    exit 1
fi
echo -e "${GREEN}✓${NC} WordPress is accessible"
echo ""

echo "=========================================="
echo "Starting Security Tests"
echo "=========================================="
echo ""

# Test 1: Normal valid request (should work)
echo "=== Baseline Tests (Should Pass) ==="
test_endpoint "Valid date range" "2025-01-01" "2025-01-31" "false"
test_endpoint "Valid single day" "2025-01-15" "2025-01-15" "false"
echo ""

# Test 2: SQL Injection attempts (should be blocked)
echo "=== SQL Injection Tests (Should Block) ==="
test_endpoint "Single quote injection" "2025-01-01'" "2025-01-31" "true"
test_endpoint "Boolean OR injection" "2025-01-01'%20OR%201=1--" "2025-01-31" "true"
test_endpoint "UNION SELECT injection" "2025-01-01'%20UNION%20SELECT%201--" "2025-01-31" "true"
test_endpoint "Comment injection" "2025-01-01;--" "2025-01-31" "true"
test_endpoint "Double quote injection" "2025-01-01\"" "2025-01-31" "true"
test_endpoint "Semicolon injection" "2025-01-01;" "2025-01-31" "true"
echo ""

# Test 3: Other injection types (should be blocked)
echo "=== Other Injection Tests (Should Block) ==="
test_endpoint "XSS attempt" "%3Cscript%3Ealert(1)%3C/script%3E" "2025-01-31" "true"
test_endpoint "Path traversal" "../../etc/passwd" "2025-01-31" "true"
test_endpoint "Command injection" "2025-01-01;ls" "2025-01-31" "true"
echo ""

# Test 4: Invalid formats (should be rejected)
echo "=== Invalid Format Tests (Should Reject) ==="
test_endpoint "Invalid date format" "01-01-2025" "2025-01-31" "true"
test_endpoint "Invalid date" "2025-13-99" "2025-01-31" "true"
test_endpoint "Non-date string" "not-a-date" "2025-01-31" "true"
echo ""

# Test 5: Legacy API endpoint
echo "=== Testing Legacy API Endpoint ==="
echo -n "Testing legacy API with SQLi... "
legacy_response=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/?my-calendar-api=json&from=2025-01-01'")
if [[ "$legacy_response" == "400" || "$legacy_response" == "403" ]]; then
    echo -e "${GREEN}✓ PASS${NC} - Blocked (HTTP $legacy_response)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo -e "${RED}✗ FAIL${NC} - Not blocked (HTTP $legacy_response)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total Tests: $((PASS_COUNT + FAIL_COUNT))"
echo -e "${GREEN}Passed: ${PASS_COUNT}${NC}"
echo -e "${RED}Failed: ${FAIL_COUNT}${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}✓ All security tests passed!${NC}"
    echo "The plugin is properly protected against SQL injection."
    exit 0
else
    echo -e "${YELLOW}⚠ Some tests failed!${NC}"
    echo ""
    echo "Failed tests indicate potential SQL injection vulnerabilities."
    echo "Review SECURITY_ANALYSIS.md for remediation steps."
    echo ""
    echo "Failed tests:"
    for result in "${TEST_RESULTS[@]}"; do
        if [[ $result == FAIL:* ]]; then
            echo "  - ${result#FAIL: }"
        fi
    done
    exit 1
fi
