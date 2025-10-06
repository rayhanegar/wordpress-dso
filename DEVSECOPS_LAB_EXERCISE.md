# DevSecOps Lab Exercise: SQL Injection Detection and Remediation

## Lab Objectives
1. Understand how SQL injection vulnerabilities occur in WordPress plugins
2. Learn to identify vulnerable code patterns
3. Practice secure coding techniques
4. Implement detection and prevention mechanisms

## Prerequisites
- Docker environment with WordPress running locally
- Basic understanding of SQL and PHP
- Access to the codebase in `/home/dso505/wordpress-dso`

## Lab Environment Setup

### 1. Verify Your Environment

```bash
# Check if WordPress is running
curl -s http://localhost:8080 | head -20

# Check if My Calendar plugin is active
ls -la /home/dso505/wordpress-dso/wp-content/plugins/my-calendar/
```

### 2. Enable WordPress Debug Mode

Edit `docker-compose.yml` or create a debug configuration:

```yaml
services:
  wordpress:
    environment:
      WORDPRESS_DEBUG: 1
      WORDPRESS_DEBUG_LOG: 1
      WORDPRESS_DEBUG_DISPLAY: 0
```

## Exercise 1: Code Review and Vulnerability Identification

### Task 1.1: Locate the Vulnerable Function

```bash
# Search for the vulnerable function
grep -n "function my_calendar_get_events" wp-content/plugins/my-calendar/my-calendar-events.php

# View the function
sed -n '111,250p' wp-content/plugins/my-calendar/my-calendar-events.php
```

**Questions:**
1. Where are the `$from` and `$to` variables used in the SQL query?
2. Are they properly escaped or sanitized?
3. What WordPress function should be used instead?

### Task 1.2: Trace Data Flow

Create a data flow diagram showing:
```
User Input → API Endpoint → Parameter Processing → SQL Query → Database
```

## Exercise 2: Safe Vulnerability Testing (Local Only!)

### Setup Test Environment

```bash
# Create a test script
cat > /tmp/test_api.sh << 'EOF'
#!/bin/bash
BASE_URL="http://localhost:8080"

echo "Testing normal request..."
curl -s "${BASE_URL}/?rest_route=/my-calendar/v1/events&from=2025-01-01&to=2025-01-31" | jq '.' | head -20

echo -e "\nTesting with quote character..."
curl -s "${BASE_URL}/?rest_route=/my-calendar/v1/events&from=2025-01-01'&to=2025-01-31" 2>&1 | head -20

echo -e "\nCheck WordPress error log..."
docker-compose exec wordpress tail -20 /var/www/html/wp-content/debug.log
EOF

chmod +x /tmp/test_api.sh
```

### Test 1: Input Validation

```bash
# Test various input formats
curl "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01&to=2025-01-31"
curl "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-13-99&to=2025-01-31"  # Invalid date
curl "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=<script>alert(1)</script>&to=2025-01-31"  # XSS attempt
```

**Questions:**
1. What happens with invalid dates?
2. Does the API properly validate input?
3. What error messages are returned?

### Test 2: SQL Syntax Characters

```bash
# Test with SQL special characters (URL encoded)
curl "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01%27&to=2025-01-31"  # Single quote
curl "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01%22&to=2025-01-31"  # Double quote
curl "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01%3B&to=2025-01-31"  # Semicolon
```

**Document your observations:**
- Response codes
- Error messages
- Database error logs
- Application behavior

## Exercise 3: Implement Security Fixes

### Task 3.1: Create a Secure Version

Create a patched version of the function:

```bash
# Create a backup
cp wp-content/plugins/my-calendar/my-calendar-events.php \
   wp-content/plugins/my-calendar/my-calendar-events.php.vulnerable

# Create patch file
cat > /tmp/secure_fix.patch << 'EOF'
--- a/my-calendar-events.php
+++ b/my-calendar-events.php
@@ -111,8 +111,24 @@ function my_calendar_get_events( $args ) {
-	$from     = isset( $args['from'] ) ? $args['from'] : '';
-	$to       = isset( $args['to'] ) ? $args['to'] : '';
+	// Secure: Validate and sanitize date inputs
+	$from_raw = isset( $args['from'] ) ? $args['from'] : '';
+	$to_raw   = isset( $args['to'] ) ? $args['to'] : '';
+	
+	// Strict date format validation (YYYY-MM-DD only)
+	if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $from_raw ) ) {
+		error_log( 'Invalid from date format: ' . $from_raw );
+		return array();
+	}
+	if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $to_raw ) ) {
+		error_log( 'Invalid to date format: ' . $to_raw );
+		return array();
+	}
+	
+	// Additional validation
+	$from = sanitize_text_field( $from_raw );
+	$to = sanitize_text_field( $to_raw );
+	
EOF
```

### Task 3.2: Implement Input Validation Helper

Create a new file: `wp-content/plugins/my-calendar/includes/class-mc-security.php`

```php
<?php
/**
 * Security helper functions for My Calendar
 *
 * @package My Calendar
 */

class MC_Security {
    
    /**
     * Validate date parameter against SQL injection
     *
     * @param string $date Input date string
     * @return string|false Validated date or false
     */
    public static function validate_date_param( $date ) {
        // Allow only YYYY-MM-DD format
        if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date ) ) {
            self::log_security_event( 'Invalid date format', $date );
            return false;
        }
        
        // Verify it's a real date
        $parts = explode( '-', $date );
        if ( ! checkdate( (int) $parts[1], (int) $parts[2], (int) $parts[0] ) ) {
            self::log_security_event( 'Invalid calendar date', $date );
            return false;
        }
        
        return $date;
    }
    
    /**
     * Log security events
     *
     * @param string $event Event type
     * @param mixed  $data Event data
     */
    public static function log_security_event( $event, $data ) {
        if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
            error_log( sprintf(
                '[MC_SECURITY] %s: %s | IP: %s | User-Agent: %s',
                $event,
                is_string( $data ) ? $data : json_encode( $data ),
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ) );
        }
    }
    
    /**
     * Detect potential SQLi patterns
     *
     * @param string $input Input string
     * @return bool True if suspicious pattern detected
     */
    public static function detect_sqli_pattern( $input ) {
        $patterns = array(
            '/(\bunion\b.*\bselect\b)/i',
            '/(\bselect\b.*\bfrom\b)/i',
            '/(;|\||&&)/',
            '/(\bor\b\s+\d+\s*=\s*\d+)/i',
            '/(\band\b\s+\d+\s*=\s*\d+)/i',
            '/(--|#|\/\*|\*\/)/i',
            '/(\bexec\b|\bexecute\b)/i',
            '/(\bdrop\b|\bdelete\b|\binsert\b|\bupdate\b)/i',
        );
        
        foreach ( $patterns as $pattern ) {
            if ( preg_match( $pattern, $input ) ) {
                self::log_security_event( 'SQLi pattern detected', $input );
                return true;
            }
        }
        
        return false;
    }
}
```

### Task 3.3: Update API Endpoint

Modify the API function to use the security class:

```php
function my_calendar_rest_route( WP_REST_Request $request ) {
    $parameters = $request->get_params();
    
    // Use security validator
    $from = MC_Security::validate_date_param( $parameters['from'] );
    $to = MC_Security::validate_date_param( $parameters['to'] );
    
    if ( false === $from || false === $to ) {
        return new WP_Error(
            'invalid_date',
            'Invalid date format. Use YYYY-MM-DD.',
            array( 'status' => 400 )
        );
    }
    
    // Check for SQLi patterns
    if ( MC_Security::detect_sqli_pattern( $parameters['from'] ) ||
         MC_Security::detect_sqli_pattern( $parameters['to'] ) ) {
        return new WP_Error(
            'security_violation',
            'Request blocked for security reasons.',
            array( 'status' => 403 )
        );
    }
    
    // Continue with validated input...
}
```

## Exercise 4: Automated Security Testing

### Setup SQLMap (Optional - Use Carefully!)

```bash
# Install SQLMap (if not already installed)
docker run --rm -it --network="host" \
    andresriancho/sqlmap \
    -u "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01*" \
    --batch \
    --level=1 \
    --risk=1 \
    --technique=B
```

### Create Custom Security Scanner

```bash
cat > /tmp/mc_security_scanner.sh << 'EOF'
#!/bin/bash

BASE_URL="http://localhost:8080"
TEST_COUNT=0
FAIL_COUNT=0

test_injection() {
    local payload="$1"
    local description="$2"
    
    TEST_COUNT=$((TEST_COUNT + 1))
    echo "Test ${TEST_COUNT}: ${description}"
    
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        "${BASE_URL}/?rest_route=/my-calendar/v1/events&from=${payload}&to=2025-01-31")
    
    if [ "$RESPONSE" != "400" ] && [ "$RESPONSE" != "403" ]; then
        echo "  ❌ FAIL - Response: $RESPONSE (should block with 400 or 403)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo "  ✓ PASS - Blocked properly with $RESPONSE"
    fi
}

echo "=== My Calendar Security Scanner ==="
echo

test_injection "2025-01-01'" "Single quote"
test_injection "2025-01-01;--" "SQL comment"
test_injection "2025-01-01' OR '1'='1" "Boolean injection"
test_injection "2025-01-01' UNION SELECT 1--" "Union injection"
test_injection "<script>alert(1)</script>" "XSS attempt"
test_injection "../../etc/passwd" "Path traversal"

echo
echo "=== Results ==="
echo "Tests run: ${TEST_COUNT}"
echo "Failures: ${FAIL_COUNT}"

if [ $FAIL_COUNT -eq 0 ]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "❌ Some tests failed!"
    exit 1
fi
EOF

chmod +x /tmp/mc_security_scanner.sh
```

### Run the Scanner

```bash
# Before fix
/tmp/mc_security_scanner.sh

# After implementing fixes
/tmp/mc_security_scanner.sh
```

## Exercise 5: Implement Monitoring and Alerting

### Create Security Monitor

```php
// Add to wp-content/mu-plugins/mc-security-monitor.php

<?php
/**
 * Security monitoring for My Calendar API
 */

add_action( 'rest_api_init', function() {
    add_filter( 'rest_pre_dispatch', 'mc_security_monitor', 10, 3 );
});

function mc_security_monitor( $result, $server, $request ) {
    $route = $request->get_route();
    
    if ( false !== strpos( $route, '/my-calendar/' ) ) {
        $params = $request->get_params();
        
        // Check for suspicious patterns
        foreach ( $params as $key => $value ) {
            if ( is_string( $value ) && mc_is_suspicious( $value ) ) {
                // Log the attempt
                error_log( sprintf(
                    '[MC_SECURITY] Suspicious request blocked | Route: %s | Param: %s | Value: %s | IP: %s',
                    $route,
                    $key,
                    $value,
                    $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ) );
                
                // Send alert
                mc_send_security_alert( $route, $key, $value );
                
                // Block the request
                return new WP_Error(
                    'security_block',
                    'Request blocked for security reasons',
                    array( 'status' => 403 )
                );
            }
        }
    }
    
    return $result;
}

function mc_is_suspicious( $value ) {
    $patterns = array(
        '/[\'\";]/',
        '/(\bunion\b.*\bselect\b)/i',
        '/(--|#|\/\*)/',
        '/(\bor\b|\band\b)\s+\d+\s*=\s*\d+/i',
    );
    
    foreach ( $patterns as $pattern ) {
        if ( preg_match( $pattern, $value ) ) {
            return true;
        }
    }
    
    return false;
}

function mc_send_security_alert( $route, $param, $value ) {
    // In production, send to SIEM or security team
    $admin_email = get_option( 'admin_email' );
    $subject = '[Security Alert] SQL Injection Attempt Detected';
    $message = sprintf(
        "A potential SQL injection attempt was detected:\n\n" .
        "Route: %s\n" .
        "Parameter: %s\n" .
        "Value: %s\n" .
        "IP: %s\n" .
        "Time: %s\n",
        $route,
        $param,
        $value,
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        current_time( 'mysql' )
    );
    
    wp_mail( $admin_email, $subject, $message );
}
```

## Exercise 6: Security Hardening Checklist

Complete this checklist for your implementation:

- [ ] All SQL queries use `$wpdb->prepare()` or equivalent
- [ ] Input validation implemented for all parameters
- [ ] Security logging enabled
- [ ] Rate limiting configured
- [ ] Error messages don't leak sensitive information
- [ ] Database user has minimal required permissions
- [ ] HTTPS enforced for API endpoints
- [ ] API authentication implemented (if needed)
- [ ] Security headers configured (CSP, HSTS, etc.)
- [ ] Regular security audits scheduled

## Lab Report Template

Document your findings:

```markdown
# Security Assessment Report

## Executive Summary
[Brief overview of findings]

## Vulnerabilities Identified
1. **SQL Injection in `my_calendar_get_events()`**
   - Severity: Critical
   - CVSS Score: 9.8
   - Status: [Fixed/In Progress/Not Fixed]

## Proof of Concept
[Your testing steps and results]

## Remediation Steps
[What you implemented]

## Verification
[How you verified the fix]

## Recommendations
[Additional security measures]

## Lessons Learned
[What you learned from this exercise]
```

## Additional Challenges

### Challenge 1: Find Other Vulnerabilities
Search for similar patterns in other parts of the plugin:
```bash
grep -r "SELECT.*FROM.*WHERE" wp-content/plugins/my-calendar/ | grep -v "prepare"
```

### Challenge 2: Implement WAF Rules
Create ModSecurity rules to block SQLi attempts at the web server level.

### Challenge 3: Create Automated Tests
Write PHPUnit tests for the security validation functions.

### Challenge 4: Security Documentation
Create developer guidelines for secure SQL query practices.

## Resources

- OWASP SQL Injection Cheat Sheet
- WordPress Coding Standards - Security
- WordPress Plugin Security Best Practices
- NIST Secure Coding Guidelines

## Submission

Document:
1. Vulnerabilities found
2. Fixes implemented
3. Test results
4. Lessons learned

---

**Remember:** This exercise is for educational purposes in a controlled environment only!
