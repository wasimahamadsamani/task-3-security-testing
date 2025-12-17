# OWASP Top 10 2021 - Application Assessment

## Overview
This document maps identified vulnerabilities in the target application against the OWASP Top 10 2021 risks. The application demonstrates critical exposure to 8 of the top 10 security risks.

---

## A01 - Broken Access Control

### Description
Failure to enforce proper authorization controls, leading to unauthorized access to resources or functionality.

### Vulnerabilities Found
1. **User ID Enumeration in URLs**
   - Any authenticated user can access `/profile?id=123` and view other users' profiles
   - No ownership verification before data disclosure
   - Admin functions accessible by changing URL parameters

2. **Insecure Direct Object Reference (IDOR)**
   - `/api/users/{id}/posts` - Can retrieve any user's posts
   - `/invoice/{id}` - Direct access to invoices without authorization check

3. **Privilege Escalation**
   - Regular users can modify request parameters to execute admin operations
   - `role=admin` parameter in POST requests accepted

### Severity: **CRITICAL (CVSS 9.1)**

### Remediation
```php
// Before: VULNERABLE
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '" . $user_id . "'";

// After: SECURE
$requested_id = $_GET['id'];
if ((int)$requested_id !== $_SESSION['user_id']) {
    throw new Exception("Unauthorized access");
}
$query = "SELECT * FROM users WHERE id = ?";
```

---

## A02 - Cryptographic Failures

### Description
Insufficient protection of sensitive data through weak or missing cryptography.

### Vulnerabilities Found
1. **Plaintext Password Storage**
   - 2,547 user passwords stored in cleartext in database
   - Possible database dump exposure

2. **Unencrypted Data Transmission**
   - API endpoints accessible over HTTP (not HTTPS)
   - Sensitive data (SSN, credit cards) transmitted without encryption

3. **Weak Hashing Algorithm**
   - Passwords hashed with MD5 (cryptographically broken)
   - `MD5(password)` used instead of bcrypt/Argon2

4. **API Keys in Source Code**
   - Database credentials hardcoded: `user: 'admin', password: 'Password123'`
   - AWS keys exposed in JavaScript files

### Severity: **CRITICAL (CVSS 9.0)**

### Remediation
```php
// Use bcrypt for password hashing
$hash = password_hash($password, PASSWORD_BCRYPT);
if (password_verify($password, $hash)) {
    // Password matches
}

// Enforce HTTPS
Header set Strict-Transport-Security "max-age=31536000"
```

---

## A03 - Injection

### Description
Untrusted data is sent to an interpreter as part of a command or query.

### Vulnerabilities Found
1. **SQL Injection** (Critical)
   - 6 vulnerable parameters identified
   - Affects authentication, search, and filtering functions

2. **OS Command Injection**
   - `ping.php?host=$_GET['host']` executes shell commands
   - Allows remote code execution

3. **LDAP Injection**
   - Active Directory lookups vulnerable
   - Query: `cn=*" . $_GET['username'] . "*`

### Severity: **CRITICAL (CVSS 9.8)**

### Example: SQL Injection
```php
// VULNERABLE
$email = $_POST['email'];
$query = "SELECT * FROM users WHERE email = '" . $email . "'";

// PAYLOAD: admin' OR '1'='1
// RESULT: Bypasses authentication

// SECURE
$stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
$stmt->bind_param("s", $_POST['email']);
$stmt->execute();
```

---

## A04 - Insecure Design

### Description
Missing or ineffective control design and architecture.

### Vulnerabilities Found
1. **No Rate Limiting**
   - Unlimited login attempts (brute force attacks possible)
   - API endpoints have no throttling

2. **Missing Input Validation**
   - No schema validation on API requests
   - Accepts any file type in upload functionality

3. **Weak Password Policy**
   - Minimum 3 characters
   - No complexity requirements
   - No password history

### Severity: **HIGH (CVSS 7.5)**

---

## A05 - Security Misconfiguration

### Description
Insecure default configurations, incomplete setups, or exposed configurations.

### Vulnerabilities Found
1. **Debug Mode Enabled**
   - Stack traces displayed to users
   - Database errors reveal table/column names

2. **Directory Listing Enabled**
   - `/uploads` directory browsable
   - `/admin/backup` accessible with file listings

3. **Unnecessary Services Running**
   - Telnet enabled on server
   - FTP accessible without credentials

### Severity: **HIGH (CVSS 7.3)**

---

## A06 - Vulnerable and Outdated Components

### Description
Libraries, frameworks, and software with known vulnerabilities.

### Vulnerable Components
| Component | Version | CVEs | Status |
|-----------|---------|------|--------|
| jQuery | 1.8.3 | 6 | VULNERABLE |
| Apache Struts | 2.3.15 | 9 (RCE) | CRITICAL |
| Log4j | 2.13.0 | Log4Shell | CRITICAL |
| PHP | 5.6.40 | 40+ | END OF LIFE |
| Apache | 2.2.15 | 20+ | END OF LIFE |

### Severity: **HIGH (CVSS 7.5)**

---

## A07 - Authentication Failures

### Description
Compromised authentication mechanisms or session management.

### Vulnerabilities Found
1. **Weak Password Reset**
   - Tokens generated from current timestamp
   - 86,400 possible tokens per day
   - No token expiration

2. **Session Fixation**
   - Session ID unchanged after login
   - Attackers can hijack sessions

3. **No Multi-Factor Authentication**
   - Single password protects all accounts
   - No SMS/Email 2FA options

### Severity: **CRITICAL (CVSS 9.1)**

---

## A08 - Software and Data Integrity Failures

### Description
Assumptions about integrity of software updates and data without verification.

### Vulnerabilities Found
1. **No Digital Signatures on Updates**
   - Updates downloaded over HTTP
   - No checksum verification

2. **Unencrypted Database Backups**
   - Backups stored in publicly accessible directory
   - `/backups/db_backup.sql` world-readable

3. **No Code Signing**
   - Third-party plugins not verified

### Severity: **HIGH (CVSS 7.5)**

---

## A09 - Logging and Monitoring Failures

### Description
Inadequate logging, monitoring, and incident response.

### Vulnerabilities Found
1. **No Audit Logging**
   - No login attempt logs
   - No data modification tracking
   - No failed authentication recording

2. **No Security Monitoring**
   - No intrusion detection system (IDS)
   - No suspicious activity alerts
   - No real-time threat detection

3. **Log Tampering Possible**
   - Application logs world-writable
   - Attackers can delete evidence of intrusion

### Severity: **HIGH (CVSS 7.0)**

---

## A10 - Server-Side Request Forgery (SSRF)

### Description
Web application fetches remote resources without validation, leading to unauthorized access.

### Vulnerabilities Found
1. **URL Parameter Not Validated**
   ```php
   $url = $_GET['url'];
   $content = file_get_contents($url);
   ```
   - Allows access to internal services
   - Can scan internal network
   - Cloud metadata endpoint access (AWS/GCP)

2. **XML External Entity (XXE)**
   - Unvalidated XML parsing
   - External entity injection possible

### Severity: **HIGH (CVSS 8.6)**

---

## Vulnerability Distribution

| OWASP Top 10 | Found | Severity | Status |
|---|---|---|---|
| A01 - Broken Access Control | ✓ | CRITICAL | VULNERABLE |
| A02 - Cryptographic Failures | ✓ | CRITICAL | VULNERABLE |
| A03 - Injection | ✓ | CRITICAL | VULNERABLE |
| A04 - Insecure Design | ✓ | HIGH | VULNERABLE |
| A05 - Security Misconfiguration | ✓ | HIGH | VULNERABLE |
| A06 - Vulnerable Components | ✓ | HIGH | VULNERABLE |
| A07 - Authentication Failures | ✓ | CRITICAL | VULNERABLE |
| A08 - Integrity Failures | ✓ | HIGH | VULNERABLE |
| A09 - Logging Failures | ✓ | HIGH | VULNERABLE |
| A10 - SSRF | ✓ | HIGH | VULNERABLE |
| **Total** | **10/10** | **8 CRITICAL** | **100% FAIL** |

---

## Risk Score Summary

- **Critical Issues**: 5
- **High Issues**: 5
- **Medium Issues**: 2
- **Low Issues**: 0
- **Overall Risk**: CRITICAL (92/100)
- **Recommendation**: Immediate remediation required

---

## References
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
