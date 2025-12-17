# Security Testing for Web Applications

## Task 3: CODTECH Internship

### Project Overview
This repository contains comprehensive security testing analysis for web applications, identifying and documenting vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), and other OWASP Top 10 vulnerabilities.

## Test Target: OWASP Juice Shop

**URL**: `https://juice-shop.herokuapp.com/`

OWASP Juice Shop is an intentionally insecure web application for learning web application security. It contains intentional vulnerabilities that can be exploited for educational purposes.

**Alternative (Local Deployment)**: `http://localhost:3000/` (after Docker installation)

Docker command to run locally:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```



### Objectives
- Identify security vulnerabilities in web applications
- Document findings with proof of concept
- Provide remediation strategies
- Create comprehensive security testing reports

### Testing Scope

#### 1. SQL Injection Testing
- Input field manipulation
- Database query analysis
- Common SQL payloads testing

#### 2. Cross-Site Scripting (XSS) Testing
- Reflected XSS vulnerabilities
- Stored XSS vulnerabilities
- DOM-based XSS

#### 3. OWASP Top 10 Analysis
- Broken Access Control
- Cryptographic Failures
- Injection attacks
- Insecure Design
- Security Misconfiguration

### Tools Used
- OWASP ZAP (Zed Attack Proxy)
- Burp Suite Community Edition
- Manual testing techniques
- Browser Developer Tools

### Files in This Repository

1. **SECURITY-REPORT.md** - Detailed security testing report
2. **VULNERABILITIES.md** - Complete list of vulnerabilities found
3. **SQL-INJECTION-TESTS.md** - SQL injection test cases and payloads
4. **XSS-TESTS.md** - XSS vulnerability test cases
5. **REMEDIATION-GUIDE.md** - Fix recommendations for each vulnerability
6. **.gitignore** - Git ignore file

### Key Findings

The security testing identified multiple vulnerabilities across the application. Detailed analysis and recommendations are provided in the individual report files.

### How to Use This Repository

1. Review the SECURITY-REPORT.md for executive summary
2. Check VULNERABILITIES.md for detailed findings
3. Review specific test files for individual vulnerability analysis
4. Follow REMEDIATION-GUIDE.md to fix identified issues

### Security Testing Methodology

The testing followed industry-standard methodologies:
- OWASP Testing Guide v4
- Manual security testing
- Automated vulnerability scanning
- Code review for security issues

### Recommendations

1. Implement input validation for all user inputs
2. Use parameterized queries to prevent SQL injection
3. Implement proper output encoding for XSS prevention
4. Regular security testing and code reviews
5. Keep all dependencies updated

### Author
CODTECH Internship - Security Testing Task

### Date
January 2025
