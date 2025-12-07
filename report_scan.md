# Security Report

## Project
Security Analisis

## Group Name
Natalia Espitia - Jesus Jauregui

## Date
2025-12-06 23:19:42

---

## 1. Vulnerabilities Found

### Bandit Findings

- **File:** ./DjangoGoat/features/environment.py | **Severity:** HIGH | **Issue:** subprocess call with shell=True identified, security issue. | **CWE:** 78 | **Line:** 37

### Trivy Image Findings

- **CVE:** NSWG-ECO-428 | **Package:** base64url | **Installed:** 0.0.6 | **Fixed:** >=3.0.0 | **Severity:** HIGH
- **CVE:** CVE-2024-4068 | **Package:** braces | **Installed:** 2.3.2 | **Fixed:** 3.0.3 | **Severity:** HIGH
- **CVE:** CVE-2023-46233 | **Package:** crypto-js | **Installed:** 3.3.0 | **Fixed:** 4.2.0 | **Severity:** CRITICAL
- **CVE:** CVE-2020-15084 | **Package:** express-jwt | **Installed:** 0.1.3 | **Fixed:** 6.0.0 | **Severity:** HIGH
- **CVE:** CVE-2025-64756 | **Package:** glob | **Installed:** 10.4.5 | **Fixed:** 11.1.0, 10.5.0 | **Severity:** HIGH
- **CVE:** CVE-2022-25881 | **Package:** http-cache-semantics | **Installed:** 3.8.1 | **Fixed:** 4.1.1 | **Severity:** HIGH
- **CVE:** CVE-2024-29415 | **Package:** ip | **Installed:** 2.0.1 | **Fixed:** None | **Severity:** HIGH
- **CVE:** CVE-2015-9235 | **Package:** jsonwebtoken | **Installed:** 0.1.0 | **Fixed:** 4.2.2 | **Severity:** CRITICAL
- **CVE:** CVE-2022-23539 | **Package:** jsonwebtoken | **Installed:** 0.1.0 | **Fixed:** 9.0.0 | **Severity:** HIGH
- **CVE:** NSWG-ECO-17 | **Package:** jsonwebtoken | **Installed:** 0.1.0 | **Fixed:** >=4.2.2 | **Severity:** HIGH
- **CVE:** CVE-2015-9235 | **Package:** jsonwebtoken | **Installed:** 0.4.0 | **Fixed:** 4.2.2 | **Severity:** CRITICAL
- **CVE:** CVE-2022-23539 | **Package:** jsonwebtoken | **Installed:** 0.4.0 | **Fixed:** 9.0.0 | **Severity:** HIGH
- **CVE:** NSWG-ECO-17 | **Package:** jsonwebtoken | **Installed:** 0.4.0 | **Fixed:** >=4.2.2 | **Severity:** HIGH
- **CVE:** CVE-2016-1000223 | **Package:** jws | **Installed:** 0.2.6 | **Fixed:** >=3.0.0 | **Severity:** HIGH
- **CVE:** CVE-2025-65945 | **Package:** jws | **Installed:** 0.2.6 | **Fixed:** 3.2.3, 4.0.1 | **Severity:** HIGH
- **CVE:** CVE-2019-10744 | **Package:** lodash | **Installed:** 2.4.2 | **Fixed:** 4.17.12 | **Severity:** CRITICAL
- **CVE:** CVE-2018-16487 | **Package:** lodash | **Installed:** 2.4.2 | **Fixed:** >=4.17.11 | **Severity:** HIGH
- **CVE:** CVE-2021-23337 | **Package:** lodash | **Installed:** 2.4.2 | **Fixed:** 4.17.21 | **Severity:** HIGH
- **CVE:** CVE-2020-8203 | **Package:** lodash.set | **Installed:** 4.3.2 | **Fixed:** None | **Severity:** HIGH
- **CVE:** GHSA-5mrr-rgp6-x4gr | **Package:** marsdb | **Installed:** 0.6.11 | **Fixed:** None | **Severity:** CRITICAL
- **CVE:** CVE-2017-18214 | **Package:** moment | **Installed:** 2.0.0 | **Fixed:** 2.19.3 | **Severity:** HIGH
- **CVE:** CVE-2022-24785 | **Package:** moment | **Installed:** 2.0.0 | **Fixed:** 2.29.2 | **Severity:** HIGH
- **CVE:** CVE-2025-47935 | **Package:** multer | **Installed:** 1.4.5-lts.2 | **Fixed:** 2.0.0 | **Severity:** HIGH
- **CVE:** CVE-2025-47944 | **Package:** multer | **Installed:** 1.4.5-lts.2 | **Fixed:** 2.0.0 | **Severity:** HIGH
- **CVE:** CVE-2025-48997 | **Package:** multer | **Installed:** 1.4.5-lts.2 | **Fixed:** 2.0.1 | **Severity:** HIGH
- **CVE:** CVE-2025-7338 | **Package:** multer | **Installed:** 1.4.5-lts.2 | **Fixed:** 2.0.2 | **Severity:** HIGH
- **CVE:** CVE-2022-25887 | **Package:** sanitize-html | **Installed:** 1.4.2 | **Fixed:** 2.7.1 | **Severity:** HIGH
- **CVE:** CVE-2023-32314 | **Package:** vm2 | **Installed:** 3.9.17 | **Fixed:** 3.9.18 | **Severity:** CRITICAL
- **CVE:** CVE-2023-37466 | **Package:** vm2 | **Installed:** 3.9.17 | **Fixed:** None | **Severity:** CRITICAL
- **CVE:** CVE-2023-37903 | **Package:** vm2 | **Installed:** 3.9.17 | **Fixed:** None | **Severity:** CRITICAL
- **CVE:** CVE-2024-37890 | **Package:** ws | **Installed:** 7.4.6 | **Fixed:** 5.2.4, 6.2.3, 7.5.10, 8.17.1 | **Severity:** HIGH

### Trivy File System Findings

- No HIGH or CRITICAL vulnerabilities found in filesystem.

---

## 2. Estimated Risk

- **Overall Risk Level:** HIGH

## 3. Recommendations Per Tool

### Bandit
- Remove hardcoded credentials and secrets.
- Replace assert statements with proper error handling.
- Avoid using shell=True in subprocess.

### Trivy
- Upgrade all vulnerable dependencies.
- Use minimal and updated base images.
- Remove unused packages and libraries.

## 4. Conclusion

The security analysis shows critical weaknesses in both the source code and container dependencies. Immediate remediation is required before moving to production.
