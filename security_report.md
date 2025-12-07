# Security Report

## Project
Security Analisis

## Group Name
Natalia Espitia - Jesus Jauregui

## Date
Sat Dec  6 11:13:45 PM EST 2025

---

## 1. Vulnerabilities Found

### Bandit
Results stored in:
- `output/bandit/results.json`

### Trivy Image Scan
Results stored in:
- `output/trivy/image.json`

### Trivy File System Scan
Results stored in:
- `output/trivy/fs.json`

---

## 2. Estimated Risk

- **High Risk:** Multiple CRITICAL and HIGH vulnerabilities found in dependencies.
- **Medium Risk:** Insecure coding practices detected.
- **Low Risk:** Minor security warnings.

---

## 3. Recommendations Per Tool

### Bandit
- Remove hardcoded secrets.
- Avoid the use of `assert` for security validations.
- Avoid using `shell=True` in subprocess.

### Trivy
- Upgrade all vulnerable dependencies.
- Rebuild images using minimal and updated base images.
- Remove unused and vulnerable packages.

---

## 4. Conclusion

The project presents several critical security issues both at the source code level and at the container dependency level. Immediate remediation is strongly recommended before deployment.

