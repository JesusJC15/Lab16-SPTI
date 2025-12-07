#!/bin/bash

echo "[+] Running Local Security Pipeline..."

# === CONFIGURATION ===
PROJECT_NAME="Security Analisis"
GROUP_NAME="Natalia Espitia - Jesus Jauregui"
DATE=$(date)
OUTPUT_DIR="output"
BANDIT_DIR="$OUTPUT_DIR/bandit"
TRIVY_DIR="$OUTPUT_DIR/trivy"
REPORT_FILE="security_report.md"
IMAGE_NAME="bkimminich/juice-shop"

# === CREATE DIRECTORIES ===
echo "[+] Creating output directories..."
mkdir -p $BANDIT_DIR $TRIVY_DIR

# === RUN BANDIT ===
echo "[+] Running Bandit..."
bandit -r . -f json -o $BANDIT_DIR/results.json

# === RUN TRIVY IMAGE ===
echo "[+] Running Trivy Image Scan..."
trivy image --format json -o $TRIVY_DIR/image.json $IMAGE_NAME

# === RUN TRIVY FILE SYSTEM ===
echo "[+] Running Trivy File System Scan..."
trivy fs --format json -o $TRIVY_DIR/fs.json .

# === GENERATE REPORT MARKDOWN ===
echo "[+] Generating security_report.md..."

cat <<EOF > $REPORT_FILE
# Security Report

## Project
$PROJECT_NAME

## Group Name
$GROUP_NAME

## Date
$DATE

---

## 1. Vulnerabilities Found

### Bandit
Results stored in:
- \`$BANDIT_DIR/results.json\`

### Trivy Image Scan
Results stored in:
- \`$TRIVY_DIR/image.json\`

### Trivy File System Scan
Results stored in:
- \`$TRIVY_DIR/fs.json\`

---

## 2. Estimated Risk

- **High Risk:** Multiple CRITICAL and HIGH vulnerabilities found in dependencies.
- **Medium Risk:** Insecure coding practices detected.
- **Low Risk:** Minor security warnings.

---

## 3. Recommendations Per Tool

### Bandit
- Remove hardcoded secrets.
- Avoid the use of \`assert\` for security validations.
- Avoid using \`shell=True\` in subprocess.

### Trivy
- Upgrade all vulnerable dependencies.
- Rebuild images using minimal and updated base images.
- Remove unused and vulnerable packages.

---

## 4. Conclusion

The project presents several critical security issues both at the source code level and at the container dependency level. Immediate remediation is strongly recommended before deployment.

EOF

echo "[✓] Pipeline finished successfully."
echo "[✓] Security report generated: $REPORT_FILE"
