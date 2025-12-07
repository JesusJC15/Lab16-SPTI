import json
from datetime import datetime
from pathlib import Path

# === CONFIG ===
BANDIT_PATH = Path("output/bandit/results.json")
TRIVY_IMAGE_PATH = Path("output/trivy/image.json")
TRIVY_FS_PATH = Path("output/trivy/fs.json")

REPORT_FILE = "report_scan.md"
GROUP_NAME = "Natalia Espitia - Jesus Jauregui"
PROJECT_NAME = "Security Analisis"

# === HELPERS ===

def load_json(path):
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return None

def extract_bandit_high(data):
    if not data:
        return []

    return [
        {
            "file": r.get("filename"),
            "severity": r.get("issue_severity"),
            "confidence": r.get("issue_confidence"),
            "issue": r.get("issue_text"),
            "cwe": r.get("issue_cwe", {}).get("id"),
            "line": r.get("line_number"),
        }
        for r in data.get("results", [])
        if r.get("issue_severity", "").upper() in ("HIGH", "CRITICAL")
    ]

def extract_trivy_high(data):
    if not data:
        return []

    findings = []
    for r in data.get("Results", []):
        vulns = r.get("Vulnerabilities") or []
        for v in vulns:
            if v.get("Severity") in ("HIGH", "CRITICAL"):
                findings.append({
                    "target": r.get("Target"),
                    "package": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "severity": v.get("Severity"),
                    "cve": v.get("VulnerabilityID"),
                    "title": v.get("Title"),
                })
    return findings

def calculate_risk(bandit, trivy):
    total = len(bandit) + len(trivy)

    if total >= 6:
        return "HIGH"
    elif total >= 3:
        return "MEDIUM"
    else:
        return "LOW"

# === MAIN GENERATOR ===

def generate_report():

    bandit_data = load_json(BANDIT_PATH)
    trivy_image_data = load_json(TRIVY_IMAGE_PATH)
    trivy_fs_data = load_json(TRIVY_FS_PATH)

    bandit_findings = extract_bandit_high(bandit_data)
    trivy_image_findings = extract_trivy_high(trivy_image_data)
    trivy_fs_findings = extract_trivy_high(trivy_fs_data)

    risk = calculate_risk(bandit_findings, trivy_image_findings)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(REPORT_FILE, "w") as report:
        report.write(f"# Security Report\n\n")
        report.write(f"## Project\n{PROJECT_NAME}\n\n")
        report.write(f"## Group Name\n{GROUP_NAME}\n\n")
        report.write(f"## Date\n{now}\n\n")
        report.write("---\n\n")

        # === VULNERABILITIES ===
        report.write("## 1. Vulnerabilities Found\n\n")

        report.write("### Bandit Findings\n\n")
        if bandit_findings:
            for b in bandit_findings:
                report.write(
                    f"- **File:** {b['file']} | "
                    f"**Severity:** {b['severity']} | "
                    f"**Issue:** {b['issue']} | "
                    f"**CWE:** {b['cwe']} | "
                    f"**Line:** {b['line']}\n"
                )
        else:
            report.write("- No HIGH or CRITICAL issues found by Bandit.\n")

        report.write("\n### Trivy Image Findings\n\n")
        if trivy_image_findings:
            for t in trivy_image_findings:
                report.write(
                    f"- **CVE:** {t['cve']} | "
                    f"**Package:** {t['package']} | "
                    f"**Installed:** {t['installed']} | "
                    f"**Fixed:** {t['fixed']} | "
                    f"**Severity:** {t['severity']}\n"
                )
        else:
            report.write("- No HIGH or CRITICAL vulnerabilities found in image scan.\n")

        report.write("\n### Trivy File System Findings\n\n")
        if trivy_fs_findings:
            for t in trivy_fs_findings:
                report.write(
                    f"- **CVE:** {t['cve']} | "
                    f"**Package:** {t['package']} | "
                    f"**Installed:** {t['installed']} | "
                    f"**Fixed:** {t['fixed']} | "
                    f"**Severity:** {t['severity']}\n"
                )
        else:
            report.write("- No HIGH or CRITICAL vulnerabilities found in filesystem.\n")

        # === RISK ===
        report.write("\n---\n\n")
        report.write("## 2. Estimated Risk\n\n")
        report.write(f"- **Overall Risk Level:** {risk}\n\n")

        # === RECOMMENDATIONS ===
        report.write("## 3. Recommendations Per Tool\n\n")

        report.write("### Bandit\n")
        report.write("- Remove hardcoded credentials and secrets.\n")
        report.write("- Replace assert statements with proper error handling.\n")
        report.write("- Avoid using shell=True in subprocess.\n\n")

        report.write("### Trivy\n")
        report.write("- Upgrade all vulnerable dependencies.\n")
        report.write("- Use minimal and updated base images.\n")
        report.write("- Remove unused packages and libraries.\n\n")

        # === CONCLUSION ===
        report.write("## 4. Conclusion\n\n")
        report.write(
            "The security analysis shows critical weaknesses in both the source "
            "code and container dependencies. Immediate remediation is required "
            "before moving to production.\n"
        )

    print(f"[✓] report_scan.md generated successfully.")


if __name__ == "__main__":
    generate_report()
