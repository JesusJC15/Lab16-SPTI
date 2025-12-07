import json
import sys
import pathlib

def filter_bandit(path):
    j = json.load(open(path))
    high = [
        r for r in j.get("results", [])
        if r.get("issue_severity", "").upper() in ("HIGH", "CRITICAL")
    ]
    return high

def filter_trivy(path):
    j = json.load(open(path))
    res = []
    for r in j.get("Results", []):
        vulns = r.get("Vulnerabilities") or []
        high = [v for v in vulns if v.get("Severity") in ("HIGH", "CRITICAL")]
        if high:
            res.append({
                "Target": r.get("Target"),
                "HighVulnerabilities": high
            })
    return res

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python3 filter.py <path_to_json>")
        sys.exit(1)

    path = pathlib.Path(sys.argv[1])

    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    if "bandit" in path.name.lower() or "results" in path.name.lower():
        print("Bandit HIGH findings:\n")
        json.dump(filter_bandit(str(path)), sys.stdout, indent=2)
        print()

    elif "fs" in path.name.lower() or "image" in path.name.lower():
        print("Trivy HIGH findings:\n")
        json.dump(filter_trivy(str(path)), sys.stdout, indent=2)
        print()

    else:
        print("Unknown JSON format (not Bandit or Trivy)")
