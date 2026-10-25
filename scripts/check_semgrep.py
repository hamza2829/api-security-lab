"""Allow the known teaching findings, require clean fixed application code."""

import json
import sys
from pathlib import Path, PurePosixPath


report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "lab-formatted-search-sql", "lab-weak-jwt-secret",
    "lab-disabled-jwt-expiry", "lab-committed-fake-key",
}
seen = set()
fixed_findings = []
for run in report["runs"]:
    for result in run.get("results", []):
        for location in result.get("locations", []):
            uri = location["physicalLocation"]["artifactLocation"]["uri"]
            parts = PurePosixPath(uri.replace("\\", "/")).parts
            if "app_fixed" in parts:
                fixed_findings.append(result["ruleId"])
            if "app_vulnerable" in parts:
                seen.add(result["ruleId"].split(".")[-1])
if fixed_findings:
    raise SystemExit(f"FAIL: Semgrep findings in fixed app: {fixed_findings}")
if not expected.issubset(seen):
    raise SystemExit(f"FAIL: Missing expected teaching findings: {expected - seen}")
print(f"PASS: {len(seen)} expected vulnerable rule matches; no fixed-app findings")
