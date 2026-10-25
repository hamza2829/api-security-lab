"""Require the intended fake-key finding so a silent scan cannot pass."""

import json
import os
import sys
from pathlib import Path


findings = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = [item for item in findings if item["RuleID"] == "lab-fake-api-key"]
if not expected:
    raise SystemExit("FAIL: Gitleaks did not detect the planted fake key")

message = (
    f"Expected vulnerable-folder findings: {len(findings)}. "
    "The fake API key was detected. Fixed-folder scanning remains a required gate."
)
print(message)
print("::notice title=Expected lab secret detected::" + message)
if os.environ.get("GITHUB_STEP_SUMMARY"):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write("### Gitleaks\n\n" + message + "\n")
