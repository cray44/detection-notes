"""
QA check for ADS-format detection writeups.
Runs automatically via pre-commit hook. Can also be run manually:
  python scripts/qa_check.py detections/network/dns/dns-tunneling-high-entropy-subdomains.md
  python scripts/qa_check.py detections/  (check all)
"""

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SIGMA_TO_SPL_RULES = Path(__file__).parent.parent.parent / "sigma-to-spl" / "rules"

REQUIRED_SECTIONS = [
    "## Goal",
    "## ATT&CK Categorization",
    "## Strategy Abstract",
    "## Technical Context",
    "## Performance Notes",
    "## Blind Spots",
    "## False Positives",
    "## Validation",
    "## Response",
    "## References",
]

PLACEHOLDER_PATTERNS = [
    (r"T1XXX", "ATT&CK technique ID not filled in"),
    (r"TA00XX", "ATT&CK tactic ID not filled in"),
    (r"^\s*- \.\.\.\s*$", "Placeholder '...' content left in section", re.MULTILINE),
    (r"Example \| How to distinguish", "FP table not filled in"),
    (r"\[Detection Name\]", "Detection name not filled in"),
    (r"rule-name\.yml", "Sigma rule path not filled in"),
    (r"category/rule-name", "Sigma rule path not filled in"),
]


@dataclass
class CheckResult:
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.failed) == 0


def check_file(path: Path) -> CheckResult:
    result = CheckResult()
    text = path.read_text(encoding="utf-8")

    # Required sections present
    for section in REQUIRED_SECTIONS:
        if section in text:
            result.passed.append(f"Section present: {section}")
        else:
            result.failed.append(f"Missing section: {section}")

    # No unchecked checklist items
    unchecked = re.findall(r"\[ \]", text)
    if unchecked:
        result.failed.append(f"Quality bar checklist has {len(unchecked)} unchecked item(s) — mark all [x] before committing")
    else:
        result.passed.append("Quality bar checklist complete")

    # No placeholder text
    for pattern, message, *flags in PLACEHOLDER_PATTERNS:
        flag = flags[0] if flags else 0
        if re.search(pattern, text, flag):
            result.failed.append(f"Placeholder text found: {message}")

    # SPL code block present in Validation section
    if "```spl" in text.lower():
        result.passed.append("SPL code block present")
    else:
        result.failed.append("No SPL code block found — add primary SPL query in Validation section")

    # Performance Notes has actual content (not just header)
    perf_match = re.search(r"## Performance Notes\s*\n+(.*?)(?=\n##|\Z)", text, re.DOTALL)
    if perf_match:
        perf_content = perf_match.group(1).strip()
        if len(perf_content) > 50:
            result.passed.append("Performance Notes has content")
        else:
            result.failed.append("Performance Notes section appears empty or minimal — add event volume, indexed fields, time range")
    else:
        result.failed.append("Performance Notes section missing content")

    # Sigma rule reference exists and points to a real file
    sigma_refs = re.findall(r"sigma-to-spl/blob/main/rules/([^\)\"'\s]+\.yml)", text)
    if not sigma_refs:
        result.failed.append("No Sigma rule reference found — add path to sigma-to-spl/rules/ in Technical Context")
    else:
        for ref in sigma_refs:
            rule_path = SIGMA_TO_SPL_RULES / ref
            if rule_path.exists():
                result.passed.append(f"Sigma rule exists: {ref}")
            else:
                result.failed.append(f"Sigma rule not found at sigma-to-spl/rules/{ref}")

    # test-data/ directory exists alongside the writeup
    test_data_dir = path.parent / "test-data"
    if test_data_dir.exists() and any(test_data_dir.iterdir()):
        result.passed.append("test-data/ directory exists with content")
    elif test_data_dir.exists():
        result.failed.append("test-data/ directory exists but is empty — add malicious and benign sample log files")
    else:
        result.failed.append("test-data/ directory missing — create with malicious and benign sample log files")

    # Blind Spots section has real content
    blind_match = re.search(r"## Blind Spots\s*\n+(.*?)(?=\n##|\Z)", text, re.DOTALL)
    if blind_match:
        blind_content = blind_match.group(1).strip()
        bullets = [l for l in blind_content.splitlines() if l.strip().startswith("-")]
        if len(bullets) >= 2:
            result.passed.append(f"Blind Spots has {len(bullets)} entries")
        else:
            result.failed.append("Blind Spots has fewer than 2 entries — be specific about what this detection misses")

    return result


def check_path(path: Path) -> dict[Path, CheckResult]:
    results = {}
    if path.is_file() and path.suffix == ".md" and path.name != "README.md":
        results[path] = check_file(path)
    elif path.is_dir():
        for p in sorted(path.rglob("*.md")):
            if p.name != "README.md" and "_template" not in str(p):
                results[p] = check_file(p)
    return results


def main():
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["detections/"]
    all_results: dict[Path, CheckResult] = {}

    for target in targets:
        all_results.update(check_path(Path(target)))

    if not all_results:
        print("No detection writeup files found.")
        sys.exit(0)

    any_failed = False
    for path, result in all_results.items():
        rel = path.relative_to(Path.cwd()) if path.is_absolute() else path
        if result.ok:
            print(f"  PASS  {rel}")
        else:
            any_failed = True
            print(f"  FAIL  {rel}")
            for msg in result.failed:
                print(f"          - {msg}")

    print()
    total = len(all_results)
    passed = sum(1 for r in all_results.values() if r.ok)
    print(f"{passed}/{total} writeups passed QA")

    if any_failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
