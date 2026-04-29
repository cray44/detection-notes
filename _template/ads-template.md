# [Detection Name]

<!--
Quality bar checklist — complete before committing:
  [ ] SPL query is primary — includes performance notes
  [ ] Sigma rule exists in sigma-to-spl/rules/ (not embedded here — reference path only)
  [ ] Sigma rule expresses full logic, OR has caveat explaining what SPL adds
  [ ] test-data/ directory alongside this file with malicious + benign sample logs
  [ ] Threat-informed framing — tied to published actor/campaign reporting where possible
  [ ] Blind spots are honest and specific
  [ ] FP table has real triage guidance
-->

## Goal

One or two sentences: what threat behavior does this detect, why does catching it matter, and what specific actor or campaign tradecraft does this map to (if applicable)?

## ATT&CK Categorization

- **Tactic:** TA00XX — Name
- **Technique:** T1XXX — Name
- **Sub-technique:** T1XXX.00X — Name (if applicable)

## Threat Context

*(Optional but preferred)* Link this detection to published threat reporting. Example: "Used by APT29 in post-compromise C2 operations per Mandiant M-Trends 2025." If no specific actor attribution, describe the threat scenario this targets.

## Strategy Abstract

Describe how the detection works conceptually — the behavioral signal and the logic behind it. Readable without a SIEM query in front of you.

## Technical Context

**Data source:** (e.g., Zeek dns.log via Corelight App for Splunk — sourcetype `corelight_dns`)

**Sigma rule:** [`rules/category/rule-name.yml`](https://github.com/cray44/sigma-to-spl/blob/main/rules/category/rule-name.yml) in sigma-to-spl

**Key fields:**
- `field_name` — what it represents and why it matters to this detection

**Environment assumptions:** What must be true for this detection to work.

## Performance Notes

- **Estimated event volume:** (e.g., ~50K events/day in a 1000-endpoint environment)
- **Indexed fields used:** List which SPL filter fields are indexed vs. extracted — affects search performance significantly
- **Recommended time range:** Typical scheduling window
- **Acceleration:** Whether an accelerated data model or summary index is advisable

## Blind Spots

Be specific and honest. Adversaries reading this section should find it unsurprising.

- ...

## False Positives

| False Positive | Triage Guidance |
|---|---|
| Example | How to distinguish from true positive |

## Validation

**Test data:** See [`test-data/`](test-data/) alongside this file — includes malicious and benign sample log events.

How to reproduce the malicious signal in a lab:

```bash
# Command or tool invocation that produces the signal
```

Expected result: what you should see in Splunk when the test runs.

**SPL (primary):**
```spl
index=... sourcetype=...
| ...
```

> *Performance note: explain any eval/stats ordering decisions, why filters appear where they do, etc.*

## Response

1. ...
2. ...

## References

- [Source or prior art](url)
- [Sigma rule](https://github.com/cray44/sigma-to-spl/blob/main/rules/...)
