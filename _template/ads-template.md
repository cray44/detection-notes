# [Detection Name]

## Goal

One or two sentences: what threat behavior does this detect and why does catching it matter?

## ATT&CK Categorization

- **Tactic:** TA00XX — Name
- **Technique:** T1XXX — Name
- **Sub-technique:** T1XXX.00X — Name (if applicable)

## Strategy Abstract

Describe how the detection works conceptually — what behavioral signal you're looking for and the logic behind it. Should be readable without a SIEM query in front of you.

## Technical Context

**Data source:** (e.g., Zeek dns.log, Windows Security Event Log, AWS CloudTrail)

**Key fields:**
- `field_name` — what it represents and why it matters to this detection

**Environment assumptions:** What needs to be true about the environment for this detection to work (log collection in place, baseline established, specific sensor deployment, etc.)

## Blind Spots

What this detection will not catch. Be specific — adversaries who know this detection exists should find this section unsurprising, so be honest about the gaps.

- ...
- ...

## False Positives

Known benign conditions that will trigger this detection. For each, note how to triage it.

| False Positive | Triage Guidance |
|---|---|
| Example | How to distinguish from true positive |

## Validation

How to confirm this detection fires correctly in a test environment.

```bash
# Example: command or tool invocation that produces the malicious signal
```

Expected result: what you should see in the SIEM/log source when the test runs.

## Response

What an analyst should do when this alert fires:

1. ...
2. ...

## References

- [Source or prior art](url)
