# New Check Request
---
## Provider
> Cloud or platform this check targets:
```
e.g. aws, azure, gcp, kubernetes, github, m365
```
---
## Service
> Optional. Main service, product, or feature to audit.
```
e.g. s3, bedrock, entra, repository, apiserver
```
---
## Suggested check name
> Optional. Use `snake_case` following `<service>_<resource>_<best_practice>`, with lowercase letters and underscores only.
```
e.g. bedrock_guardrail_sensitive_information_filter_enabled
```
---
## Context and goal
> Describe the security problem, why it matters, and what this new check should help detect.

**Security condition to validate:**
```
[ Write here: describe the specific misconfiguration, risk, or behavior to detect ]
```
**Why it matters:**
```
[ Write here: explain the security impact or risk if this condition is not met ]
```
**Resource, feature, or configuration involved:**
```
[ Write here: name the resource type, setting, or feature this check targets ]
```
---
## Expected behavior
> Explain what the check should evaluate and what PASS, FAIL, or MANUAL should mean.

**Resource or scope to evaluate:**
```
[ Write here: specify what resource, object, or scope the check will inspect ]
```
**PASS when:**
```
[ Write here: describe the condition that indicates a compliant, secure state ]
```
**FAIL when:**
```
[ Write here: describe the condition that indicates a non-compliant or insecure state ]
```
**MANUAL when** *(if applicable)*:
```
[ Write here: describe any condition that requires human judgment and cannot be automated ]
```
**Exclusions, thresholds, or edge cases:**
```
[ Write here: list any exceptions, special values, or edge cases the check should account for ]
```
---
## References
> Add vendor docs, API references, SDK methods, CLI commands, endpoint docs, sample payloads, or similar reference material.

**Product or service documentation:**
```
[ Write here: paste URL(s) or title(s) of official product or service documentation ]
```
**API or SDK reference:**
```
[ Write here: paste URL(s) or method names from the relevant API or SDK reference ]
```
**CLI command or endpoint documentation:**
```
[ Write here: provide CLI commands or endpoint paths used to retrieve or evaluate this resource ]
```
**Sample payload or response:**
```
[ Write here: paste a sample API response, JSON payload, or CLI output showing relevant fields ]
```
**Security advisory or benchmark:**
```
[ Write here: link to CIS benchmark, CVE, vendor advisory, or compliance control if applicable ]
```
---
## Suggested severity
> Your best estimate. Reviewers will confirm during triage.
- [ ] Critical
- [ ] High
- [ ] Medium
- [ ] Low
- [ ] Informational
- [ ] Not sure
---
## Additional implementation notes
> Optional. Add permissions, unsupported regions, config knobs, product limitations, or anything else that may affect implementation.

**Required permissions or scopes:**
```
[ Write here: list IAM permissions, OAuth scopes, or roles needed to run this check ]
```
**Region, tenant, or subscription limitations:**
```
[ Write here: note any regions, tenants, or subscriptions where this check does not apply ]
```
**Configurable behavior or thresholds:**
```
[ Write here: describe any values or thresholds that should be user-configurable ]
```
**Other constraints:**
```
[ Write here: add any other known limitations, quirks, or implementation considerations ]
```
