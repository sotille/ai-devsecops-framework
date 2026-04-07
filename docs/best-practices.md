# Operational Best Practices for AI Pipeline Components

## Table of Contents

- [AI Component Lifecycle](#ai-component-lifecycle)
- [Secrets and Credentials](#secrets-and-credentials)
- [Prompt Engineering and System Prompt Management](#prompt-engineering-and-system-prompt-management)
- [Defense Against Injection](#defense-against-injection)
- [Audit and Observability](#audit-and-observability)
- [Model Governance](#model-governance)
- [Incident Response](#incident-response)

---

## AI Component Lifecycle

**Treat AI pipeline components as external dependencies with SLA, availability, and versioning requirements.**

When the model provider experiences an outage, your pipeline must not fail in an unsafe way. Define what "unavailable" means for each AI component (rate limiting, timeout, API error) and implement the circuit breaker pattern (see [pipeline-controls.md](pipeline-controls.md)) so the pipeline continues with deterministic controls when the AI component is unavailable.

Document the SLA expectations for each AI provider API used in the pipeline. For critical pipeline stages, evaluate whether a self-hosted model or a secondary provider fallback is warranted.

**Pin model versions in all pipeline configurations and treat version upgrades as change events.**

A model update by the provider can change response patterns, format, capability, and occasionally safety characteristics. Pin the model version explicitly in every pipeline configuration:

```yaml
# In pipeline configuration — always specify the full model version
model: "claude-3-5-sonnet-20241022"       # Good: specific version
# model: "claude-3-5-sonnet-latest"       # Bad: version can change without notice
```

When upgrading a pinned model version:
- Review the model provider's changelog for the new version
- Run the component's test suite (including adversarial tests) against the new version
- Deploy to a staging pipeline before production
- Monitor behavioral metrics for 1 week after production deployment

**Establish a model deprecation policy.**

Define a process for replacing models when:
- The provider announces end-of-life for the model version
- A security vulnerability is discovered in the model
- The model's security-relevant behavior degrades (detected via evaluation metrics)
- A newer version provides significantly better injection resistance or output quality

The deprecation process should include: notification to affected teams, evaluation of the replacement model, a staged rollout, and verification that the replacement meets the behavioral baseline established for the component.

---

## Secrets and Credentials

**Never log raw LLM inputs or outputs to shared log aggregators.**

LLM context windows frequently contain sensitive information: code with hardcoded secrets (which secrets detection may have missed), environment variable values, file contents, and sometimes credentials passed as function parameters or test fixtures. If this context is logged verbatim to a shared log aggregator (Splunk, CloudWatch, Datadog), it is accessible to anyone with log access — a significantly larger audience than the intended recipients of that data.

Options, in order of preference:
1. Log only hashes of inputs and outputs (see [agent-audit-trail.md](agent-audit-trail.md))
2. Apply secret redaction before logging: run the content through Gitleaks or a similar tool and replace detected secrets before writing to the log
3. Log to a restricted-access log stream separate from the general log aggregator

**Apply the same key management controls to AI provider API keys as to cloud credentials.**

AI provider API keys grant access to potentially expensive compute, to the capability to generate content on your organization's behalf, and in some cases to fine-tuning operations on your model. A compromised API key can:
- Run up API charges in the thousands or tens of thousands of dollars
- Be used to generate content that appears to come from your organization
- Be used to extract data from any agent that uses the key

Controls:
- Store in Vault, AWS Secrets Manager, or equivalent — not in environment variables or `.env` files
- Rotate quarterly and on team member departures
- Set spend limits at the provider level (most providers support this)
- Enable usage monitoring and alert on anomalous consumption (sudden spike in tokens used is an indicator of credential compromise or an injection-triggered prompt flooding attack)
- Include in the secrets rotation automation — manual rotation is often missed

See [devsecops-framework/docs/secret-lifecycle-management.md](../devsecops-framework/docs/secret-lifecycle-management.md) for the full secret lifecycle framework.

---

## Prompt Engineering and System Prompt Management

**Version your system prompts like code: in git, with review.**

System prompts define an AI component's behavior, constraints, and identity. They are as important as the code that invokes the LLM. Changes to system prompts can introduce security regressions: removing injection resistance instructions, adding information that could be leaked, or changing behavior in ways that affect security gates.

Requirements:
- System prompts are stored in a version-controlled repository
- Changes require review from both the owning team and the security team
- The adversarial test suite runs against the new prompt before deployment
- The system prompt SHA is recorded in every audit log entry (see [agent-audit-trail.md](agent-audit-trail.md))
- Changes are logged in a CHANGELOG with a description of what changed and why

**Never include secrets, internal URLs, or sensitive information in system prompts.**

System prompts are subject to extraction via jailbreak and direct prompt attacks. A system prompt that contains an API key, an internal service URL, or instructions that reveal sensitive organizational information is a liability.

If the agent needs a credential to function, pass it via the tool execution layer (injected at runtime from secrets management), not via the system prompt. If the agent needs to know an internal service URL, configure it as an environment variable that the tool execution layer uses — not as a literal value in the natural language prompt.

**Give AI components only the context they need — the minimum context principle.**

Every piece of information included in an agent's context window is information that could be leaked via prompt injection, jailbreak, or context window exfiltration. Apply the minimum context principle:

- A PR reviewer needs the PR diff and the relevant sections of the security policy — not the entire repository history
- A triage agent processing a specific CVE needs that CVE's details and the affected dependency information — not the organization's full dependency graph
- A deployment agent executing a specific deployment needs the deployment configuration for that deployment — not credentials for all environments

Reducing context reduces the blast radius of any context exfiltration attack and often also reduces token cost and latency.

---

## Defense Against Injection

**Assume indirect prompt injection is attempted constantly — design for resilience, not prevention.**

Indirect prompt injection via user-controlled data sources (PR descriptions, commit messages, CVE text) is not fully preventable. An organization that processes public repositories or CVE feeds will encounter injection attempts in the normal course of operation. Design AI pipeline components to be resilient to injection: tool authorization limits what a successfully injected agent can do, approval gates prevent irreversible actions, and output validation detects anomalous behavior.

The design goal is not "no injection attempts succeed" — it is "a successful injection cannot cause material harm."

**Separate the AI reasoning trace from the action execution — log both independently.**

The AI component's reasoning about what to do and the actual execution of that action via tool calls are distinct events. Log them separately:

1. Log the reasoning trace (the agent's stated reasoning for the action, with context hashes) before tool execution
2. Log the tool invocation independently (with input/output hashes) at execution time
3. If the reasoning trace does not match the tool invocation (e.g., the agent stated "I will post a review comment" but the tool call is `pr.merge`), this is a red flag requiring investigation

This separation makes injection attacks detectable: an injected agent will often produce a reasoning trace that is inconsistent with its normal behavior or that references the injected instruction.

**Test AI pipeline components adversarially on a defined schedule.**

Passive monitoring detects attacks after they occur. Adversarial testing proactively identifies vulnerabilities before attackers do. Run adversarial tests:
- At every deployment of a new system prompt or model version
- Quarterly as part of the security testing program
- After any security incident involving an AI pipeline component

See [prompt-injection-defense.md](prompt-injection-defense.md) for the adversarial test framework.

---

## Audit and Observability

**Every agent action must be traceable to a human principal.**

For any action taken by an agent — posting a comment, creating a PR, triggering a deployment — it must be possible to answer: which human initiated the session that resulted in this action? This chain of attribution is required for security incident investigation, compliance, and accountability.

Implement this via the `human_principal` field in the session initialization record and carry it through all audit records in the session.

If an agent can take actions without any human initiating the session (e.g., a monitoring agent that fires on an alert), the initiating event must be recorded (e.g., the specific alert ID, the timestamp of the triggering condition). "The agent decided to act autonomously" is not an acceptable audit record.

**Implement sequence numbers in audit logs to detect deleted entries.**

Standard log timestamps are insufficient for log integrity because time gaps can have innocent explanations. Sequence numbers (monotonically increasing integers per session, or globally per agent log stream) make deletions detectable: a gap in sequence numbers indicates that one or more log entries were removed.

```python
# Maintain a monotonic sequence counter per session
# Persist across log writes to enable integrity verification

class AuditSequencer:
    def __init__(self, session_id: str, redis_client):
        self.session_id = session_id
        self.redis = redis_client
        self.key = f"audit:seq:{session_id}"

    def next_sequence(self) -> int:
        """Atomically increment and return the next sequence number."""
        return self.redis.incr(self.key)

    def verify_sequence(self, records: list[dict]) -> list[int]:
        """Return any missing sequence numbers in a list of audit records."""
        actual = sorted([r["sequence_number"] for r in records])
        if not actual:
            return []
        expected = list(range(actual[0], actual[-1] + 1))
        return list(set(expected) - set(actual))
```

---

## Model Governance

**Treat shadow model usage as a policy violation, not a workflow preference.**

When developers use personal API keys to access AI services outside the approved tool list, they:
- Send proprietary code to providers whose data handling agreements have not been reviewed
- Circumvent security controls designed to prevent prompt injection and data exfiltration
- Create credentials that are not managed by the organization's secrets program

Address shadow model usage through policy, training, and technical controls:
- Policy: clearly define approved models and communicate the prohibition on unapproved usage
- Training: explain the security rationale, not just the policy
- Technical: network egress filtering on CI/CD runners; alert on API keys for unapproved providers in secrets scanning

**Treat the fine-tuning pipeline with the same rigor as the production deployment pipeline.**

A compromised fine-tuning pipeline that introduces a backdoor into a model is equivalent to a compromised CI/CD pipeline that introduces a backdoor into application code. Apply:
- Source code review for fine-tuning scripts
- Data provenance tracking for training data
- Immutable checkpoint storage with hash verification
- Evaluation gates before deployment
- Audit trail for all fine-tuning runs

---

## Incident Response

**Define AI-specific incident indicators and response procedures before you need them.**

Standard incident response procedures do not address AI-specific scenarios. Define procedures for:

| Incident Indicator | Initial Response | Investigation Steps |
|---|---|---|
| Prompt canary detected in output | Terminate session; page security team | Review session audit log; identify injection vector; assess what data was potentially exposed |
| Anomalous agent approval rate | Alert to team lead; suspend AI-assisted approvals | Review approved PRs; check PR content for injection payloads; audit AI component behavior |
| Agent attempts unauthorized tool invocation | Alert to security team; suspend agent session | Review session audit log; trace to initiating input; determine whether injection or misconfiguration |
| Model provider API key compromised | Revoke key immediately; rotate; suspend dependent components | Review API usage logs for the key; assess what requests were made; determine whether unauthorized fine-tuning or data access occurred |
| Unexpected model behavior after version change | Revert to previous pinned version; suspend new version | Compare behavioral metrics; run adversarial test suite against new version; report to model provider if a security regression is suspected |

**Practice session replay before an incident requires it.**

Session replay (reconstructing an agent session from audit logs and content archive) is a skill that degrades without practice. Include session replay exercises in the quarterly red team exercises: given a session ID from 30 days ago, reconstruct the session from logs and verify that the reconstruction matches the known-good behavior from that session.

If session replay fails (missing logs, content archive not queryable, prompt SHA no longer resolvable), the logging or archiving configuration has a gap that must be fixed before a real incident requires it.
