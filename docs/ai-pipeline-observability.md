# AI Pipeline Observability

## Table of Contents

1. [Why AI Pipelines Require Dedicated Observability](#why-ai-pipelines-require-dedicated-observability)
2. [Observability Architecture](#observability-architecture)
3. [Signal Categories](#signal-categories)
4. [Key Metrics by Agent Role](#key-metrics-by-agent-role)
5. [Alert Hierarchy](#alert-hierarchy)
6. [Dashboard Design](#dashboard-design)
7. [Instrumentation Requirements](#instrumentation-requirements)
8. [Correlation and Investigation Workflows](#correlation-and-investigation-workflows)
9. [Operational Runbooks](#operational-runbooks)
10. [Integration with Security Tooling](#integration-with-security-tooling)

---

## Why AI Pipelines Require Dedicated Observability

Traditional CI/CD pipeline observability focuses on deterministic execution: a step either runs or fails, produces expected outputs or errors, and completes within a known time bound. AI pipeline components break each of these assumptions.

**Non-determinism:** The same input to an LLM-based agent may produce different tool call sequences, different output structure, and different session durations across executions. Standard alerting on deviations from expected output is not applicable — what counts as "normal" is statistical, not deterministic.

**Emergent behavior:** A multi-agent pipeline can produce emergent behaviors not present in any individual agent. A code review agent that produces borderline-compliant output, combined with a triage agent that trusts that output, can result in a security finding being dismissed without either agent individually appearing anomalous.

**Invisible reasoning:** The decision process that produces an agent's tool calls is not observable through standard pipeline logs. An agent may call five tools and produce correct output for the wrong reasons, making correctness an insufficient signal for security assurance.

**Dual-use telemetry:** The same audit trail that enables security investigation also enables forensic reconstruction of what an agent did and why. Observability infrastructure designed only for operational monitoring may not preserve the evidence required for a forensic investigation.

These properties require observability systems that are:
- Statistical rather than threshold-exact
- Evidence-preserving by design
- Sensitive to behavioral sequences, not just individual events
- Capable of correlating across agent boundaries in multi-agent pipelines

---

## Observability Architecture

```
AI Pipeline Observability Stack:

Agent Runtime
├── Tool call instrumentation (pre/post hooks)
├── Session lifecycle events (start, suspend, resume, terminate)
├── Authorization decision log (ALLOW / DENY / APPROVAL_REQUIRED)
└── Output schema validation results

↓ Structured JSONL audit stream

Collection Layer
├── Centralized audit log ingest (immutable, append-only)
├── Real-time stream processor (anomaly detection, alert generation)
└── Session correlation engine (links events across multi-agent chains)

↓

Storage and Analysis
├── Hot tier: Last 30 days — full event detail, queryable
├── Warm tier: 30–365 days — aggregated per session, queryable
├── Cold/archive: 365 days+ — immutable archives for compliance/forensics
└── Baseline store: Statistical distributions per agent role × policy version

↓

Observability Surfaces
├── Security operations dashboard (real-time alerts, anomaly feed)
├── Agent health dashboard (throughput, latency, error rates)
├── Forensic investigation workbench (session replay, correlation)
└── Compliance reporting (audit evidence, control effectiveness)
```

The audit log is the primary data source for all observability surfaces. It must be immutable and append-only — agents must not have write access to their own audit records. See [agent-audit-trail.md](agent-audit-trail.md) for the required schema.

---

## Signal Categories

AI pipeline observability signals fall into four categories with different properties and uses.

### Category 1 — Invariant Signals

Signals that should never occur regardless of agent workload or task complexity. A single occurrence is actionable without statistical context.

| Signal | Source | Alert Threshold |
|---|---|---|
| Tool call to a prohibited tool | Authorization log | Single occurrence = CRITICAL |
| Network connection to non-allowlisted destination | Network egress log | Single occurrence = CRITICAL |
| Canary token in agent output | Output monitor | Single occurrence = HIGH |
| Agent modified its own tool policy | Policy change log | Single occurrence = CRITICAL |
| Session started without a valid trigger event | Session log | Single occurrence = HIGH |
| Audit log write failure or gap | Log integrity monitor | Single occurrence = CRITICAL |

These signals are invariant because they are either policy-enforced (the tool execution layer prevents prohibited tool calls regardless of LLM reasoning) or structurally impossible under normal operation (an agent cannot legitimately connect to a non-allowlisted destination).

### Category 2 — Statistical Signals

Signals where normal variation is expected. Alerting requires comparison against the agent's behavioral baseline.

| Signal | Normal Source | Alert Approach |
|---|---|---|
| Total tool calls per session | Task complexity variation | Alert when > baseline P99 × 1.5 |
| Session duration | Task complexity, model temperature | Alert when > baseline P99 |
| Unique file paths accessed | Repository structure variation | Alert when > baseline P95 × 1.3 |
| Authorization denial rate | Policy configuration changes | Alert when > 3× baseline mean |
| Output token count | Response length variation | Alert when > baseline P99 × 2.0 |
| Cross-repository access count | Multi-repo tasks | Alert when > expected scope for task type |

Statistical signals require a calibrated baseline. See [ai-behavioral-baseline.md](../../forensics-and-incident-response-framework/docs/ai-behavioral-baseline.md) for baseline methodology.

### Category 3 — Operational Health Signals

Signals that indicate pipeline health, not security incidents. Required for capacity planning and SLA management.

| Signal | Healthy Range | Degraded | Action Required |
|---|---|---|---|
| Agent task queue depth | < 10 pending | 10–50 pending | Scale review |
| Tool call latency (P95) | < 2s | 2–10s | Infrastructure review |
| LLM API error rate | < 1% | 1–5% | Provider status check |
| Session completion rate | > 98% | 90–98% | Configuration review |
| Circuit breaker trip rate | < 0.1% | > 1% | Security/config review |

### Category 4 — Compliance Evidence Signals

Signals required for regulatory evidence and audit trails. Must be captured regardless of operational or security value.

- Every tool authorization decision (ALLOW / DENY / APPROVAL_REQUIRED) with timestamp, session ID, agent role, tool name, operation, and parameters
- Every approval gate event with approver identity, decision, and timestamp
- Every session start and end with trigger source, task description, and system prompt version hash
- Every policy version change with effective timestamp and changed content hash

---

## Key Metrics by Agent Role

Different agent roles have different legitimate behavioral profiles. Observability thresholds should be calibrated per role.

### Code Review Agent

**Purpose:** Reads PR diffs and posts security findings as comments.

| Metric | Typical Range | Investigation Threshold |
|---|---|---|
| Tool calls per session | 8–35 | > 100 |
| Session duration | 2–8 minutes | > 25 minutes |
| Files read per session | 3–20 | > 60 |
| Comment operations per session | 1–5 | > 15 |
| Cross-repository reads | 0 | > 0 (invariant) |
| Merge/approve operations | 0 | > 0 (invariant — prohibited) |

**Key alert:** Any merge, approve, or branch-write operation is prohibited. A single occurrence requires immediate circuit breaker and session suspension.

### Vulnerability Triage Agent

**Purpose:** Receives scanner findings and classifies severity; opens or closes issues.

| Metric | Typical Range | Investigation Threshold |
|---|---|---|
| Tool calls per session | 5–25 | > 75 |
| Issues opened per session | 0–3 | > 10 |
| Issues closed per session | 0–2 | > 5 |
| Secret read operations | 0 | > 0 (check policy) |
| PR write operations | 0 | > 0 (prohibited for this role) |

**Key alert:** Issue close operations at more than 3× the session average warrant investigation — an injected instruction causing mass-dismissal of security findings would manifest as a spike here.

### Autonomous Remediation Agent

**Purpose:** Creates branches, commits dependency updates, opens PRs for human review.

| Metric | Typical Range | Investigation Threshold |
|---|---|---|
| Branches created per session | 1–2 | > 5 |
| Commits per session | 1–4 | > 12 |
| Files modified per commit | 1–5 | > 20 |
| PRs created per session | 1–2 | > 6 |
| Direct commits to protected branches | 0 | > 0 (invariant — prohibited) |
| Deploy operations | 0 | > 0 (invariant — prohibited) |
| IAM or policy changes | 0 | > 0 (invariant — prohibited) |

**Key alert:** Any direct commit to a protected branch or any deploy/IAM operation is prohibited. These are the highest-impact actions an agent can take and must trigger immediate suspension.

---

## Alert Hierarchy

Alerts are classified into four tiers based on required response time and business impact.

### Tier 1 — CRITICAL (respond within 15 minutes)

Indicators of active compromise or policy violation with immediate impact potential.

- Prohibited tool call attempted (blocked or not)
- Canary token detected in agent output
- Audit log integrity failure or write gap
- Agent modified its own authorization policy
- Direct commit to a protected branch
- IAM or deploy operation by an agent without explicit authorization
- Circuit breaker trip on a remediation or deploy-capable agent
- Network connection to a non-allowlisted destination

**Response:** Suspend the agent session and the session chain immediately. Preserve all logs. Initiate forensic investigation using [af-01-prompt-injection-unauthorized-action.md](../../forensics-and-incident-response-framework/docs/agent-forensics/af-01-prompt-injection-unauthorized-action.md) or the appropriate playbook.

### Tier 2 — HIGH (respond within 2 hours)

Significant statistical anomalies or indicators that require investigation before the agent continues operating.

- Session duration > 3× the P99 baseline
- Tool call count > 2× the P99 baseline
- Authorization denial rate spike (> 5× baseline mean)
- Mass issue close in a single session (> 5 closes, no approvals)
- Session triggered by an unexpected source (e.g., manual trigger on a scheduled-only agent)
- Output schema validation failure

**Response:** Flag the session for review. Do not automatically terminate — session logs may be needed for investigation. Review within 2 hours. If the session is still running when reviewed, make a human decision on whether to allow it to complete or suspend.

### Tier 3 — MEDIUM (review within 24 hours)

Anomalies that may represent policy misconfiguration, task scope changes, or early indicators of a developing incident.

- Session duration between P99 and 3× P99
- New file paths accessed outside the 30-day baseline
- Minor scope expansion (< 50% above baseline P99)
- LLM API error rate > 3% for a specific agent
- Circuit breaker trip on a non-deploy agent (review, do not escalate immediately)

**Response:** Add to the daily security operations review queue. No immediate action required unless the anomaly pattern persists across multiple sessions.

### Tier 4 — INFO (weekly review)

Operational metrics and compliance evidence. Not security alerts.

- Normal session completions
- Standard authorization approvals
- Routine policy version updates
- Baseline recalibration reminders (quarterly)

---

## Dashboard Design

### Security Operations Dashboard

The primary real-time view for security teams. Shows the current health of all AI agent sessions.

**Panel 1 — Active Sessions Feed**
- Session ID, agent role, task description, elapsed time
- Current tool call count vs. P99 baseline
- Authorization status (all permits / any denials)
- Canary status (no exposure / exposure detected)
- Color coding: Green (within baseline), Yellow (1–2× P99), Red (> 2× P99 or any invariant violation)

**Panel 2 — Alert Timeline**
- Last 6 hours of alerts by tier
- Alert rate trend (is the rate increasing?)
- Unacknowledged Tier 1 and Tier 2 alerts

**Panel 3 — Circuit Breaker Status**
- Circuit breaker state per agent chain: Closed (normal), Open (tripped), Half-open (testing)
- Trip history (last 7 days)

**Panel 4 — Audit Log Health**
- Events received per minute
- Last-event timestamp per agent
- Any log write gaps in the last hour

### Agent Health Dashboard

Operational view for platform engineers. Shows throughput, latency, and error rates.

- Task queue depth per agent role
- Session completion rate (last 24 hours)
- P50/P95/P99 tool call latency by tool type
- LLM API error rate and error type breakdown
- Session duration distribution vs. baseline

---

## Instrumentation Requirements

Every AI agent deployed in the pipeline must emit the following instrumentation.

### Required Event Types

```jsonl
// Session start
{"event": "session_start", "session_id": "uuid", "agent_role": "code-review",
 "trigger_source": "github_pr_event", "trigger_ref": "pull_request:42",
 "system_prompt_version": "sha256:a3f9...", "policy_version": "2.4.0",
 "timestamp": "2026-04-08T10:00:00Z"}

// Tool call (pre-execution authorization check)
{"event": "tool_authorization", "session_id": "uuid", "tool": "github.repo.read",
 "operation": "get_file_contents", "parameters": {"path": "src/auth.py"},
 "decision": "ALLOW", "policy_rule": "tools[0].operations[0]",
 "timestamp": "2026-04-08T10:00:05Z"}

// Tool call result
{"event": "tool_result", "session_id": "uuid", "tool": "github.repo.read",
 "operation": "get_file_contents", "duration_ms": 142,
 "result_size_bytes": 4821, "content_source": "repository:org/repo:src/auth.py",
 "timestamp": "2026-04-08T10:00:05.142Z"}

// Output produced
{"event": "agent_output", "session_id": "uuid", "output_type": "review_comment",
 "output_token_count": 312, "schema_valid": true,
 "canary_detected": false, "timestamp": "2026-04-08T10:02:11Z"}

// Session end
{"event": "session_end", "session_id": "uuid", "outcome": "completed",
 "total_tool_calls": 14, "total_duration_s": 131,
 "timestamp": "2026-04-08T10:02:12Z"}
```

### Immutability Requirements

- The audit event stream must be written to an append-only store before the tool call result is returned to the agent
- Agents must not have write, update, or delete permissions on the audit log store
- The audit log store must use object-level locking or a write-once storage backend
- Log integrity must be verifiable: events must be hash-chained so that gaps or modifications are detectable

---

## Correlation and Investigation Workflows

### Multi-Agent Session Correlation

In a pipeline where multiple agents process the same task, all events from all agents in the chain must be correlatable via a shared `chain_id`. The `chain_id` is set by the orchestrator at task initiation and passed to each subagent. Each agent appends events with both its own `session_id` and the inherited `chain_id`.

```python
def investigate_chain(chain_id: str, audit_store) -> list[dict]:
    """
    Retrieve all events from all agents in a multi-agent chain, ordered by timestamp.
    Enables reconstruction of the complete action sequence across agent boundaries.
    """
    events = audit_store.query(
        filter={"chain_id": chain_id},
        sort=[{"timestamp": "asc"}]
    )
    return events
```

This structure enables the cascade compromise pattern to be detected: an injection in the code review agent's input that propagates through triage and remediation agents will appear as a correlated anomaly in the chain view even if each individual agent session looks within its own statistical baseline.

### Five Questions Investigation Entry Points

When a Tier 1 or Tier 2 alert fires, the investigation entry point depends on the alert type:

| Alert Type | Primary Entry Point | Reference Playbook |
|---|---|---|
| Prohibited tool call | Q4 (What tools did it invoke?) → Q5 (Authorization basis) | AF-01 |
| Canary token in output | Q2 (What was it instructed?) → Q3 (What data did it access?) | AF-01 |
| Cascade compromise indicator | Chain correlation → Q1 per agent → Q3 aggregated | AF-02 |
| Unknown artifact provenance | Q4 (tool calls that produced the artifact) → Q5 | AF-03 |
| Permission escalation | Q4 (IAM/policy tool calls) → Q5 | AF-04 |

---

## Operational Runbooks

### Runbook: Responding to a Tier 1 Prohibited Tool Call Alert

1. Immediately suspend the session chain via the circuit breaker API
2. Confirm the session is suspended (check circuit breaker state = Open)
3. Preserve the audit log for the session chain — set retention hold
4. Retrieve all events for `chain_id` and `session_id` associated with the alert
5. Determine: was the prohibited tool call BLOCKED by the policy (attempted but denied) or did it succeed (indicating a policy misconfiguration)?
   - If blocked: the policy worked; proceed with investigation to determine what caused the agent to attempt the call
   - If succeeded: escalate immediately — this is a policy enforcement failure
6. Apply Five Questions Framework: [agent-forensics/five-questions-framework.md](../../forensics-and-incident-response-framework/docs/agent-forensics/five-questions-framework.md)
7. Determine whether the attempt was caused by prompt injection (check Q2), policy misconfiguration, or system prompt ambiguity
8. Do not return the agent to production until the root cause is resolved and the tool policy is reviewed

### Runbook: Responding to a High Tool Call Count Alert

1. Check whether the session is still running or completed
2. If still running: review the current tool call sequence in the audit log — is it following a recognizable task pattern or does it appear to be probing?
3. If probing indicators are present (repeated calls to different paths with no pattern, calls to unusual tools): escalate to Tier 1 and suspend
4. If the pattern appears to be a large legitimate task: allow the session to complete but flag for post-session review
5. After session completion: compare the session's tool call sequence against the 30-day baseline using sequence analysis, not just count analysis — anomalous sequences (e.g., calls in unexpected order) matter more than total count

---

## Integration with Security Tooling

### SIEM Integration

Audit log events should be forwarded to the organization's SIEM in real time. The SIEM correlation rules for AI pipeline events should cover:

- Alert correlation: link a Tier 1 audit event with concurrent GitHub events (did the agent's session coincide with an unexpected PR approval or merge?)
- Cross-system timeline: link agent session timestamps with repository push events, deployment events, and IAM changes
- Historical investigation: SIEM enables queries across multiple agents and sessions over time, supporting incident timeline reconstruction

### Vulnerability Management Integration

When an agent opens a security issue, the issue should be linked to the session ID and chain ID that generated it. This enables:
- Audit of whether the finding was generated by a session that showed anomalous behavior
- Verification that high-severity findings opened by agents were generated in sessions with clean audit trails
- Detection of mass-finding-creation attacks (an injected agent opening many spurious issues to cause alert fatigue)

*Cross-references:* [agent-audit-trail.md](agent-audit-trail.md) — audit trail schema and immutability requirements; [ai-behavioral-baseline.md](../../forensics-and-incident-response-framework/docs/ai-behavioral-baseline.md) — behavioral baseline methodology for statistical signal calibration; [blast-radius-containment.md](blast-radius-containment.md) — containment architecture that limits the impact of incidents detected via observability; [multi-agent-architecture.md](multi-agent-architecture.md) — multi-agent chain correlation context.
