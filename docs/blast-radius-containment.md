# Blast Radius Containment for AI Agents

## Table of Contents

- [Overview](#overview)
- [Why Blast Radius is a Distinct Problem for AI Agents](#why-blast-radius-is-a-distinct-problem-for-ai-agents)
- [The Four Containment Dimensions](#the-four-containment-dimensions)
- [Scope Constraints](#scope-constraints)
- [Rate Limiting and Invocation Budgets](#rate-limiting-and-invocation-budgets)
- [Reversibility Requirements](#reversibility-requirements)
- [Temporal Limits and Session Boundaries](#temporal-limits-and-session-boundaries)
- [Circuit Breaker Integration](#circuit-breaker-integration)
- [Multi-Agent Blast Radius](#multi-agent-blast-radius)
- [Containment by Agent Role](#containment-by-agent-role)
- [Implementation Reference](#implementation-reference)

---

## Overview

Blast radius containment defines the bounded scope of actions an AI agent can take before an authorization boundary, rate limit, or circuit breaker halts further execution. It is an architectural property, not solely a policy property: containment requires that authorization policies, rate limits, reversibility constraints, and session lifetimes all operate as independent enforcement layers. If any single layer is absent, the effective blast radius expands to the limits of the missing control.

This document defines the containment architecture for AI agents operating in DevSecOps pipelines. It is a companion to `agent-authorization.md` (which defines what agents are permitted to do) and `pipeline-controls.md` (which defines circuit breaker and approval gate implementation). Where `agent-authorization.md` addresses authorization at the permission level, this document addresses the architectural constraints that bound the consequences of both authorized and unauthorized actions.

---

## Why Blast Radius is a Distinct Problem for AI Agents

Traditional blast radius analysis addresses what a compromised human account or service credential can do before detection. For AI agents, blast radius has additional dimensions:

**Non-determinism:** The same agent running the same task twice may take different paths, invoking different tools in different orders. A compromised context window (via prompt injection) may cause the agent to exhaust a high-impact action in a single session that a human would have spread across multiple deliberate steps.

**Speed of execution:** An agent can invoke dozens of tools in seconds. Human-equivalent operations that would take a human analyst 30 minutes may complete in under a minute, compressing the detection window available before the blast radius ceiling is reached.

**Non-local effects in agent chains:** In a multi-agent system, one compromised agent's actions propagate through the entire chain. The blast radius of the entry point is multiplied by the authority of every downstream agent.

**Ambient authority accumulation:** Agents that run with long-lived credentials (rather than session-scoped credentials) accumulate effective authority over time as they are granted access to additional systems. An agent operating for 60 minutes with a persistent service account has accumulated more effective blast radius than one operating for 5 minutes with session-scoped credentials.

These properties require containment controls designed specifically for agent execution models, not adaptations of traditional credential scoping.

---

## The Four Containment Dimensions

Blast radius containment operates across four dimensions:

| Dimension | Question answered | Control mechanism |
|---|---|---|
| **Scope** | What can the agent touch? | Tool authorization policy; resource-level permissions |
| **Rate** | How fast can the agent act? | Invocation rate limits; concurrency limits |
| **Reversibility** | Can the action be undone? | Action classification; approval gates for irreversible actions |
| **Time** | How long can the session run? | Session TTL; inactivity timeout |

All four dimensions must be addressed. A policy that perfectly scopes permissions but sets no rate limits allows an agent to exhaust its entire authorization scope in seconds. A policy that enforces rate limits but places no reversibility requirements allows the agent to make irreversible changes at a controlled pace over an extended session.

---

## Scope Constraints

Scope constraints define the resources and operations an agent can affect. They operate at two levels:

### Tool-Level Scope

Define which tools the agent can invoke. Prefer deny-by-default: the agent can invoke only the tools explicitly listed in its authorization policy. See `agent-authorization.md` for policy schema and enforcement patterns.

Scope constraints must cover:
- **Tool set:** The specific tools available to the agent (not all tools the agent's framework supports)
- **Resource identifiers:** Where applicable, restrict tools to specific repositories, directories, environments, or services rather than all resources the tool can address
- **Operation types:** For tools that support multiple operation types (read/write/delete), authorize only the types required for the agent's task

```yaml
# Example: Triage agent — read-only scope, no write operations
tools:
  - name: read_file
    operations: [read]
    paths:
      - /workspace/**
      - /tmp/scan-results/**
  - name: list_directory
    operations: [list]
    paths: [/workspace/**]
  - name: create_ticket
    operations: [create]
    projects: [SECURITY-TRIAGE]
    # No update or close operations — triage only creates, humans manage lifecycle
prohibited_tools:
  - write_file
  - delete_file
  - merge_pull_request
  - deploy
  - http_post  # No external egress
```

### Data Classification Scope

Define which data classifications the agent is authorized to access. An agent that reads public CVE feeds does not need access to internal proprietary code or customer data. Where the tool execution layer can enforce data classification, do so:

- Read access to repositories should be constrained to the specific repositories relevant to the agent's task, not all repositories in the organization
- Access to secrets managers should be scoped to the specific secret paths needed, not to all secrets in the vault

---

## Rate Limiting and Invocation Budgets

Rate limits constrain how quickly an agent can exhaust its authorization scope, providing time for anomaly detection and human intervention before irreversible actions occur at scale.

### Per-Session Invocation Budget

Define a maximum number of tool invocations per session for each agent role. The budget is derived from the expected maximum number of invocations for a legitimate task execution, with a safety multiplier:

```yaml
session_limits:
  reviewer_agent:
    max_tool_invocations: 50      # Typical PR review: 15–25 invocations; 2x safety margin
    max_session_duration_minutes: 10
  triage_agent:
    max_tool_invocations: 30      # Typical triage: 10–15 invocations
    max_session_duration_minutes: 5
  remediation_agent:
    max_tool_invocations: 40      # Typical remediation: 15–20 invocations
    max_session_duration_minutes: 15
    requires_human_approval_after_invocations: 20  # Approval gate mid-session
```

When an agent reaches its session invocation budget, the session is suspended and the human principal is alerted. The agent does not simply fail — the partial state is preserved for inspection and the human principal can choose to continue (requiring explicit re-authorization), discard, or investigate.

### Per-Tool Rate Limits

Apply rate limits to high-impact tools independently of the session budget:

```yaml
tool_rate_limits:
  write_file:
    max_per_minute: 5
    max_per_session: 20
  http_post:
    max_per_minute: 2
    max_per_session: 10
  create_pull_request:
    max_per_session: 3            # Creating 4+ PRs in one session is anomalous
  deploy:
    max_per_session: 1            # One deployment per agent session
    requires_approval: true       # Every invocation requires human approval
```

### Concurrency Limits

Limit the number of concurrent sessions for each agent role:

```yaml
concurrency_limits:
  reviewer_agent: 5               # Max 5 simultaneous PR reviews
  remediation_agent: 2            # Max 2 simultaneous remediation sessions
  monitor_agent: 10               # Monitor agents are lightweight; higher concurrency allowed
```

High concurrency of remediation agents is a signal of either legitimate high-volume activity (expected during an incident response push) or an anomaly (multiple injected sessions running simultaneously). Alert when concurrency exceeds the defined ceiling.

---

## Reversibility Requirements

Classify all tool operations by reversibility and apply controls proportional to the classification:

### Reversibility Classification

| Classification | Definition | Examples |
|---|---|---|
| **Fully reversible** | Action can be exactly undone without data loss | Read operations; creating a new branch; creating a draft PR |
| **Recoverable** | Action can be undone, but may require effort or cause brief disruption | Merging a PR (revert is possible); modifying a file (git revert); pushing to a non-production environment |
| **Partially reversible** | Some consequences can be undone; others cannot | Deploying to production (rollback available, but downtime occurred); sending a notification (cannot unsend) |
| **Irreversible** | Action cannot be undone | Deleting a branch with no backup; sending an email; posting to external webhook; deleting a secret |

### Reversibility-Based Controls

```yaml
# Enforce reversibility preferences in agent authorization policy
reversibility_policy:
  prefer_reversible: true          # Agent must choose reversible alternatives when equivalent options exist

  require_approval:
    - classification: partially_reversible
      when: affects_production     # All partially reversible actions affecting production require approval
    - classification: irreversible # All irreversible actions require explicit human approval

  prohibited_without_explicit_override:
    - delete_branch
    - delete_secret
    - send_external_notification   # Any action that cannot be recalled
```

When an agent must take a partially reversible or irreversible action, the authorization policy requires an out-of-band human approval event before the tool is invoked. The approval event is logged in the audit trail with the approver's identity and the specific action approved.

---

## Temporal Limits and Session Boundaries

AI agent sessions must have defined start and end boundaries. An unbounded session accumulates effective blast radius over time: the longer the session runs, the more operations it can complete, the more data it has accessed, and the more context it has accumulated from tool results that may include attacker-controlled content.

### Session TTL Requirements

```yaml
session_limits:
  max_session_duration_minutes:
    reviewer_agent: 10
    triage_agent: 5
    remediation_agent: 20          # Longer tasks allowed for complex remediation
    monitor_agent: 60              # Monitoring agents may run longer; rate limits apply

  inactivity_timeout_minutes: 3    # Session terminated if no tool invocations for 3 minutes

  hard_ceiling_minutes: 120        # Absolute maximum — no session exceeds 2 hours regardless of activity
```

When a session reaches its TTL, the session is terminated gracefully: any in-progress tool invocation is allowed to complete (with a 30-second timeout), and the session is then closed. The audit record is sealed with a TTL-expiry event.

### Session Isolation

Each agent session must be isolated: credentials issued for one session must not be reusable in a subsequent session. Use short-lived session tokens (GitHub App installation tokens, AWS STS sessions, Vault leases) with TTLs that match the session duration:

```python
# Session-scoped credential issuance
def issue_session_credentials(agent_role: str, session_id: str, session_ttl_minutes: int):
    """Issue credentials scoped to this specific session and agent role."""
    token = github_app.create_installation_token(
        permissions=ROLE_PERMISSIONS[agent_role],
        expires_at=datetime.utcnow() + timedelta(minutes=session_ttl_minutes)
    )
    audit_log.record(
        event="session_credentials_issued",
        session_id=session_id,
        agent_role=agent_role,
        token_expires_at=token.expires_at,
        permissions=token.permissions
    )
    return token
```

---

## Circuit Breaker Integration

Circuit breakers are the real-time enforcement mechanism that responds to blast radius events as they develop, rather than after the fact. A circuit breaker monitors session behavior and suspends the session when anomaly thresholds are exceeded.

### Circuit Breaker Triggers

```yaml
circuit_breaker:
  triggers:
    - condition: schema_validation_failure
      threshold: 1                  # Any schema failure suspends the session
    - condition: canary_token_detected
      threshold: 1                  # Any canary detection suspends immediately
    - condition: authorization_policy_violation_attempted
      threshold: 1                  # Any attempted unauthorized tool invocation
    - condition: session_age_exceeded
      threshold: session_ttl        # As defined in session_limits
    - condition: invocation_rate_spike
      threshold:
        multiplier: 3.0             # Rate exceeds 3x the per-tool limit
        window_seconds: 60
    - condition: cumulative_invocations_exceeded
      threshold: session_max_invocations

  on_trigger:
    action: suspend_session         # Not terminate — preserve state for forensics
    alert: human_principal          # Notify the person who initiated the session
    seal_audit_record: true         # Seal audit record with circuit-breaker event
    preserve_context_window: true   # Capture context window contents for forensic review
```

### Circuit Breaker vs. Authorization Policy

A circuit breaker is not a replacement for authorization policy. The authorization policy defines what the agent is permitted to do; the circuit breaker detects when the agent's behavior deviates from expected patterns, including patterns that are individually authorized but collectively anomalous. Example: an agent authorized to read files at a rate of 5/minute but invoking the read tool at 40/minute in a 30-second burst may be within authorization for each individual read, but the pattern indicates potential automation of an exfiltration or reconnaissance task.

---

## Multi-Agent Blast Radius

In multi-agent systems, blast radius is non-local. A single compromised or injected agent can affect every agent in its chain.

### Authority Ceiling Enforcement

The most critical containment control in multi-agent systems: no agent can grant a subagent more authority than it holds itself. This must be enforced by the tool execution layer, not by the agents themselves:

```python
def authorize_subagent_session(
    orchestrator_session: Session,
    subagent_role: str,
    requested_permissions: PermissionSet
) -> Session:
    """
    Issue a subagent session whose permissions cannot exceed the orchestrator's.
    """
    # Intersect: subagent gets the lesser of what it needs and what the orchestrator has
    effective_permissions = requested_permissions.intersect(
        orchestrator_session.effective_permissions
    )

    if effective_permissions != requested_permissions:
        audit_log.record(
            event="subagent_permissions_bounded",
            orchestrator_session_id=orchestrator_session.id,
            requested=requested_permissions,
            granted=effective_permissions,
            reason="orchestrator_authority_ceiling"
        )

    return Session(
        role=subagent_role,
        permissions=effective_permissions,
        parent_session_id=orchestrator_session.id,    # Provenance propagation
        human_principal=orchestrator_session.human_principal,
        ttl_minutes=min(
            ROLE_TTL[subagent_role],
            orchestrator_session.remaining_ttl_minutes  # Cannot outlive parent
        )
    )
```

### Cascade Propagation Containment

Install containment controls at every agent chain boundary to interrupt cascade propagation before it reaches high-impact agents:

1. **Schema enforcement at boundaries:** Subagent inputs must conform to a defined schema. Free-text content from external sources must not be interpolated as instructions.

2. **Canary tokens in sensitive data:** Embed unique, session-specific canary tokens in data sources that agents read. If a canary token appears in a subagent's tool call parameters or output, a cascade is in progress.

3. **Independent circuit breakers per tier:** Each agent tier has its own circuit breaker. A compromised orchestrator that triggers the orchestrator's circuit breaker does not suppress the subagents' circuit breakers.

4. **Subagent sessions bound by parent session authority:** Even if the orchestrator's session is active and uncircuit-broken, subagent sessions initiated during a compromised orchestrator session cannot exceed the authority ceiling established at the orchestrator level.

---

## Containment by Agent Role

### Reviewer Agent

```yaml
# Read-only; no write access; blast radius limited to information disclosure
scope: read_only
rate_limit: 50 invocations/session
reversibility: all operations fully reversible
session_ttl: 10 minutes
circuit_breaker_triggers: [schema_failure, canary_detection, rate_spike_3x]
```

### Triage Agent

```yaml
# Read security alerts; label/tag operations only; no alert dismissal
scope: read + label/tag only
rate_limit: 30 invocations/session
reversibility: label/tag operations recoverable (label can be removed)
session_ttl: 5 minutes
circuit_breaker_triggers: [schema_failure, canary_detection, attempted_dismiss]
```

### Remediation Agent

```yaml
# Create branches and PRs; no merge operations without human approval
scope: read + create_branch + create_pr
rate_limit: 40 invocations/session; max 3 PRs/session
reversibility: PR creation recoverable; branch deletion requires approval
session_ttl: 20 minutes
requires_approval_for: [deploy, merge, delete_branch]
circuit_breaker_triggers: [schema_failure, canary_detection, rate_spike_3x, >20 invocations without approval checkpoint]
```

### Monitor Agent

```yaml
# Read logs/metrics; create incident tickets; no configuration modification
scope: read + create_ticket
rate_limit: 60 invocations/session (higher — monitoring is high-volume read)
reversibility: ticket creation recoverable
session_ttl: 60 minutes (monitoring tasks are longer-running)
circuit_breaker_triggers: [schema_failure, canary_detection, attempted_config_modification]
```

---

## Implementation Reference

- `docs/agent-authorization.md` — Tool authorization policy schemas and POLA implementation
- `docs/pipeline-controls.md` — Circuit breaker implementation patterns and approval gate configuration
- `docs/multi-agent-architecture.md` — Multi-agent trust propagation and cascade compromise controls
- `docs/agent-audit-trail.md` — Audit record requirements including circuit-breaker events
- `docs/production-operations.md` — Progressive autonomy levels and blast radius limits for production agents
- `book-5-ai-agentic-security/ch11-multi-agent-trust/` — Multi-agent blast radius lab exercises
- `book-5-ai-agentic-security/ch12-pipeline-controls/` — Circuit breaker and approval gate labs
- `book-5-ai-agentic-security/ch13-ai-production-ops/` — Progressive autonomy and production blast radius governance

## Forensics Cross-Reference

When blast radius containment fails — when an agent takes an action outside its authorized scope — the following investigation playbooks govern the forensic response. The containment specifications above define what should have prevented each incident type; the playbooks define how to investigate when containment failed.

| Incident Type | Applicable Playbook | Key Evidence |
|---------------|--------------------|----|
| Agent produced artifact not authorized by its task | [AF-03: Artifact Unknown Provenance](../../forensics-and-incident-response-framework/docs/agent-forensics/af-03-artifact-unknown-provenance.md) | Cosign signing identity, SLSA provenance, session audit log, Q5 authorization chain |
| Agent modified its own permissions, system prompt, or policy | [AF-04: Agent Permission Escalation](../../forensics-and-incident-response-framework/docs/agent-forensics/af-04-agent-permission-escalation.md) | CloudTrail/RBAC change event, git blame on policy file, tool call log turn of modification |
| Model shows weight or version tampering post-deployment | [AF-06: Model Supply Chain Tampering](../../forensics-and-incident-response-framework/docs/agent-forensics/af-06-model-supply-chain-tampering.md) | Model digest mismatch, Cosign model verification, layer-hash comparison, contamination window |
| Agent exceeded scope via prompt injection | [AF-01: Prompt Injection Unauthorized Action](../../forensics-and-incident-response-framework/docs/agent-forensics/af-01-prompt-injection-unauthorized-action.md) | Session turns with external content sources, injection vector classification, Q2/Q3 analysis |
| Cascade compromise across agent chain | [AF-02: Multi-Agent Cascade Compromise](../../forensics-and-incident-response-framework/docs/agent-forensics/af-02-multi-agent-cascade-compromise.md) | Cross-agent session correlation by root_session_id, authority ceiling violations per tier |

The blast radius assessment in each playbook uses the scope, rate, reversibility, and session TTL specifications defined in this document as the baseline for determining which actions were within the agent's authorized containment profile.
