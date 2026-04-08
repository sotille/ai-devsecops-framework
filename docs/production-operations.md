# AI in Production Operations: Autonomous Remediation and Risk Governance

## Table of Contents

- [Overview](#overview)
- [Autonomous Remediation Risk Taxonomy](#autonomous-remediation-risk-taxonomy)
- [Dry-Run and Shadow Mode](#dry-run-and-shadow-mode)
- [Progressive Autonomy Model](#progressive-autonomy-model)
- [Blast Radius Limits for Autonomous Actions](#blast-radius-limits)
- [Human Escalation Triggers](#human-escalation-triggers)
- [Rollback as a Prerequisite for Autonomy](#rollback-as-a-prerequisite)
- [SLO and SLA Implications](#slo-and-sla-implications)
- [AI Operations Governance](#ai-operations-governance)
- [Production Incident Response for AI Agents](#production-incident-response)
- [Implementation Checklist](#implementation-checklist)

---

## Overview

AI agents operating in production operations — autonomous remediation agents, AIOps systems, AI-assisted incident response — represent the highest-risk deployment of AI in the DevSecOps lifecycle. These agents operate in production environments, take actions with immediate business impact, and often operate at times when human oversight is limited (overnight, during incidents, in automated response chains).

The fundamental risk is not that production AI agents fail at their stated purpose. The risk is that the blast radius of a compromised or misbehaving agent in production is much larger than in development or CI/CD contexts, and the time-to-detect may be longer if anomalous agent behavior resembles legitimate incident response activity.

This document defines the security architecture and governance model for production AI operations, with the objective of enabling the operational benefits of AI autonomy while maintaining meaningful human oversight and limiting the damage an adversary can cause by compromising a production agent.

---

## Autonomous Remediation Risk Taxonomy

Production AI agent risks fall into four categories:

### Category 1: Prompt Injection via Operational Data

Production agents process operational data — log streams, metric events, alert payloads, incident reports — that originates from the infrastructure the agents monitor. An adversary who can write to any of these data sources can potentially inject instructions into the agent's context.

*Examples:*
- Log messages crafted to contain instruction-like language that causes the agent to execute unauthorized commands
- Metric labels or alert annotations containing override instructions
- JIRA or PagerDuty incident descriptions with injected directives

*Control:* Sanitize all operational data before passing it to production agents. Apply the same input sanitization rules as for CI/CD injection (see [prompt-injection-defense.md](prompt-injection-defense.md)). Production agents should process structured data (parsed JSON, typed alerts) rather than raw text wherever possible.

### Category 2: Scope Creep in Long-Running Sessions

Production agents that run continuously or handle multiple incidents within a single session may accumulate context that expands their effective scope beyond what was established at session initialization.

*Example:* A remediation agent tasked with CVE-2024-12345 is also handed CVE-2024-67890 in the same session. It now holds context for two separate incidents and may apply decisions from one to the other. A compromised agent may deliberately accumulate scope.

*Control:* Enforce session isolation. Each production incident or remediation task runs in a dedicated session with a defined scope. When the task is complete, the session terminates and credentials expire. The agent does not carry context across task boundaries.

### Category 3: Incorrect Autonomous Actions

An agent may take correct actions for incorrect reasons (acting on injected instructions that happen to be legitimate actions) or incorrect actions for correct reasons (attempting the right action but selecting the wrong target or parameters).

*Example:* An auto-scaling agent correctly identifies that a service needs scaling but scales the wrong service due to a data extraction error that confused service names.

*Control:* Dry-run mode before execution, output schema validation, and scope constraints on which resources the agent can modify. High-consequence actions require human approval regardless of the agent's confidence level.

### Category 4: Compromise Leading to Production Manipulation

A compromised production agent can take actions that look like legitimate remediation but are actually adversarial: deploying backdoored artifacts, modifying configuration to weaken security controls, exfiltrating data in the course of "incident investigation."

*Control:* Minimal standing permissions, approval gates for irreversible actions, immutable audit trail, canary tokens in production resources, and behavioral anomaly detection for agent sessions.

---

## Dry-Run and Shadow Mode

Before an AI agent is authorized to take autonomous production actions, it must operate in dry-run or shadow mode for a validation period.

### Dry-Run Mode

In dry-run mode, the agent generates action recommendations but does not execute them. All recommended actions are logged and reviewed by the operations team.

```yaml
# agent-config.yaml — dry-run mode configuration
agent:
  name: remediation-agent-prod
  mode: dry-run  # Options: dry-run, shadow, confirm, automate

  dry_run:
    # Log all recommended actions to the audit trail
    log_recommendations: true
    # Send recommendations to human review queue
    recommendation_queue: ops-review@example.com
    # Alert if the agent recommends an action outside its intended scope
    scope_violation_alert: true
```

Dry-run mode should run for a minimum of two weeks and cover at least 50 real incident scenarios before the agent is considered for promotion to shadow mode.

### Shadow Mode

In shadow mode, the agent executes actions but they take effect in a staging or shadow environment, not in production. Human operators take the same actions in production based on the agent's recommendations.

Shadow mode validation criteria:
- Agent recommendation accuracy ≥ 95% compared to human operator decisions over the shadow period
- No scope violations (the agent attempted no actions outside its defined scope)
- No authorization policy violations
- All approval-gated actions were correctly routed to human approval (not bypassed)

Shadow mode should run for a minimum of 30 days, covering at least three distinct incident types the agent is designed to handle.

---

## Progressive Autonomy Model

The progressive autonomy model expands agent authority incrementally based on demonstrated safety properties:

| Level | Name | Agent Behavior | Human Role |
|---|---|---|---|
| 0 | Suggest | Agent generates recommendations only | Human executes all actions |
| 1 | Confirm | Agent proposes actions; human must approve each before execution | Human reviews and approves |
| 2 | Automate (supervised) | Agent executes low-risk actions autonomously; human approval for medium/high risk | Human reviews audit trail; approves significant actions |
| 3 | Automate (alert on exception) | Agent executes all authorized actions autonomously; human alerted on anomalies | Human monitors; investigates anomalies |

**Promotion criteria from Level 1 to Level 2:**
- 30-day period with no authorization violations
- 30-day period with no scope violations
- 30-day period with ≥ 95% recommendation accuracy
- Rollback capability verified for all automatable actions
- Incident response playbook for agent compromise tested

**Promotion criteria from Level 2 to Level 3:**
- 90-day period at Level 2 with no violations
- Forensic readiness verified: all Five Forensic Questions can be answered for Level 2 agent sessions
- Behavioral baseline established: normal patterns documented for anomaly detection
- Human-in-the-loop confirmed for all approval-gated actions

**Demotion triggers:** Any authorization violation, scope violation, or confirmed compromise immediately demotes the agent to Level 1 pending investigation.

---

## Blast Radius Limits for Autonomous Actions

Every autonomous agent action must be evaluated against three blast radius dimensions:

### Scope

The agent can only act on resources within its defined scope. Scope is set at session initialization and cannot be expanded during the session.

```yaml
# Tool authorization policy with explicit scope constraints
agent_roles:
  - role: incident-remediation-agent
    permitted_tools:
      - tool: kubernetes.deployment.scale
        constraints:
          namespace: ["production", "staging"]
          deployment_pattern: "^(?!.*-db).*$"  # Cannot scale database deployments
          max_replicas_change: 10
          requires_approval_above_replicas: 50

      - tool: aws.ec2.security_group.rule.add
        constraints:
          vpc_id: ["vpc-prod-12345"]  # Only the production VPC
          direction: "ingress"
          requires_approval_for_public_access: true  # 0.0.0.0/0 requires approval

    explicitly_denied_tools:
      - kubernetes.cluster.delete
      - aws.iam.policy.create
      - aws.iam.role.attach_policy
      - aws.s3.bucket.policy.put
```

### Rate

Rate limits prevent a compromised agent from conducting large-scale operations before detection:

```yaml
rate_limits:
  per_session:
    max_tool_calls: 200
    max_high_consequence_actions: 10  # Actions that modify production state
    max_resource_modifications: 50
  per_hour:
    max_deployments: 5
    max_security_group_changes: 10
    max_configuration_changes: 20
```

### Reversibility

Before executing any action, the agent must identify whether the action is reversible. Irreversible actions require human approval regardless of autonomy level.

```python
IRREVERSIBLE_ACTIONS = {
    "kubernetes.pvc.delete",
    "aws.rds.cluster.delete",
    "aws.s3.object.delete",
    "aws.iam.role.delete",
    "aws.kms.key.schedule_deletion",
}

HIGH_BLAST_RADIUS_ACTIONS = {
    "kubernetes.deployment.delete",
    "aws.ec2.instance.terminate",
    "aws.elasticloadbalancing.listener.rule.delete",
}

def requires_approval(tool_name: str, parameters: dict, autonomy_level: int) -> bool:
    if tool_name in IRREVERSIBLE_ACTIONS:
        return True  # Always require approval, regardless of autonomy level
    if tool_name in HIGH_BLAST_RADIUS_ACTIONS:
        return True  # Always require approval
    if autonomy_level < 2:
        return True  # All actions require approval at Level 0 and 1
    return False
```

---

## Human Escalation Triggers

Define conditions under which the agent pauses autonomous execution and escalates to human operators:

| Trigger | Rationale | Escalation Path |
|---|---|---|
| Authorization policy violation attempt | Agent attempted unauthorized action — possible compromise | Page on-call security engineer; suspend agent session |
| Scope expansion attempt | Agent attempted to act outside session scope | Page on-call operations; suspend agent session |
| Consecutive action failures | Agent is stuck or operating on incorrect data | Alert operations; agent continues in suggest-only mode |
| Canary token triggered | Agent processed content containing a canary — possible injection | Page security; suspend agent session; preserve full context |
| Session age threshold exceeded | Session running longer than expected for the task type | Alert operations; agent requires re-authorization to continue |
| Impact threshold exceeded | Agent has modified more resources than expected for the incident | Alert operations; agent pauses pending human review |

---

## Rollback as a Prerequisite for Autonomy

An autonomous agent should not be authorized to take an action in production unless the action can be rolled back. This is not just a good practice — it is a prerequisite for autonomy authorization.

**Rollback verification checklist for each action type:**

| Action Type | Rollback Mechanism | Pre-authorization Verification |
|---|---|---|
| Kubernetes deployment scale | `kubectl scale` to previous replica count (from audit trail) | Verify previous replica count is recorded before scaling |
| EC2 security group rule add | `aws ec2 revoke-security-group-ingress` with original rule | Verify rule can be retrieved from audit trail post-add |
| Configuration parameter change | Change configuration back to audit trail value | Verify parameter history is accessible |
| DNS record modification | Revert to previous value from audit trail | Verify TTL and propagation time acceptable for rollback |
| Certificate rotation | Re-deploy previous certificate from vault | Verify previous certificate is retained in vault for 72h post-rotation |

**Rollback capability test:** Before promoting an agent from dry-run to shadow mode, execute a rollback drill: the agent takes a test action, the operations team identifies the action in the audit trail, and they execute the rollback procedure. The rollback must complete successfully within the target recovery time objective (RTO).

---

## SLO and SLA Implications

Introducing autonomous AI agents into production operations affects SLO and SLA commitments in ways that must be explicitly evaluated:

**Potential SLO improvements:**
- Faster mean time to remediate (MTTR) for incident types the agent handles reliably
- 24/7 remediation coverage without on-call fatigue

**Potential SLO risks:**
- Agent misconfiguration or compromise may cause the agent to make the incident worse
- Agent indecision (escalating everything to human) may not improve MTTR
- Agent approval gates introduce latency if the approval queue is not promptly staffed

**SLO governance:**

When an AI agent is responsible for a remediation path, the SLO commitment must account for:
1. Agent detection lag (how long before the agent identifies the incident)
2. Agent decision time (how long before the agent generates a recommendation)
3. Approval gate latency (if approval required: how long before a human approves)
4. Execution time

If the approval gate at Level 1 or Level 2 is consistently staffed by a human who takes 15 minutes to approve, the effective MTTR for those incident types is the agent detection time + 15 minutes + execution time. This must be measured and compared to the MTTR without the agent.

---

## AI Operations Governance

Organizations operating production AI agents should establish a lightweight AI Operations Governance function:

**AI Operations Review Board (quarterly):**
- Review agent performance metrics against targets
- Review authorization violations and escalation events from the prior quarter
- Evaluate promotion or demotion of agents in the autonomy model
- Review and approve changes to agent scope and authorization policies
- Review forensic readiness: are all Five Forensic Questions answerable for agent incidents?

**Metrics to track:**

| Metric | Target | Alert Threshold |
|---|---|---|
| Agent authorization violation rate | 0 | >0 in any 30-day period |
| Agent scope violation rate | 0 | >0 in any 30-day period |
| Approval gate latency (P95) | < 15 minutes | > 30 minutes |
| Agent recommendation accuracy | > 95% | < 90% over 30 days |
| Rollback success rate | 100% | < 100% |
| Mean time to detect agent anomaly | < 5 minutes | > 15 minutes |

---

## Production Incident Response for AI Agents

When a production AI agent behaves anomalously or is suspected to be compromised:

**Immediate actions (minutes 0–5):**
1. Suspend the agent session (revoke session credentials)
2. Preserve the agent audit trail (flag for legal hold if compromise is confirmed)
3. Identify the last 10 actions taken by the agent; assess whether any require rollback
4. Page the security incident response team

**Investigation actions (minutes 5–60):**
1. Apply the Five Forensic Questions framework (see [forensics-and-incident-response-framework](../../../forensics-and-incident-response-framework/docs/agent-forensics/five-questions-framework.md))
2. Identify the session ID and retrieve the full tool call sequence
3. Identify the point in the session where behavior diverged from expected
4. Determine the likely injection vector if injection is suspected

**Recovery actions:**
1. Roll back any actions that were unauthorized or incorrect
2. Scan the production environment for artifacts created by the agent during the anomalous period
3. Rotate any credentials that were accessible to the agent
4. Root cause analysis and authorization policy update before re-enabling the agent

---

## Implementation Checklist

### Pre-Deployment
- [ ] Agent has completed dry-run period (minimum 2 weeks, 50 scenarios)
- [ ] Agent has completed shadow mode period (minimum 30 days, 3 incident types)
- [ ] Promotion criteria for dry-run and shadow mode verified and documented
- [ ] Rollback procedures documented and tested for all automatable action types
- [ ] Forensic readiness verified: all Five Forensic Questions answerable for test sessions

### Authorization and Scope
- [ ] Tool authorization policy in version control with explicit scope constraints
- [ ] Blast radius limits (scope, rate, reversibility) defined per action type
- [ ] Human escalation triggers defined and routing configured
- [ ] Approval gate coverage: human reviewers available within SLO for approval-gated actions

### Monitoring
- [ ] Behavioral baseline documented for anomaly detection
- [ ] Canary tokens deployed in production resources accessible to the agent
- [ ] Authorization and scope violation alerts configured and routed to security
- [ ] Agent audit trail append-only, tamper-resistant, with 12-month retention

### Governance
- [ ] Autonomy level documented and reviewed quarterly
- [ ] AI Operations Review Board cadence established
- [ ] Agent metrics tracked and reported to operations leadership
