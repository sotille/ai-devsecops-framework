# Building an AI Security Program: From AI-Naive to AI-Secure

## Table of Contents

- [Overview](#overview)
- [The Minimum Viable AI Security Program](#minimum-viable-program)
- [Program Roadmap: 90-Day, 6-Month, 12-Month Horizons](#program-roadmap)
- [AI Security Roles and Responsibilities](#roles-and-responsibilities)
- [Metrics and KPIs](#metrics-and-kpis)
- [Executive Communication for AI Security Investment](#executive-communication)
- [Program Review Cadence](#program-review-cadence)
- [Integration with Existing Security Program](#integration)
- [Common Failure Modes](#common-failure-modes)

---

## Overview

An AI security program is the organizational structure — roles, processes, metrics, and governance — that sustains AI security controls over time as the threat landscape evolves and AI adoption within the organization expands. Controls without a program decay: they are not maintained, exceptions accumulate, new AI tools are adopted outside the program's scope, and the organization regresses to a lower maturity level.

This guide provides the organizational blueprint for building and sustaining an AI security program. It is anchored to the five-level AI Security Maturity Model (see [maturity-model.md](maturity-model.md)) and structured around three planning horizons that allow organizations to achieve meaningful early outcomes while building toward comprehensive capability.

An AI security program does not require a dedicated team at the outset. A program can begin with a single security engineer who owns the AI security function as part of a broader AppSec or platform security role. The program should scale with AI adoption — the organizational structure described in this guide represents the target for organizations that have reached Level 4 or Level 5 maturity.

---

## Minimum Viable AI Security Program

The minimum viable AI security program (MVASP) is the smallest set of activities that provides meaningful security coverage for an organization's current AI use. It is not a destination — it is the starting point from which the full program is built.

**MVASP requirements:**

| Component | Requirement |
|---|---|
| AI inventory | A maintained list of all AI tools in use: which teams use them, for what purpose, and what data they can access |
| Acceptable use policy | A published policy that defines what code and data may be used with external AI providers |
| Dependency verification | A process that verifies AI-suggested dependencies before they enter version control |
| Pre-commit secret scanning | Automated secret detection that runs before code is committed |
| Responsible person | One named person accountable for AI security — even if this is not their full-time role |

These five components can be implemented by a single engineer in two to four weeks. Without them, the organization is at Level 1 (AI-Naive) and every new AI tool adoption increases risk without corresponding controls.

---

## Program Roadmap

### Days 1–90: Foundation

**Objective:** Establish AI inventory, acceptable use policy, and basic developer environment controls. Reach Level 2 maturity.

**Key activities:**

1. **AI tool inventory** (Week 1–2)
   - Identify all AI tools currently in use across engineering (IDE plugins, API integrations, internal tooling)
   - Document: tool name, provider, data classification of code/data processed, responsible team
   - Identify shadow AI use: tools in use without security review

2. **Acceptable use policy** (Week 2–3)
   - Draft and publish the developer AI usage policy (see [developer-environment-controls.md](developer-environment-controls.md))
   - Define data classification rules for AI transmission
   - Establish the tooling approval process

3. **Developer environment controls** (Week 3–6)
   - Deploy pre-commit secret scanning to all repositories
   - Configure AI context exclusion for credential files
   - Establish approved package registry mirror (if not already present)
   - Deploy dependency verification pre-commit hook

4. **AI security training** (Week 4–8)
   - Slopsquatting awareness for developers
   - AI acceptable use policy rollout and acknowledgment
   - Incident reporting process for AI-related security events

5. **Baseline metrics** (Week 8–12)
   - Establish baseline for secret scanning coverage, pre-commit hook coverage
   - Document AI tool inventory completeness
   - Identify high-priority gaps for the next phase

**Level 2 exit criteria:**
- AI tool inventory complete and reviewed
- Acceptable use policy published and distributed
- Pre-commit secret scanning deployed across all engineering repositories
- Dependency verification in place for teams using AI coding assistants

---

### Months 3–6: Controls

**Objective:** Implement systematic controls for prompt injection, CI/CD AI integration, and initial agent authorization. Reach Level 3 maturity.

**Key activities:**

1. **Prompt injection defense** (Month 3–4)
   - Implement input sanitization at all CI/CD AI integration points
   - Deploy output schema validation for AI pipeline steps
   - Configure prompt injection detection alerting
   - Review all AI components in CI/CD pipelines against controls in [pipeline-controls.md](pipeline-controls.md)

2. **AI code review security** (Month 4–5)
   - Implement deterministic security scanning as a prerequisite for AI review
   - Configure AI review output as advisory (non-blocking)
   - Define human-in-the-loop requirements for security-sensitive change categories
   - Deploy AI review audit trail

3. **Initial agent authorization** (Month 5–6)
   - Inventory all agents operating in the organization
   - For each agent: document authorized tools, authorized scope, and approval gates
   - Create tool authorization policy YAML for highest-risk agents
   - Implement session-scoped credentials for agent service accounts

**Level 3 exit criteria:**
- Input sanitization deployed at all CI/CD AI integration points
- Output schema validation in place for AI pipeline steps that drive automated actions
- Human-in-the-loop requirements defined and enforced for security-sensitive change categories
- Tool authorization policies in version control for all production agents

---

### Months 6–12: Governance

**Objective:** Implement agent audit trails, forensic readiness, and model supply chain controls. Reach Level 4 maturity.

**Key activities:**

1. **Agent audit trail** (Month 6–8)
   - Implement append-only agent audit trail (see [agent-audit-trail.md](agent-audit-trail.md))
   - Deploy tool execution layer with authorization decision logging
   - Establish audit log retention and tamper protection
   - Verify that audit trail enables answering Five Forensic Questions

2. **Model supply chain governance** (Month 7–9)
   - Establish approved model registry
   - Implement model provenance verification and scanning
   - Define model upgrade approval process
   - Deploy ModelScan or equivalent for all models loaded from external registries

3. **Forensic readiness** (Month 8–10)
   - Assess current Forensics Readiness Score (FRS) against the criteria in [forensics-and-incident-response-framework/docs/agent-forensics/readiness-guide.md](../../../forensics-and-incident-response-framework/docs/agent-forensics/readiness-guide.md)
   - Implement context window capture for production agents
   - Document and test agent incident response playbooks
   - Conduct first tabletop exercise

4. **Production AI operations governance** (Month 10–12)
   - Establish Progressive Autonomy Model for production agents
   - Complete dry-run and shadow mode for any agents targeting Level 2+ autonomy
   - Establish AI Operations Review Board
   - Publish AI security metrics dashboard

**Level 4 exit criteria:**
- Agent audit trail in place, append-only, tamper-resistant, with authorization decision records
- All Five Forensic Questions answerable for production agent sessions
- Model supply chain governance operational (approved registry, provenance verification)
- Forensics Readiness Score Level 4 achieved for all production agents

---

## AI Security Roles and Responsibilities

### Minimum Staffing (Levels 1–3)

**AI Security Lead** (may be embedded in AppSec or Platform Security):
- Owns the AI tool inventory and acceptable use policy
- Reviews AI tool adoption requests
- Monitors prompt injection and slopsquatting alerts
- Maintains developer AI security guidance

### Target Staffing (Levels 3–4)

**AI Security Lead (dedicated 50–100% FTE):**
- Owns all AI security controls and the AI security program roadmap
- Approves new AI tool adoptions and agent deployments
- Leads AI security incident response
- Reports AI security metrics to security leadership

**Platform AI Governance (embedded in Platform Engineering):**
- Implements and maintains tool authorization policy infrastructure
- Manages agent service accounts and session credential lifecycle
- Maintains agent audit trail infrastructure

**Product Security AI Liaison (embedded in each product team with AI features):**
- Reviews AI component designs for security risks
- Ensures product AI components follow framework controls
- Provides security input to AI feature specifications

### Full Staffing (Level 5)

At Level 5, the AI security function expands to include:
- Dedicated AI red team or contracted AI adversarial testing
- AI security architecture review for significant new AI system designs
- AI regulatory compliance liaison (EU AI Act, NIST AI RMF)

---

## Metrics and KPIs

### Level 2 Metrics

| Metric | Definition | Target |
|---|---|---|
| AI inventory coverage | % of AI tools in use that are in the inventory | 100% |
| Pre-commit secret scanning coverage | % of repositories with secret scanning enabled | 100% |
| Acceptable use policy acknowledgment | % of developers who have acknowledged the policy | > 95% |

### Level 3 Metrics

| Metric | Definition | Target |
|---|---|---|
| Slopsquatting detection rate | % of AI-generated dependency suggestions that are verified before commit | 100% |
| Prompt injection alert rate | Number of prompt injection alerts per 1000 CI runs | Track; investigate all |
| AI code review output blocked | Number of times AI code review output was the sole basis for a merge decision | 0 |
| Human-in-the-loop compliance | % of security-sensitive PRs that received required human security review | 100% |

### Level 4 Metrics

| Metric | Definition | Target |
|---|---|---|
| Agent authorization coverage | % of production agents with version-controlled tool authorization policies | 100% |
| Agent audit trail coverage | % of production agent tool calls with full audit records | 100% |
| Forensic readiness score | FRS level for highest-risk production agents | Level 4 |
| Model provenance verification rate | % of model loads with verified provenance | 100% |
| Mean time to detect agent anomaly | Time from anomalous agent behavior to detection | < 10 minutes |

### Level 5 Metrics

| Metric | Definition | Target |
|---|---|---|
| Adversarial testing coverage | % of AI components tested adversarially in the past 12 months | 100% |
| Agent incident MTTR | Mean time to remediate confirmed agent incidents | Track; improve quarterly |
| AI security program maturity | Self-assessed maturity level verified by external review | Level 5, verified annually |

---

## Executive Communication for AI Security Investment

Communicating AI security investment requirements to non-technical leadership requires translating technical controls into business risk terms.

### Risk Framing

AI security risks map to four business risk categories that resonate with executives:

**Supply chain risk:** "Our AI coding tools can suggest package names that don't exist. Adversaries register those names with malware. Without verification controls, our code could include a backdoored dependency that an AI suggested. The same type of supply chain compromise that affected SolarWinds is now automatable at AI speed."

**Data breach risk:** "AI coding assistants transmit code context to external providers. Without data handling policies and exclusion controls, code containing credentials or proprietary algorithms may be transmitted to these providers. If a provider is breached or subpoenaed, that data is at risk."

**Unauthorized action risk:** "AI agents that operate in CI/CD and production can be manipulated into taking actions outside their intended scope through a technique called prompt injection. An adversary who can write to any data source the agent reads can potentially cause the agent to execute unauthorized commands. Without authorization controls, the blast radius of a single injection attack is the agent's full permission scope."

**Compliance risk:** "The EU AI Act, NIST AI RMF, and emerging regulations require organizations to demonstrate controls over AI systems used in consequential processes. Organizations using AI in software delivery without documented controls, audit trails, or governance structures will face increasing compliance gaps as these regulations take effect."

### Investment Justification Template

```
Current state: [Current maturity level, specific uncontrolled risk]
Target state: [Next maturity level, specific controls to implement]
Investment required: [Team time, tooling cost, training cost]
Risk reduced: [Specific risk scenarios that become controlled]
Compliance requirement addressed: [Specific regulation or audit requirement]
Success metric: [How we will know the investment achieved its goal]
```

---

## AI Operations Review Board

The AI Operations Review Board (AIORB) is the governance body responsible for decisions that affect the scope, autonomy level, and risk posture of AI systems operating in the software delivery pipeline. It is distinct from the security team's internal review process — the AIORB includes cross-functional stakeholders and has explicit decision authority over agent deployments.

### Composition

| Role | Responsibility on the AIORB | Required at |
|---|---|---|
| AI Security Lead (chair) | Owns the agenda; presents risk analysis; holds the casting vote on security disputes | All levels |
| Platform AI Governance lead | Represents enforcement feasibility; owns implementation timeline | All levels |
| Legal / Privacy counsel | Reviews regulatory compliance implications; approves audit log retention policies | Level 3+ |
| Compliance / GRC representative | Maps agent capabilities to audit obligations; approves control exceptions | Level 3+ |
| Engineering leadership representative | Represents development velocity interests; approves resource commitments | Level 3+ |
| Product Security AI Liaison | Represents product team AI deployments; surfaces new adoption requests | Level 4+ |

The chair (AI Security Lead) has authority to table a decision if insufficient information is available and to escalate to the CISO or CTO for decisions that exceed the AIORB's scope.

### Decision Authority

The AIORB has authority over:
- Approving or rejecting new agent deployments in production
- Increasing an agent's autonomy level (from advisory to automated action)
- Approving exceptions to the tool authorization policy framework
- Reviewing and accepting the residual risk of agents that cannot meet the standard forensic readiness requirements
- Reviewing and approving significant changes to agent system prompts or tool sets

The AIORB does not have authority over individual security incidents (handled by the IR process) or individual tool authorization policy details (delegated to the AI Security Lead and Platform AI Governance lead).

### Operating Cadence

**Quarterly meeting (standing):** Review all production agents' autonomy levels and authorization policies. Review any policy exceptions granted since the last meeting. Review AI security metrics and any near-miss incidents. Consider new adoption requests not yet approved through the fast-track process.

**Ad-hoc meeting (triggered):** Required within 10 business days of: any confirmed AI-related security incident, a request to increase an agent's autonomy above Level 2 (Supervised), or a new agent deployment in a PCI/HIPAA/regulated scope.

**Decision documentation:** Every AIORB decision is recorded in the AI security risk register with: the decision, the reasoning, the dissenting views (if any), and the review date (when the decision will be revisited). Decisions are not permanent — autonomy approvals expire and must be renewed.

---

## Program Review Cadence

| Review | Frequency | Participants | Output |
|---|---|---|---|
| AI security metrics review | Monthly | AI Security Lead, Security Director | Metrics update; exception review |
| AI tool inventory review | Quarterly | AI Security Lead, platform team leads | Inventory updates; new adoption requests reviewed |
| AI Operations Review Board | Quarterly | See composition above | Agent autonomy level review; policy updates |
| AI security maturity assessment | Annual | Security team | Updated maturity level; next-year roadmap |
| External adversarial testing review | Annual (Level 5) | Security, Red Team | Findings review; remediation plan |

---

## Integration with Existing Security Program

An AI security program does not replace existing security functions — it extends them. Integration points:

**Vulnerability management:** AI-specific vulnerabilities (prompt injection, slopsquatting, model poisoning) must be tracked in the existing vulnerability management system with appropriate severity classification.

**Incident response:** AI agent incidents are handled by the existing IR process with AI-specific playbooks. The forensics capability (Five Forensic Questions, agent audit trail) extends the existing IR toolset.

**Security awareness training:** AI security awareness is added to the existing developer security training program, not delivered separately.

**Change management:** AI tool adoptions go through the existing change management process with an AI-specific security review step added.

**Risk register:** AI security risks are tracked in the existing risk register. The AI Security Lead owns the AI risk entries and updates them at the quarterly review.

---

## Common Failure Modes

**Failure: Shadow AI use grows faster than the program**

Organizations that require approval for AI tools without a fast-track process see developers adopt tools informally to avoid the process. Result: the inventory is always incomplete.

*Correction:* Create a 5-day fast-track path for tool categories with standard risk profiles. Most developer AI coding tools can be approved in 5 days if the provider has a standard data processing agreement. Reserve the full 10-day process for novel tool types or high-sensitivity data access.

**Failure: Controls implemented but not maintained**

Pre-commit hooks that fail silently. Alert rules that route to a closed email list. Authorization policies that are not updated when agents are reconfigured. Result: the program's controls are on paper but not functioning.

*Correction:* Monthly verification of control operational status as a standing agenda item for the metrics review. Each control has an owner and a monthly "is it working?" check.

**Failure: AI security is treated as separate from software supply chain security**

Organizations with mature supply chain security programs sometimes treat AI security as an entirely separate domain. Result: AI tool adoption is not evaluated through the existing supply chain security lens, and AI-specific supply chain risks (model provenance, slopsquatting) are missed.

*Correction:* AI tool adoption review is added as a step in the existing supply chain security process. Model supply chain controls use the same provenance verification tooling (Cosign, SLSA) as software supply chain controls.

**Failure: Metrics without action**

Organizations collect AI security metrics but do not act on them. A pre-commit hook failure rate that has been trending upward for three months with no investigation is a governance failure, not a metrics success.

*Correction:* Each metric has a defined alert threshold. When a threshold is crossed, it generates a named task assigned to a specific person, with a resolution timeline tracked in the next review.
