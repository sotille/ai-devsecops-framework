# Regulatory Classification Decision Trees for AI in DevSecOps

## Table of Contents

- [Purpose](#purpose)
- [EU AI Act — Risk Tier Classification](#eu-ai-act--risk-tier-classification)
- [EU AI Act — Common DevSecOps Scenarios Resolved](#eu-ai-act--common-devsecops-scenarios-resolved)
- [NIST AI RMF — Function Prioritization for Resource-Constrained Teams](#nist-ai-rmf--function-prioritization-for-resource-constrained-teams)
- [ISO 42001 — Scope Boundary Decision](#iso-42001--scope-boundary-decision)
- [Multi-Framework Conflict Resolution](#multi-framework-conflict-resolution)

---

## Purpose

[regulatory-mapping.md](regulatory-mapping.md) maps framework controls to regulatory obligations. This document answers the decision questions that precede that mapping — specifically:

- Under the EU AI Act, what risk tier does a given DevSecOps AI component fall into?
- Which NIST AI RMF functions should be implemented first given limited resources?
- What AI systems fall within an ISO 42001 AIMS scope boundary?
- When two regulations conflict, which obligation prevails?

Use these decision trees before applying the control mappings in `regulatory-mapping.md`. Incorrect risk tier classification is the most common source of either over-investment (treating a limited-risk tool as high-risk) or regulatory exposure (treating a high-risk deployment as minimal-risk).

---

## EU AI Act — Risk Tier Classification

### Decision Tree

Start at Step 1 for every AI component in your DevSecOps pipeline.

```
STEP 1 — Does the component fall under a prohibited practice (Article 5)?
  ├─ YES → Component is PROHIBITED. Do not deploy.
  │         Prohibited: real-time remote biometric surveillance in public spaces;
  │         social scoring by public authorities; subliminal manipulation of vulnerable groups;
  │         exploitation of age or disability; predictive policing solely based on profiling.
  │         None of these apply to standard DevSecOps AI use cases.
  └─ NO → Proceed to Step 2.

STEP 2 — Is this a General Purpose AI (GPAI) model you are PROVIDING (not deploying)?
  ├─ YES → Apply GPAI obligations (Article 51–55). Requires transparency, copyright policy,
  │         technical documentation, and systemic risk assessment if >10^25 FLOP.
  │         This tree does not apply further — consult legal for GPAI provider compliance.
  └─ NO (you are a DEPLOYER of a third-party model) → Proceed to Step 3.

STEP 3 — Does the component appear in Annex III high-risk categories?
  Annex III categories include:
  (a) Biometric identification or categorization
  (b) Critical infrastructure management (water, gas, electricity, transport)
  (c) Education and vocational training
  (d) Employment, worker management, or access to self-employment
  (e) Access to essential private/public services and benefits
  (f) Law enforcement
  (g) Migration, asylum, border control
  (h) Administration of justice and democratic processes
  ├─ Clearly YES → HIGH-RISK. Apply full Annex III obligations.
  │                Go to: High-Risk Obligations Checklist.
  ├─ Clearly NO → Proceed to Step 4.
  └─ AMBIGUOUS → Apply the Annex III Disambiguation Test below.

STEP 4 — Does the component interact directly with natural persons?
  ├─ YES → LIMITED-RISK (Article 52). Transparency obligation applies.
  │         Users must be informed they are interacting with an AI.
  │         Go to: Limited-Risk Obligations Checklist.
  └─ NO → MINIMAL-RISK. No specific EU AI Act obligations beyond GPAI deployer
           record-keeping. Apply as general good practice.
```

---

### Annex III Disambiguation Test

Category (d) — Employment, Worker Management, and Access to Self-Employment — is the Annex III category most likely to apply in DevSecOps contexts. Apply this test:

```
ANNEX III (d) DISAMBIGUATION TEST

Question A: Does the AI component make or substantially influence a decision that
            affects a natural person's employment status, working conditions,
            or access to self-employment opportunities?
  ├─ YES → HIGH-RISK under Annex III (d). See High-Risk Obligations Checklist.
  └─ NO  → Proceed to Question B.

Question B: Does the AI component rank, score, or categorize individual employees
            in a way that has employment consequences (performance review, work
            allocation, discipline)?
  ├─ YES → HIGH-RISK under Annex III (d).
  └─ NO  → Proceed to Question C.

Question C: Does the component operate autonomously on tasks previously performed
            by a human worker, where the output directly determines workload,
            scheduling, or task assignment for individual employees?
  ├─ YES → Likely HIGH-RISK. Consult legal counsel for definitive classification.
  └─ NO  → Not high-risk under Annex III (d). Continue to Step 4 of the main tree.
```

**DevSecOps-specific interpretations of Annex III (d):**

| Scenario | Classification | Rationale |
|----------|---------------|-----------|
| AI code review agent that posts PR suggestions | Not high-risk | Does not make employment decisions; a human developer accepts or rejects suggestions |
| AI agent that automatically closes PRs or tickets | Not high-risk | Automated administrative action on artifacts, not on employment status |
| AI vulnerability triage agent that prioritizes security work queues | Not high-risk | Influences task prioritization, not employment decisions |
| AI system that evaluates developer productivity and feeds into performance reviews | HIGH-RISK | Directly influences employment conditions (performance assessment) |
| AI pipeline agent that autonomously assigns issues to specific developers | Ambiguous — consult legal | May constitute worker management depending on enforcement consequences |
| AI agent that triggers automated PIP (Performance Improvement Plan) criteria | HIGH-RISK | Directly affects employment status |

---

### High-Risk Obligations Checklist

If a component is classified high-risk under Annex III:

- [ ] **Risk management system** (Article 9): Establish and maintain a documented risk management process for the AI system's lifecycle
- [ ] **Data governance** (Article 10): Ensure training data is relevant, representative, and free of errors; document data governance procedures
- [ ] **Technical documentation** (Article 11 + Annex IV): Maintain documentation covering: general description, intended purpose, interaction with other systems, training methodology, validation and testing procedures
- [ ] **Record-keeping** (Article 12): Enable automatic logging of operations for the lifetime of the system; logs must be tamper-evident
- [ ] **Transparency for deployers** (Article 13): Provide clear instructions for use; document capabilities and limitations
- [ ] **Human oversight** (Article 14): Design the system to allow effective human oversight; provide stop and override mechanisms
- [ ] **Accuracy, robustness, cybersecurity** (Article 15): Test for accuracy and cybersecurity throughout lifecycle
- [ ] **Conformity assessment** (Article 43): Conduct conformity assessment before placing on the market or putting into service
- [ ] **Registration** (Article 49): Register the system in the EU AI Act public database before deployment

**Framework controls that satisfy high-risk obligations:**

| Obligation | Framework Control |
|---|---|
| Article 12 — Automatic logging | Immutable audit trail (agent-audit-trail.md) — append-only audit record with session reconstruction capability |
| Article 14 — Human oversight | Approval gates (agent-authorization.md) — human confirmation required for consequential actions |
| Article 15 — Cybersecurity | Adversarial testing methodology (prompt-injection-defense.md); behavioral monitoring |
| Article 11 — Technical documentation | Threat model (threat-model.md); model registry entries |
| Article 9 — Risk management | STRIDE analysis; maturity model risk assessment |

---

### Limited-Risk Obligations Checklist

If a component is classified limited-risk (interacts with natural persons):

- [ ] **Transparency disclosure** (Article 52(1)): Users must be clearly informed that they are interacting with an AI system, unless this is obvious from context
- [ ] **Disclosure format requirements**: Disclosure must be provided at the latest at the first interaction; must be in clear language appropriate to the audience

**Implementation in DevSecOps contexts:**

A PR comment posted by an AI code review agent satisfies Article 52 if:
- The bot account name contains "bot", "ai", or "assistant" (e.g., `security-review-bot`)
- The comment header or footer includes a statement such as: `*AI-generated analysis — review and judgment required from human reviewer*`
- The organization's engineering handbook documents that AI tools post to code review systems

A Jira or GitHub Issue comment posted by an AI triage agent satisfies Article 52 if:
- The author field shows a service account clearly identified as AI-operated
- Issue comments include a disclosure line

---

## EU AI Act — Common DevSecOps Scenarios Resolved

The following scenarios are resolved for reference. These represent the most common classification questions in internal DevSecOps AI deployments.

| AI Component | Risk Tier | Basis |
|---|---|---|
| GitHub Copilot or similar IDE code completion | Minimal-risk (GPAI deployer) | No interaction with natural persons in real-time regulated context; purely suggestive |
| AI-powered PR description generator | Limited-risk | Posts content visible to developers; must disclose AI authorship |
| AI security vulnerability scanner in CI | Minimal-risk | No human-facing output in the regulated sense; output consumed by pipeline |
| AI triage agent that labels and assigns issues | Limited-risk | Posts comments visible to developers; disclose AI authorship in bot account name |
| AI-powered developer productivity scoring for management | HIGH-RISK (Annex III d) | Employment/worker management decision influence |
| Autonomous remediation agent (creates PRs, runs tests, merges) | Minimal-risk by classification; HIGH operational risk | Not Annex III high-risk per se, but requires strong authorization controls under Article 9 risk management good practice |
| AI coding assistant trained on proprietary internal code | Minimal-risk (GPAI deployer) | You are the deployer, not the provider; no high-risk categorization applies |
| AI agent that reviews and approves/rejects access requests | HIGH-RISK (Annex III e) | Affects access to essential services (employment systems, internal tooling access) |

---

## NIST AI RMF — Function Prioritization for Resource-Constrained Teams

The NIST AI RMF defines four functions: Govern, Map, Measure, Manage. For organizations that cannot implement all functions simultaneously, the following sequencing is recommended based on risk reduction per implementation effort:

### Recommended Implementation Sequence

```
PHASE 1 (Weeks 1–4) — GOVERN: Establish policy foundation
  Priority: GOVERN 1.1 (AI policy), GOVERN 4.1 (risk tolerance), GOVERN 6.1 (supply chain policy)
  Why first: Without governance policy, all downstream controls lack organizational authority.
             These three subcategories establish the minimum policy basis for all other functions.
  Framework controls: AI acceptable use policy; model registry (governance owner field);
                      model supply chain governance (model-supply-chain.md)

PHASE 2 (Weeks 5–8) — MAP: Inventory and context
  Priority: MAP 1.1 (context), MAP 5.1 (risk estimation), MAP 3.5 (third-party risk)
  Why second: You cannot Measure or Manage what you have not Mapped.
              Inventory of AI components is the prerequisite for all subsequent controls.
  Framework controls: AI integration inventory; threat model (threat-model.md); STRIDE analysis

PHASE 3 (Weeks 9–16) — MEASURE: Establish baselines
  Priority: MEASURE 2.5 (output testing), MEASURE 1.1 (risk measurement methods)
  Why third: Testing AI outputs and establishing adversarial test baselines is the highest
             leverage Measure control before production deployment.
  Framework controls: Output schema validation; adversarial testing (prompt-injection-defense.md)

PHASE 4 (Ongoing) — MANAGE: Operationalize response
  Priority: MANAGE 4.1 (incident response), MANAGE 4.2 (tracking), MANAGE 1.3 (risk treatment)
  Why fourth: Incident response and risk treatment build on the inventory and baseline
              established in Map and Measure.
  Framework controls: AI incident response procedures; forensic capability (agent-forensics.md);
                      approval gates (agent-authorization.md)
```

**For teams with < 2 engineering weeks available:** Implement only GOVERN 1.1 (AI acceptable use policy) and MAP 1.1 (AI integration inventory). These two controls provide the minimum defensible posture and are prerequisites for everything else.

---

## ISO 42001 — Scope Boundary Decision

Before implementing ISO 42001 controls, define the AIMS scope boundary. Use this test:

```
SCOPE BOUNDARY TEST

Question 1: Is this AI system designed, developed, or deployed by the organization?
  ├─ YES → Include in AIMS scope.
  └─ NO  → Exclude from scope (it is a third-party provider system).
            Document the third-party provider's own certifications in your supply chain register.

Question 2: Does the AI system have a defined organizational owner accountable for its behavior?
  ├─ YES → Include in AIMS scope.
  └─ NO  → Assign an owner before including. Unowned AI systems cannot be managed under ISO 42001.

Question 3: Does the AI system interact with or influence external stakeholders or data subjects?
  ├─ YES → Include in AIMS scope (higher priority for conformity assessment).
  └─ NO  → Include in AIMS scope but lower priority; internal tooling requires the same
            governance but carries lower external risk.

Question 4: Is the AI system used only by employees within the organization's control?
  ├─ YES → Internal AIMS scope. Full controls apply; external disclosure not required.
  └─ NO  → External AIMS scope. Additional transparency requirements apply under Article 13.
```

**Practical scope boundaries for DevSecOps organizations:**

| System | In Scope? | Notes |
|--------|-----------|-------|
| Internal AI code review agent | Yes | Deployed and operated by the organization |
| GitHub Copilot (SaaS product) | No (deployer record-keeping only) | Microsoft is the provider; you are the deployer |
| Custom fine-tuned model for vulnerability triage | Yes | Organization is both developer and deployer |
| Pre-trained foundational model accessed via API | No (API usage only) | Provider handles ISO 42001 obligations for the model itself |
| Agentic pipeline component in CI/CD | Yes | Organization deploys and configures the agent behavior |

---

## Multi-Framework Conflict Resolution

Some regulatory obligations appear to conflict with each other. The following table resolves the most common conflicts for DevSecOps AI deployments.

| Conflict | Frameworks | Resolution |
|----------|-----------|------------|
| **Audit trail retention vs. GDPR right to erasure** | EU AI Act Article 12 vs. GDPR Article 17 | Apply Article 17(3)(b): right to erasure does not apply where retention is necessary for compliance with a legal obligation. If Article 12 requires audit trail retention (e.g., for a high-risk system), that obligation overrides erasure requests. Implement pseudonymization of personal data in audit logs to minimize GDPR exposure while preserving forensic integrity. |
| **NIST AI RMF MEASURE vs. privacy-preserving AI testing** | NIST AI RMF MEASURE 2.5 vs. GDPR Article 5(1)(b) (purpose limitation) | Use synthetic data or differential privacy techniques for adversarial testing where personal data would otherwise be required. Document the privacy-preserving approach in the AI risk assessment. |
| **ISO 42001 transparency vs. security through obscurity** | ISO 42001 Clause 5.2 vs. operational security practices | ISO 42001 transparency requirements apply to policy and governance, not to system prompt content or security control implementation details. Publish the AI policy and governance framework; keep system prompt specifics and security control configurations internal. |
| **EU AI Act Article 14 human oversight vs. autonomous pipeline operation** | EU AI Act Article 14 vs. operational efficiency | Article 14 applies to high-risk systems only. For minimal-risk or limited-risk pipeline components, human oversight is good practice but not legally mandated. For high-risk systems, implement approval gates (agent-authorization.md) to satisfy Article 14 without blocking non-critical pipeline operations. |
| **GDPR data minimization vs. NIST AI RMF comprehensive logging** | GDPR Article 5(1)(c) vs. NIST AI RMF MANAGE 4.2 | Log what is necessary for incident response and regulatory compliance (tool call parameters, authorization decisions, data access summaries) without logging raw personal data content. Define a log schema that satisfies MANAGE 4.2 without violating GDPR data minimization. The audit record schema in agent-audit-trail.md implements this balance. |

---

*Cross-references:* [regulatory-mapping.md](regulatory-mapping.md) — Control mapping to satisfy obligations identified by this decision tree; [agent-authorization.md](agent-authorization.md) — Human oversight implementation (Article 14); [agent-audit-trail.md](agent-audit-trail.md) — Automatic logging implementation (Article 12); [iso-42001-certification-roadmap.md](iso-42001-certification-roadmap.md) — Certification timeline for ISO 42001 AIMS.
