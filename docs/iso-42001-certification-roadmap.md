# ISO/IEC 42001 Certification Roadmap for DevSecOps Organizations

## Table of Contents

- [Overview](#overview)
- [What ISO 42001 Certification Requires](#what-iso-42001-certification-requires)
- [Scoping Decision](#scoping-decision)
- [12-Month Certification Roadmap](#12-month-certification-roadmap)
- [Clause-by-Clause Framework Mapping](#clause-by-clause-framework-mapping)
- [Audit Preparation Checklist](#audit-preparation-checklist)
- [Common Certification Failure Modes](#common-certification-failure-modes)
- [Cost and Effort Estimates](#cost-and-effort-estimates)

---

## Overview

ISO/IEC 42001 (December 2023) defines requirements for an AI Management System (AIMS). Certification demonstrates that an organization has established documented, implemented, and continuously improved governance over its AI systems. It is the AI-specific equivalent of ISO 27001 for information security management systems.

**Who should pursue ISO 42001 certification:**
- Organizations that develop or deploy AI in regulated industries (financial services, healthcare, critical infrastructure)
- Enterprise software vendors whose customers require demonstrated AI governance assurance
- Organizations subject to EU AI Act high-risk classification that need a systematic governance framework
- Organizations where AI governance maturity is a competitive differentiator in enterprise sales

**Who can defer certification:**
- Organizations whose AI use is purely internal, limited-risk, and not customer-facing
- Early-stage companies where the certification effort would divert engineering resources from core product development
- Organizations that have not yet completed the AI integration inventory (MAP 1.1) — certification before inventory is premature

If deferring formal certification, this roadmap still provides a useful governance maturity progression. Implement the clauses as a framework improvement path without pursuing the third-party audit.

---

## What ISO 42001 Certification Requires

ISO 42001 certification is issued by an accredited third-party Certification Body (CB). The certification process includes:

1. **Stage 1 Audit (Documentation Review):** The CB reviews your AIMS documentation to assess whether it meets ISO 42001 requirements. This is conducted remotely in most cases. Findings from Stage 1 must be addressed before Stage 2.

2. **Stage 2 Audit (Implementation Verification):** The CB conducts an on-site (or virtual) audit to verify that documented controls are actually implemented and effective. Auditors interview staff, review records, and test control operation.

3. **Certification Decision:** If no major nonconformities remain, the CB issues a certificate valid for 3 years, subject to annual surveillance audits.

4. **Annual Surveillance Audits:** Lighter-weight reviews confirming continued compliance. Major changes to AI systems or governance must be reported to the CB.

5. **Recertification (every 3 years):** Full audit cycle repeated.

**Typical timeline from start to certificate:** 12–18 months for a mature organization. 18–24 months if significant control gaps exist at the start of the program.

---

## Scoping Decision

Before beginning any implementation work, define the AIMS scope boundary. See `docs/regulatory-decision-trees.md` (ISO 42001 — Scope Boundary Decision section) for the decision tree.

**Scope statement format:**
> The AIMS applies to the design, development, deployment, and operation of AI systems used within [organization name]'s software delivery pipeline, including: [list of specific agent types, AI-integrated tools, and model types]. The scope excludes third-party AI services used as black-box APIs where [organization name] is solely a deployer.

**Scope principles:**
- Narrow the scope to achieve certification faster; you can expand later
- Include all AI systems you develop or fine-tune
- Include all agentic systems where the organization defines the system prompt and tool authorization
- Exclude pure SaaS AI tools where you have no control over model behavior

---

## 12-Month Certification Roadmap

### Month 1–2: Foundation and Scoping

**Objective:** Establish the AIMS organizational structure and complete the AI system inventory.

| Activity | ISO 42001 Clause | Framework Control | Owner |
|----------|-----------------|-------------------|-------|
| Appoint AI governance owner and AIMS program lead | 5.3 | Governance owner field in model registry | CISO or designated AI Security Lead |
| Define AIMS scope boundary | 4.3 | AI integration inventory | AI Security Lead |
| Complete AI system inventory | 4.3, MAP 1.1 | AI integration inventory — enumerate all AI systems in scope | Platform Engineering |
| Conduct context analysis (internal/external issues, stakeholder needs) | 4.1, 4.2 | Regulatory mapping (regulatory-mapping.md); threat model | AI Security Lead + Legal |
| Identify and document interested parties | 4.2 | Stakeholder list: regulators, customers, employees, AI providers | CISO |
| Draft AIMS scope document | 4.3 | Scope statement per template above | AI Security Lead |

**Deliverables:** Signed scope document; initial AI system inventory; stakeholder register; context analysis document.

---

### Month 3–4: Policy and Risk Assessment

**Objective:** Establish documented AI policy, define risk assessment methodology, and complete initial risk assessment.

| Activity | ISO 42001 Clause | Framework Control | Owner |
|----------|-----------------|-------------------|-------|
| Draft and approve AI policy | 5.2 | AI acceptable use policy | CISO + Executive Sponsor |
| Define AI risk assessment methodology | 6.1.2 | Threat model methodology (threat-model.md); STRIDE for LLMs | AI Security Lead |
| Conduct AI risk assessment for all in-scope systems | 6.1.2 | STRIDE analysis per AI system | Security Engineers |
| Define risk treatment options and criteria | 6.1.3 | Control implementation per maturity model | AI Security Lead |
| Draft risk treatment plan | 6.1.3 | Maturity roadmap aligned to risk findings | AI Security Lead |
| Establish AIMS objectives | 6.2 | AI security metrics (program-guide.md — KPIs per maturity level) | CISO |

**Deliverables:** Approved AI policy; risk assessment methodology document; completed risk assessment; risk treatment plan; AIMS objectives register.

---

### Month 5–6: Control Implementation — Core Technical Controls

**Objective:** Implement the technical controls that satisfy ISO 42001 Clauses 8.3–8.5.

| Activity | ISO 42001 Clause | Framework Control | Owner |
|----------|-----------------|-------------------|-------|
| Implement AI system lifecycle controls | 8.4 | Model supply chain (model-supply-chain.md); pipeline controls (pipeline-controls.md) | Platform Engineering |
| Implement data governance for AI | 8.5 | Training data provenance; data classification for AI context | Data Engineering |
| Implement model registry with provenance | 8.4 | Model registry schema with digest verification | Platform Engineering |
| Deploy immutable audit trail | 9.1 | Audit trail implementation (agent-audit-trail.md) — append-only log store | Platform Engineering |
| Implement behavioral monitoring | 9.1 | Behavioral baseline (ai-behavioral-baseline.md in FIRF); behavioral monitoring alerts | Security Engineering |
| Deploy prompt injection controls | 8.4 | Prompt injection defense (prompt-injection-defense.md) — input validation, output schema | AppSec |
| Implement tool authorization policy | 8.4 | Agent authorization (agent-authorization.md) — POLA, approval gates | Platform Engineering |

**Deliverables:** Implemented technical controls; evidence of operation (log samples, configuration records, test results).

---

### Month 7–8: Operational Procedures and Training

**Objective:** Document operating procedures; train staff; establish monitoring and measurement.

| Activity | ISO 42001 Clause | Framework Control | Owner |
|----------|-----------------|-------------------|-------|
| Document AI incident response procedure | 8.6, 10.2 | AI incident response (production-operations.md — incident response procedure) | Security Engineering |
| Conduct AI security awareness training | 7.2, 7.3 | Developer environment controls (developer-environment-controls.md) | Training Team |
| Establish monitoring and measurement program | 9.1 | Behavioral monitoring; adversarial testing cadence; AI security metrics | AI Security Lead |
| Schedule and conduct first adversarial test | 9.1 | Adversarial testing methodology (prompt-injection-defense.md) | Security Engineering |
| Document AI operational procedures | 8.1 | Standard operating procedures for agent deployment, model updates, incident response | Platform Engineering |
| Establish management review cadence | 9.3 | Program review cadence (program-guide.md) | CISO |

**Deliverables:** AI incident response procedure; training completion records; monitoring program documentation; first adversarial test report; management review schedule.

---

### Month 9–10: Internal Audit and Gap Remediation

**Objective:** Conduct internal audit against ISO 42001 requirements; remediate findings before external audit.

| Activity | ISO 42001 Clause | Framework Control | Owner |
|----------|-----------------|-------------------|-------|
| Conduct ISO 42001 internal audit | 9.2 | Internal audit against all AIMS clauses | Internal Audit or designated Lead Auditor |
| Categorize findings (major/minor nonconformity, observation) | 9.2 | Nonconformity log | AI Security Lead |
| Implement corrective actions for all major nonconformities | 10.1, 10.2 | Corrective action plan with owners and dates | AI Security Lead |
| Implement corrective actions for minor nonconformities | 10.1 | Corrective action plan | AI Security Lead |
| Conduct management review | 9.3 | Management review meeting — inputs: audit findings, KPIs, incidents, risk changes | CISO + Executive |
| Update risk assessment based on internal audit findings | 6.1.2 | Risk treatment plan revision | AI Security Lead |

**Deliverables:** Internal audit report; nonconformity log; corrective action plan with evidence of closure; management review minutes.

---

### Month 11: Stage 1 Audit Preparation

**Objective:** Prepare documentation package for Certification Body Stage 1 audit.

**Document package for Stage 1 (required):**

| Document | ISO 42001 Clause | Location |
|----------|-----------------|----------|
| AIMS scope document | 4.3 | Internal governance repo |
| AI policy | 5.2 | Internal governance repo (approved version) |
| AI risk assessment methodology | 6.1.2 | Internal governance repo |
| Risk assessment results | 6.1.2 | Internal governance repo (restricted access) |
| Risk treatment plan | 6.1.3 | Internal governance repo |
| AIMS objectives | 6.2 | Internal governance repo |
| Training records | 7.2 | HR/training system |
| Internal audit report | 9.2 | Internal governance repo |
| Management review minutes | 9.3 | Internal governance repo |
| Corrective action evidence | 10.1 | Internal governance repo |

**Activities:**
- Brief Stage 1 document review with external consultant (optional but reduces Stage 1 findings)
- Confirm all required documented information is available and version-controlled
- Prepare staff briefing on audit protocol (what to expect, who speaks to auditors)
- Address any documentation gaps identified in pre-audit review

---

### Month 12: Stage 1 and Stage 2 Audits

**Stage 1 Audit (typically 1–2 days):**
- Auditors review documentation package
- Stage 1 findings issued within 1–2 weeks
- Address any Stage 1 findings (typically 2–4 weeks remediation time)

**Stage 2 Audit (typically 2–4 days for a mid-size organization):**
- Auditors conduct interviews with AI governance owner, security engineering, platform engineering, and executive sponsor
- Auditors review evidence records (audit trail samples, training logs, incident records, test reports)
- Nonconformities issued at close of Stage 2 — major nonconformities prevent certification

**Post-Stage 2:**
- Address any nonconformities (30–90 days for major, 90+ days for minor)
- Certification decision issued when nonconformities are closed and verified

---

## Clause-by-Clause Framework Mapping

| ISO 42001 Clause | Requirement Summary | Framework Control(s) |
|---|---|---|
| 4.1 — Context | Internal/external AI-related issues and opportunities | Threat model; regulatory-mapping.md |
| 4.2 — Interested parties | Stakeholders and their AI-related requirements | Regulatory mapping; stakeholder register |
| 4.3 — Scope | AIMS boundary definition | AI integration inventory; regulatory-decision-trees.md |
| 5.1 — Leadership | Top management commitment to AIMS | AI policy; governance ownership in model registry |
| 5.2 — Policy | AI policy document | AI acceptable use policy |
| 5.3 — Roles | AIMS roles and responsibilities | Program guide (program-guide.md) — AI security roles |
| 6.1.2 — Risk assessment | AI risk assessment process and results | Threat model (threat-model.md); STRIDE analysis |
| 6.1.3 — Risk treatment | Risk treatment options, plan, acceptance | Maturity roadmap (roadmap.md); control implementation |
| 6.2 — Objectives | AIMS objectives and plans to achieve them | AI security metrics; KPIs (program-guide.md) |
| 7.1 — Resources | Resources for AIMS operation | Staffing models (program-guide.md) |
| 7.2 — Competence | Training and awareness | Developer environment controls; security training records |
| 7.4 — Communication | Internal and external communication | Executive communication framework (program-guide.md) |
| 7.5 — Documented information | AIMS documentation requirements | Version-controlled governance repository |
| 8.1 — Operational planning | Planning, implementing, and controlling processes | Deployment procedures; change management |
| 8.4 — AI system lifecycle | Controls throughout AI system lifecycle | Model supply chain; pipeline controls; agent authorization |
| 8.5 — Data for AI | Data governance for AI training and operation | Training data provenance; data classification |
| 8.6 — Third-party considerations | Third-party AI system risk | Model registry (third-party models); vendor risk assessment |
| 9.1 — Monitoring | Performance monitoring and measurement | Behavioral monitoring; adversarial testing; AI security metrics |
| 9.2 — Internal audit | Internal AIMS audit | Internal audit program; audit evidence |
| 9.3 — Management review | Executive review of AIMS performance | Program review cadence; management review minutes |
| 10.1 — Nonconformity | Corrective action for nonconformities | Incident response; corrective action log |
| 10.2 — Continual improvement | AIMS continual improvement process | Quarterly framework review; maturity roadmap updates |

---

## Audit Preparation Checklist

Before Stage 2, verify all of the following are in place and evidenced:

**Documentation:**
- [ ] AIMS scope document — approved and version-controlled
- [ ] AI policy — approved by top management, distributed to all staff
- [ ] Risk assessment — completed for all in-scope AI systems; results documented
- [ ] Risk treatment plan — with implementation status and residual risk acceptance
- [ ] Internal audit report — completed within last 12 months; findings addressed
- [ ] Management review minutes — completed within last 12 months

**Technical Controls:**
- [ ] AI integration inventory — complete; all in-scope systems listed
- [ ] Model registry — all in-scope models listed with provenance and version records
- [ ] Immutable audit trail — operational; sample audit records retrievable
- [ ] Prompt injection controls — implemented and tested; test evidence available
- [ ] Tool authorization policy — documented per agent type; approval gates operational
- [ ] Behavioral monitoring — alerts configured; alert history available

**Operational Records:**
- [ ] Training completion records — AI security training for all relevant staff
- [ ] Adversarial test report — completed within last 12 months
- [ ] AI incident response procedure — documented; tested via tabletop exercise
- [ ] AI incident log — maintained (even if no incidents; document "no AI incidents in period")

---

## Common Certification Failure Modes

| Failure Mode | Why It Causes Nonconformity | Prevention |
|---|---|---|
| AI inventory incomplete | Auditors will identify AI systems not covered by the AIMS | Complete inventory before scope definition; revisit after organization changes |
| Policy not approved by top management | Clause 5.2 requires top management approval — team-level approval insufficient | Obtain signature from CISO or C-suite; document approval date |
| Risk assessment covers threats but not likelihood/impact | Clause 6.1.2 requires risk assessment, not just threat identification | Use STRIDE analysis with likelihood and impact ratings; document risk level |
| Controls documented but not implemented | Stage 2 auditors verify implementation, not just documentation | Maintain evidence of control operation: log samples, test results, screenshots |
| Behavioral monitoring not measuring against defined thresholds | Clause 9.1 requires demonstrated monitoring and measurement | Implement baseline (ai-behavioral-baseline.md); configure alerts against thresholds |
| No corrective action process | Clause 10.1 requires a defined process for nonconformity | Document corrective action procedure; maintain log with dates and closure evidence |
| Management review too infrequent | Clause 9.3 requires regular management review | Annual minimum; quarterly recommended; document inputs and outputs |

---

## Cost and Effort Estimates

These estimates apply to a mid-size organization (50–500 engineers) deploying 3–8 distinct AI agent types. Actual costs vary significantly by organization size, existing governance maturity, and Certification Body selection.

| Activity | Engineering Effort | External Cost |
|---|---|---|
| Initial inventory and scoping | 2–4 weeks (1 engineer) | — |
| Policy and risk assessment | 4–8 weeks (2 engineers) | Optional: consultant review $5k–$15k |
| Technical control implementation | 8–20 weeks (2–4 engineers) | Tooling costs (logging infrastructure, monitoring) |
| Documentation and procedures | 4–8 weeks (1 engineer) | — |
| Internal audit | 2–4 weeks (1 auditor, internal or external) | External auditor: $15k–$40k if used |
| Stage 1 + Stage 2 external audit | — | $25k–$80k depending on CB and scope size |
| Corrective action remediation | 2–8 weeks (varies by finding severity) | — |
| **Total engineering effort** | **22–52 weeks FTE equivalent** | |
| **Total external cost** | | **$45k–$135k** |

**Annual maintenance after certification:** 4–8 weeks FTE for surveillance audits, documentation updates, and management reviews. Annual CB surveillance audit: $8k–$25k.

---

*Cross-references:* [regulatory-mapping.md](regulatory-mapping.md) — ISO 42001 clause-to-control mapping overview; [regulatory-decision-trees.md](regulatory-decision-trees.md) — AIMS scope boundary decision; [maturity-model.md](maturity-model.md) — Maturity levels referenced in risk treatment planning; [program-guide.md](program-guide.md) — AI security program structure supporting AIMS implementation.
