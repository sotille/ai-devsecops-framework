# Regulatory and Standards Mapping for AI Security in DevSecOps

## Table of Contents

- [Overview](#overview)
- [EU AI Act](#eu-ai-act)
- [NIST AI Risk Management Framework](#nist-ai-risk-management-framework)
- [OWASP LLM Top 10](#owasp-llm-top-10)
- [ISO/IEC 42001 — AI Management Systems](#isoiec-42001--ai-management-systems)
- [NIST SP 800-218A — Secure Software Development for AI](#nist-sp-800-218a--secure-software-development-for-ai)
- [Unified Control Mapping](#unified-control-mapping)

---

## Overview

Organizations deploying AI in their software delivery pipeline face a growing set of regulatory and standards obligations that were not designed with DevSecOps use cases in mind. This document provides a practical mapping between those external requirements and the controls defined in the AI DevSecOps Framework, to:

1. Identify which framework controls satisfy which regulatory requirements
2. Avoid redundant compliance work across multiple frameworks
3. Identify compliance gaps that require controls not yet present in the organization's security program

This mapping is not legal advice and does not constitute a compliance certification. Organizations must consult legal counsel for authoritative interpretation of applicable regulations.

**Scope:** This mapping covers AI use in the software delivery lifecycle — IDE tools, code review, vulnerability triage, agentic pipeline components, and AIOps. It does not cover AI deployed as a product or service to end customers, which may fall under different regulatory tiers.

---

## EU AI Act

The EU AI Act (effective August 2024, phased application through 2027) establishes a risk-based classification of AI systems. The risk tier determines the applicable compliance obligations.

### Classifying Internal DevSecOps AI Use

**Prohibited (Article 5):** The prohibited practices — real-time remote biometric surveillance, social scoring, manipulation of vulnerable groups — do not apply to DevSecOps AI use cases.

**High-risk (Annex III):** The high-risk categories defined in Annex III are primarily oriented toward AI deployed in critical infrastructure, employment decisions, access to essential services, law enforcement, and biometric identification. Internal DevSecOps AI tools (code review assistants, pipeline security agents) are not classified as high-risk under Annex III in most interpretations.

**Limited-risk (Article 52):** AI systems that interact with natural persons (chatbots, AI-generated content) have transparency obligations — users must be informed they are interacting with an AI. This applies to AI-powered developer tools that interact with engineers (code review bots that post comments, AI triage tools that update tickets).

*Practical implication:* AI pipeline components that post PR comments or update issue trackers should be clearly identified as AI-generated in their outputs. This is good practice independent of regulatory obligation.

**Minimal-risk / General-purpose AI:** AI models accessed through API providers (Anthropic, OpenAI, Google) are subject to the GPAI provisions for providers. As a deployer (not a provider), the organization's obligations under GPAI are more limited — primarily record-keeping for high-capability models and basic transparency requirements.

### Act Obligations Applicable to DevSecOps Deployers

| Obligation | Applicable To | Framework Control |
|---|---|---|
| Transparency for human-facing AI outputs | AI bots posting to GitHub/Jira | Label AI-generated outputs clearly; include "AI" in bot display names |
| Human oversight requirement (high-risk only) | High-risk deployments only | Approval gates (agent-authorization.md) cover this if classification applies |
| Record-keeping for GPAI with systemic risk | Models with >10^25 FLOP training | Registry entry with provider documentation; not directly implementable by deployer |
| Incident reporting to national authority | High-risk deployments involving serious incidents | AI incident response procedures (roadmap.md Level 4) |
| Technical documentation | High-risk deployments | Not generally applicable to DevSecOps internal use |

### EU AI Act Phased Compliance Deadlines

The EU AI Act applies in phases. Organizations must track which obligations are already in force versus those with future application dates.

| Date | Obligation | Applies To |
|------|-----------|-----------|
| **August 2024** | Act enters into force | All |
| **February 2025** | Prohibited practices prohibition (Article 5) | All deployers and providers |
| **August 2025** | GPAI model obligations (Articles 51–55) | GPAI providers only |
| **August 2026** | High-risk AI system obligations (Annexes I and III) | High-risk system deployers and providers |
| **August 2027** | High-risk AI in regulated products (Annex I safety components) | Regulated product manufacturers |

**For most DevSecOps teams deploying internal AI tools:**
- February 2025 is already in effect: do not deploy prohibited practices (none apply to standard DevSecOps AI)
- August 2026 is the relevant high-risk deadline: if any component is classified high-risk, begin conformity assessment preparation by Q4 2025 (12-month lead time for audit and documentation)
- Limited-risk transparency obligations (Article 52) apply from August 2026 but implementing them now costs almost nothing and is recommended as immediate good practice

**Quarterly implementation roadmap for DevSecOps teams (2025–2026):**

| Quarter | Recommended Action |
|---------|-------------------|
| Q1–Q2 2025 | Complete AI integration inventory (MAP 1.1); classify all AI components using the decision tree in regulatory-decision-trees.md; confirm no prohibited practices are deployed |
| Q3 2025 | Implement transparency labeling for all limited-risk components (bot naming, disclosure footers); establish model registry with provenance records |
| Q4 2025 | Begin conformity assessment preparation for any high-risk components; document technical documentation (Annex IV) for high-risk systems; implement Article 12 logging via immutable audit trail |
| Q1–Q2 2026 | Complete high-risk conformity assessment; implement Article 14 human oversight for high-risk systems; finalize registration for EU AI Act public database if required |
| Q3 2026 | August 2026 deadline: all high-risk system obligations in force; validate compliance posture against full Annex III requirements |

---

## NIST AI Risk Management Framework

The NIST AI RMF (January 2023) defines four core functions: **Govern**, **Map**, **Measure**, and **Manage**. The framework is voluntary in the US context but is increasingly referenced in procurement requirements, regulatory guidance, and international standards.

### GOVERN

The Govern function establishes organizational policies, accountability structures, and risk management strategies for AI.

| AI RMF Govern Subcategory | Framework Control | Maturity Level |
|---|---|---|
| GOVERN 1.1 — Policies for responsible AI development | AI acceptable use policy | Level 2 |
| GOVERN 1.2 — Accountability for AI risk | Governance owner field in model registry | Level 4 |
| GOVERN 2.2 — Organizational teams' AI risk awareness | AI security training; threat model documentation | Level 2–3 |
| GOVERN 4.1 — Organizational risk tolerance defined | Risk classification in model registry; approval gate thresholds | Level 4 |
| GOVERN 6.1 — Policies for AI supply chain risk | Model supply chain governance | Level 4 |

### MAP

The Map function identifies context, stakeholders, and risks for specific AI use cases.

| AI RMF Map Subcategory | Framework Control | Maturity Level |
|---|---|---|
| MAP 1.1 — Context established for each AI system | AI integration inventory; use case documentation | Level 2 |
| MAP 2.1 — Scientific basis for AI capability claims | Behavioral baseline documentation | Level 3 |
| MAP 3.5 — Risks from third-party AI components identified | Model registry with provenance; vendor risk assessment | Level 4 |
| MAP 5.1 — Likelihood and magnitude of risks estimated | Threat model (threat-model.md); STRIDE analysis | Level 3 |
| MAP 5.2 — Practices for AI supply chain risk | Model supply chain controls (model-supply-chain.md) | Level 4 |

### MEASURE

The Measure function analyzes and assesses AI risks and controls.

| AI RMF Measure Subcategory | Framework Control | Maturity Level |
|---|---|---|
| MEASURE 1.1 — Methods for measuring AI risks identified | Adversarial testing methodology (prompt-injection-defense.md) | Level 3 |
| MEASURE 2.5 — AI system outputs tested for quality and safety | Output schema validation; behavioral testing | Level 3 |
| MEASURE 2.6 — AI risk metrics established | AI security metrics in program reporting | Level 5 |
| MEASURE 2.8 — AI system impact on humans measured | Approval gates; human oversight requirements | Level 4 |
| MEASURE 4.1 — Measurement approaches reviewed regularly | Annual framework review; quarterly adversarial testing | Level 5 |

### MANAGE

The Manage function prioritizes and addresses identified AI risks.

| AI RMF Manage Subcategory | Framework Control | Maturity Level |
|---|---|---|
| MANAGE 1.3 — Responses to identified AI risks implemented | Control implementation per maturity roadmap | Level 2–4 |
| MANAGE 2.4 — Risk treatment documented | Implementation plan; roadmap documentation | Level 3 |
| MANAGE 3.1 — AI risk and benefit tradeoffs considered | Approval gate risk assessment; blast radius analysis | Level 4 |
| MANAGE 4.1 — Incidents and errors responded to | AI incident response procedures | Level 4 |
| MANAGE 4.2 — Incidents reported and tracked | AI incident tracking; forensic documentation | Level 4–5 |

---

## OWASP LLM Top 10

The OWASP LLM Top 10 (version 1.1, 2023) defines the most critical security risks for LLM-integrated applications. Unlike the regulatory frameworks above, OWASP LLM Top 10 provides direct technical guidance.

| OWASP LLM Risk | Description | Framework Controls | Maturity Level |
|---|---|---|---|
| **LLM01 — Prompt Injection** | Malicious inputs override LLM instructions | Input sanitization, output validation, prompt canaries, behavioral monitoring (prompt-injection-defense.md) | 3 |
| **LLM02 — Insecure Output Handling** | LLM outputs passed to downstream systems without validation | Output schema validation; output sanitization before rendering or execution | 3 |
| **LLM03 — Training Data Poisoning** | Malicious data in training corrupts model behavior | Fine-tuning pipeline security; training data provenance (model-supply-chain.md) | 4 |
| **LLM04 — Model Denial of Service** | Adversarial inputs cause excessive resource consumption | Rate limiting on AI pipeline components; circuit breakers (multi-agent-architecture.md) | 3–4 |
| **LLM05 — Supply Chain Vulnerabilities** | Third-party models or plugins introduce risk | Model registry, integrity verification, ModelScan (model-supply-chain.md) | 2 (inventory), 4 (controls) |
| **LLM06 — Sensitive Information Disclosure** | LLM reveals confidential information from training or context | Data classification for AI context; system prompt confidentiality; context window controls | 3 |
| **LLM07 — Insecure Plugin Design** | Plugins with excessive permissions are exploited | Tool authorization policy; POLA for agent tools (agent-authorization.md) | 4 |
| **LLM08 — Excessive Agency** | LLM takes harmful actions with too much autonomy | Tool authorization policy; approval gates; session scoping (agent-authorization.md) | 4 |
| **LLM09 — Overreliance** | Excessive trust in LLM outputs without validation | Human approval gates for consequential decisions; output schema validation | 3 |
| **LLM10 — Model Theft** | LLM models are extracted or stolen | Model access controls; network egress filtering; shadow model controls | 4 |

### OWASP LLM Top 10 — Implementation Sequence for Resource-Constrained Teams

Not all OWASP LLM Top 10 controls can be implemented simultaneously. The following sequence prioritizes controls by: (a) attack frequency in production DevSecOps environments, (b) implementation effort, and (c) blast radius if exploited.

**Phase 1 — Implement First (Weeks 1–4): Highest frequency, highest blast radius**

| Priority | OWASP LLM Risk | Why First | Minimum Viable Control |
|----------|----------------|-----------|----------------------|
| 1 | **LLM01 — Prompt Injection** | Most frequent attack vector in DevSecOps CI/CD AI; enables all downstream risks | Input sanitization at trust boundaries; output validation schema; prompt canaries |
| 2 | **LLM08 — Excessive Agency** | Autonomous agents acting without authorization can cause immediate, irreversible harm | Tool authorization policy with POLA; approval gates for consequential actions |
| 3 | **LLM05 — Supply Chain Vulnerabilities** | Model or plugin compromise contaminates all downstream outputs; discovered late | Model registry with digest verification; ModelScan in pipeline |

**Phase 2 — Implement Second (Weeks 5–8): Medium frequency, containable blast radius**

| Priority | OWASP LLM Risk | Why Second | Minimum Viable Control |
|----------|----------------|------------|----------------------|
| 4 | **LLM02 — Insecure Output Handling** | Often exploited after LLM01 succeeds; required to contain secondary injection | Output schema validation; sanitize before rendering in browser or executing in shell |
| 5 | **LLM06 — Sensitive Information Disclosure** | Credentials or PII in context window can be extracted via crafted prompts | Data classification for AI context; exclude secrets from context window |
| 6 | **LLM07 — Insecure Plugin Design** | Common in agentic systems with many tools; enables privilege escalation | Tool scope minimization; per-tool authorization; parameter validation |

**Phase 3 — Implement Third (Weeks 9–16): Lower frequency or higher effort to exploit**

| Priority | OWASP LLM Risk | Why Third | Minimum Viable Control |
|----------|----------------|-----------|----------------------|
| 7 | **LLM09 — Overreliance** | Requires process/culture change; technical controls alone insufficient | Human approval gates for consequential decisions; output uncertainty disclosure |
| 8 | **LLM03 — Training Data Poisoning** | Requires access to training pipeline; higher attacker capability threshold | Fine-tuning pipeline security; training data provenance |
| 9 | **LLM04 — Model Denial of Service** | Requires sustained attacker access; contained blast radius | Rate limiting on AI pipeline components; circuit breaker pattern |
| 10 | **LLM10 — Model Theft** | Requires substantial network access; less common in internal DevSecOps deployments | Model access controls; network egress filtering; audit of model API access |

**For teams with limited time:** Implement only LLM01 and LLM08 (Phase 1, items 1 and 2). These two controls prevent the most frequent and highest-severity attacks in internal DevSecOps AI deployments.

---

## ISO/IEC 42001 — AI Management Systems

ISO/IEC 42001 (December 2023) is the international standard for AI management systems, analogous to ISO 27001 for information security. It defines requirements for establishing, implementing, maintaining, and continually improving an AI management system (AIMS).

Organizations subject to ISO/IEC 42001 (or preparing for certification) can use the following mapping:

| ISO 42001 Clause | Requirement | Framework Mapping |
|---|---|---|
| 4.1 — Context of the organization | Understand AI-related obligations and interested parties | AI acceptable use policy; regulatory mapping (this document) |
| 4.3 — Scope of the AIMS | Define the boundary of the AI management system | AI integration inventory; maturity model scope |
| 5.2 — AI policy | Top management AI policy commitment | AI acceptable use policy; governance ownership in model registry |
| 6.1.2 — AI risk assessment | Assess risks to objectives from AI | Threat model (threat-model.md); STRIDE analysis |
| 6.1.3 — AI risk treatment | Treat identified risks | Control implementation per roadmap |
| 8.4 — AI system lifecycle | Controls throughout the AI system lifecycle | Model supply chain; deployment pipeline controls |
| 9.1 — Monitoring and measurement | Monitor and measure AI system performance | Behavioral monitoring; adversarial testing; AI security metrics |
| 10.2 — Nonconformity and corrective action | Address AI incidents and nonconformities | AI incident response procedures; forensic capability |

ISO 42001 certification requires a third-party audit and is not directly achievable through this framework alone. This framework provides the technical controls that satisfy the implementable requirements of ISO 42001 Clauses 6, 8, and 9.

---

## NIST SP 800-218A — Secure Software Development for AI

NIST SP 800-218A (September 2023) extends the Secure Software Development Framework (SSDF) with practices specific to AI-enabled software and AI components. It is directly relevant to organizations that develop or integrate AI components into software delivery pipelines.

Key practices from SP 800-218A relevant to DevSecOps AI integration:

| Practice | Description | Framework Control |
|---|---|---|
| PW.1.3 — AI component risk assessment | Assess risks introduced by AI components before integration | Threat model; STRIDE analysis; maturity assessment |
| PW.4.4 — Train/test data protection | Protect training and test datasets | Fine-tuning pipeline security; training data provenance |
| PW.5.1 — AI component security testing | Test AI components for security vulnerabilities | Adversarial testing methodology; output validation |
| PO.3.2 — AI component inventory | Maintain inventory of AI components and dependencies | AI integration inventory; model registry |
| RV.1.3 — AI-specific vulnerability monitoring | Monitor for vulnerabilities in AI models and dependencies | Model deprecation process; shadow model controls |

---

## GDPR Interaction with AI Regulatory Obligations

Organizations operating in the EU (or processing EU personal data) face a dual obligation: AI-specific regulations (EU AI Act, ISO 42001) and data protection law (GDPR). These obligations are not always aligned. The following matrix identifies the conflicts most likely to arise in DevSecOps AI deployments and provides resolution guidance.

### Conflict Matrix

| Conflict | EU AI Act / ISO 42001 Obligation | GDPR Obligation | Resolution |
|---|---|---|---|
| **Audit trail retention vs. right to erasure** | Article 12 (high-risk): automatic logging for the system's operational lifetime | Article 17: right to erasure upon withdrawal of consent or end of necessity | Apply Article 17(3)(b) exception: erasure does not apply where retention is required by Union or Member State law. Article 12 logging for high-risk systems creates this legal retention requirement. Implement pseudonymization of personal identifiers in audit logs to limit erasure scope. |
| **Training data for fine-tuning** | NIST SP 800-218A PW.4.4: protect training data; ISO 42001 Clause 8.4: lifecycle controls | Article 5(1)(b): purpose limitation — personal data collected for one purpose cannot be reused for another | Conduct a legitimate interest assessment or obtain specific consent before using operational personal data as fine-tuning training data. Prefer synthetic data or anonymized datasets for fine-tuning. |
| **Behavioral monitoring and data minimization** | NIST AI RMF MEASURE 2.6: establish risk metrics; behavioral monitoring | Article 5(1)(c): data minimization — collect only what is necessary | Define a minimum viable behavioral log that captures tool call sequences, authorization decisions, and anomaly indicators without logging personal data content (e.g., log file names accessed, not file contents; log query patterns, not query results). |
| **Adversarial testing with real user data** | NIST AI RMF MEASURE 1.1: test AI risks; adversarial testing methodology | Article 5(1)(b): purpose limitation; Article 9: special category data prohibition | Use synthetic datasets or differential privacy techniques for adversarial testing. If real data is required, obtain a specific legal basis (contractual necessity, legitimate interest with DPIA). |
| **Model output transparency vs. trade secret protection** | EU AI Act Article 13: transparency for deployers; ISO 42001 Clause 5.2: AI policy disclosure | GDPR Article 15: right of access to automated decision-making logic (Article 22) | For automated decisions with legal or significant effect, GDPR Article 22 requires meaningful information about the logic involved. This does not require disclosing proprietary model weights, but does require explaining the decision logic in human-understandable terms. |
| **Agent audit trail cross-border transfer** | EU AI Act Article 12: tamper-evident logging for operational lifetime | GDPR Chapter V: restrictions on personal data transfers outside the EEA | Store audit logs in EEA-resident immutable storage (e.g., AWS S3 in EU regions with Object Lock). If cross-region replication is used for DR, apply Standard Contractual Clauses (SCCs) or equivalent mechanism for the replication destination. |

### Recommended Implementation Pattern: GDPR-Compliant AI Audit Trail

The audit trail schema in [agent-audit-trail.md](agent-audit-trail.md) is designed to satisfy both Article 12 logging requirements and GDPR data minimization obligations. Key design principles:

1. **Pseudonymize human principals in audit records.** Log the agent's service account identifier and the human principal's role or team, not personal identifiers. Maintain a separate, access-controlled mapping table that links pseudonymous IDs to individual identities.

2. **Avoid logging personal data content.** Log the existence and type of data accessed (e.g., `file_type: "source_code"`, `data_classification: "internal"`), not the content. Log query patterns and result counts, not result content.

3. **Apply separate retention policies to different audit record types.** Security-relevant audit records (authorization decisions, anomaly events) may have longer retention under legitimate interest; operational telemetry records that contain personal data should be subject to shorter retention and automated deletion.

4. **Document the retention basis.** Each log category in the audit trail should have an associated record in the data processing register (Article 30 GDPR), specifying the legal basis, retention period, and erasure mechanism.

---

## Unified Control Mapping

The following table maps key controls from this framework to their corresponding obligations across all frameworks covered in this document. Use this table to identify which controls simultaneously satisfy multiple obligations, enabling efficient compliance.

| Framework Control | Maturity Level | EU AI Act | NIST AI RMF | OWASP LLM | ISO 42001 | SP 800-218A |
|---|---|---|---|---|---|---|
| AI integration inventory | 2 | Deployer obligations | MAP 1.1 | LLM05 | 4.3, 5.2 | PO.3.2 |
| AI acceptable use policy | 2 | Transparency | GOVERN 1.1 | — | 5.2 | — |
| Input sanitization | 3 | — | MAP 5.1 | LLM01 | 8.4 | PW.5.1 |
| Output schema validation | 3 | — | MEASURE 2.5 | LLM02, LLM09 | 9.1 | PW.5.1 |
| Behavioral monitoring | 3 | — | MEASURE 2.6 | LLM01 | 9.1 | — |
| Adversarial testing | 3 | — | MEASURE 1.1 | LLM01, LLM02 | 9.1 | PW.5.1 |
| Tool authorization policy | 4 | Human oversight | GOVERN 4.1 | LLM07, LLM08 | 8.4 | — |
| Approval gates | 4 | Human oversight | MANAGE 2.4 | LLM08, LLM09 | 8.4 | — |
| Immutable audit trail | 4 | — | MANAGE 4.1 | — | 9.1 | — |
| Model registry | 4 | GPAI record-keeping | GOVERN 6.1 | LLM05 | 4.3 | PO.3.2 |
| Model integrity verification | 4 | — | MAP 3.5 | LLM05 | 8.4 | RV.1.3 |
| Model scanning (ModelScan) | 4 | — | MAP 5.2 | LLM05 | 8.4 | PW.5.1 |
| AI incident response | 4 | Incident reporting | MANAGE 4.1 | — | 10.2 | RV.1.3 |
| AI security metrics | 5 | — | MEASURE 2.6 | — | 9.1 | — |
| Quarterly adversarial testing | 5 | — | MEASURE 4.1 | — | 9.1 | PW.5.1 |

---

*Cross-references:* [maturity-model.md](maturity-model.md) — Maturity level definitions used in this document; [roadmap.md](roadmap.md) — Implementation sequencing for the controls mapped above; [threat-model.md](threat-model.md) — STRIDE threat analysis referenced by NIST AI RMF MAP function.
