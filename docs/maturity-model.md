# AI Security Maturity Model

## Table of Contents

- [Overview and Purpose](#overview-and-purpose)
- [Level 1 — AI-Naive](#level-1--ai-naive)
- [Level 2 — AI-Aware](#level-2--ai-aware)
- [Level 3 — AI-Defended](#level-3--ai-defended)
- [Level 4 — AI-Governed](#level-4--ai-governed)
- [Level 5 — AI-Secure](#level-5--ai-secure)
- [Assessment Methodology](#assessment-methodology)
- [Relationship to Other Frameworks](#relationship-to-other-frameworks)

---

## Overview and Purpose

The AI Security Maturity Model defines five levels of organizational capability for operating AI components safely within a DevSecOps delivery pipeline. It provides:

- A common assessment language for communicating AI security posture to technical and non-technical stakeholders
- A sequenced implementation path — controls at higher levels depend on the foundation established at lower levels
- A gap analysis framework for identifying the highest-leverage control investments at any given maturity state

The model applies to organizations using AI tools in any part of the software delivery lifecycle: IDE code completion, AI-powered code review, LLM-based vulnerability triage, automated remediation agents, and AIOps. The scope is intentionally bounded to AI in the delivery pipeline — it does not cover AI in production applications or AI as a business service.

**Prerequisite:** This model assumes that baseline DevSecOps maturity is established. Organizations that have not implemented the foundational controls from the [Techstream DevSecOps Framework](../../devsecops-framework/) should prioritize that foundation before advancing beyond Level 1 of this AI security model. Specifically, TDMM Level 2 or higher is recommended before attempting Level 2 of this model.

The detailed implementation roadmap, timeline guidance, and level-specific checklists are documented in [roadmap.md](roadmap.md). This document defines the maturity model itself; the roadmap provides implementation sequencing.

---

## Level 1 — AI-Naive

**Definition:** AI tools are in active use but the organization has not inventoried them, established specific security controls governing their use, or assigned responsibility for AI security.

**Characteristics:**
- No formal inventory of AI tools integrated into the development or delivery workflow
- No AI acceptable use policy
- AI pipeline components (if any) share service accounts with human users or other systems
- No AI-specific secrets detection (AI provider API keys not in detection patterns)
- No dependency confusion detection; slopsquatting risk unmitigated
- Production access of AI pipeline components has not been reviewed or restricted

**Risks at this level:** Exfiltration of AI provider credentials via secrets scanning misses, supply chain compromise via AI-hallucinated package names (slopsquatting), excessive blast radius if any AI pipeline component is compromised.

**Transition to Level 2:** Complete all Level 2 checklist items documented in [roadmap.md](roadmap.md).

---

## Level 2 — AI-Aware

**Definition:** The organization knows what AI tools it uses, has published basic governance policies, and has deployed foundational protective controls.

**Required capabilities:**
- Complete, current inventory of all AI tools integrated into the development and delivery workflow (updated within the last 30 days)
- Published AI acceptable use policy covering: approved tools, data handling requirements, developer obligations for reviewing AI-generated code, reporting requirements for AI-related security concerns
- Secrets detection (Gitleaks or equivalent) extended with AI provider key patterns, deployed as both pre-commit hook and CI gate
- SCA tool configured with dependency confusion detection and private registry preference where applicable
- AI pipeline components restricted from production deployment access unless explicitly required and approved
- Dedicated service accounts for each AI pipeline component; no shared credentials with human users

**What Level 2 does not cover:** Input manipulation defense (prompt injection), agent authorization beyond basic permission restriction, model supply chain integrity, forensic capability.

---

## Level 3 — AI-Defended

**Definition:** AI pipeline components are treated as untrusted integration points with systematic controls on their inputs and outputs. Prompt injection is specifically addressed.

**Required capabilities (in addition to Level 2):**
- All data sources read by each AI pipeline component have been mapped with injection risk ratings
- Input sanitization deployed for all AI pipeline component inputs where external or user-controlled data is processed
- All LLM API integrations use the `system` role for static instructions and the `user` role for variable data; untrusted content is never interpolated into system prompts
- Output schema validation deployed for all AI pipeline components producing structured output (JSON, YAML, structured reports)
- Prompt canary tokens embedded in all AI pipeline component system prompts, with alerting on canary exposure
- Behavioral baselines established for all AI pipeline components; anomaly alerting active
- Adversarial test suite from [prompt-injection-defense.md](prompt-injection-defense.md) run against all AI pipeline components at least once

**What Level 3 does not cover:** Agent tool authorization governance, model supply chain, and continuous assurance.

---

## Level 4 — AI-Governed

**Definition:** Agentic systems are governed by explicit authorization policies enforced at the execution layer. Model supply chain integrity is verified. Forensic capability for agent incidents is established.

**Required capabilities (in addition to Level 3):**

*Agent authorization (applies to all AI agents that can invoke tools):*
- Tool authorization policy expressed as YAML in version control for all agent roles, reviewed by the security team
- Tool authorization enforced at the tool execution layer (not just at LLM configuration); unauthorized tool calls are blocked and logged
- Human approval gates implemented and tested for all irreversible agent actions (PR creation, merges, deployments, deletions, permission changes)
- Immutable tool call audit trail: every tool invocation logged to an external, append-only store with the minimum audit record fields defined in [agent-authorization.md](agent-authorization.md)
- System prompts version-controlled; git SHA of system prompt recorded in session initialization audit records
- Session-scoped credentials: agent tokens expire at session end; no persistent standing permissions for agents
- Verified that agents cannot modify their own tool authorization policy, system prompt, IAM role, or audit log configuration

*Model supply chain:*
- Approved model registry maintained: all models used in pipeline components listed with provider, version, and use case
- Model versions pinned by digest or commit SHA; hash verification before model load
- `modelscan` (or equivalent) deployed in the pipeline for self-hosted models
- Model version upgrade process documented and followed for all version changes
- Shadow model controls: network egress filtering and policy prevent use of unapproved AI services on organizational systems

*Forensic capability:*
- Incident response procedures defined for AI agent incidents covering the Five Forensic Questions framework (see [forensics-and-incident-response-framework](../../forensics-and-incident-response-framework/docs/agent-forensics.md))
- Session replay capability: procedure for reconstructing any agent session from audit logs documented and tested

**What Level 4 does not cover:** Continuous assurance — the ongoing operational capability to maintain controls against an evolving threat landscape.

---

## Level 5 — AI-Secure

**Definition:** AI security is a continuous operational capability, not a completed project. Controls are continuously validated, threats are actively monitored, and the program improves based on operational data.

**Required capabilities (in addition to Level 4):**
- Quarterly adversarial testing exercises covering prompt injection, agent authorization, and model supply chain attacks — with documented results and remediation actions
- Continuous behavioral monitoring for all AI pipeline components with automated anomaly alerting and defined escalation paths
- AI-specific incident response procedures practiced at tabletop or simulation level at least semi-annually
- Session replay capability tested in the last six months with a documented procedure
- AI security metrics included in security program reporting: slopsquatting detection rate, agent authorization coverage, forensic readiness score, mean time to detect AI-related incidents
- AI integration inventory maintained continuously: new AI tool adoption requires a security review before deployment, with documented approval
- Annual framework review against the current threat landscape, incorporating findings from adversarial testing, incident response, and external threat intelligence

**Operational indicators of Level 5:**
- The security team regularly reviews behavioral anomaly alerts from AI pipeline components as part of normal security operations
- Red team exercises include AI components as primary or secondary targets
- Model version upgrades follow the documented process and are treated as change management events, not routine maintenance
- New AI tool adoption goes through a documented security review before deployment
- AI-related security incidents are investigated with forensic capability comparable to incidents involving traditional systems

---

## Assessment Methodology

**Assessment principles:**
- Maturity level is the highest level at which **all** checklist items are satisfied. Partial satisfaction of a level does not count.
- Assessments should be conducted by the security team with input from platform engineering, not self-reported by engineering teams.
- Each checklist item requires documented evidence (policy files, configuration screenshots, audit records, test results), not attestation alone.
- Assessment results should be reviewed against the evidence annually or following a significant AI security incident.

**Assessment process:**
1. Gather evidence for all items at the claimed current level
2. For each item, determine: Satisfied (evidence demonstrates compliance), Partial (partially implemented), or Not Satisfied (not implemented or no evidence)
3. Identify the current level as the highest level where all items are satisfied
4. Identify the gap items at the next level as the basis for the advancement roadmap
5. Document the assessment with evidence references and a timestamp

The complete assessment checklist is in [roadmap.md](roadmap.md#maturity-self-assessment-checklist).

---

## Relationship to Other Frameworks

**Techstream DevSecOps Maturity Model (TDMM):** This model is designed to be used alongside the [TDMM](../../devsecops-maturity-model/). TDMM provides the baseline DevSecOps maturity structure; this model extends it with AI-specific controls. TDMM Level 2 is recommended before advancing beyond AI Security Level 1.

**NIST AI RMF:** This model provides the technical implementation layer for NIST AI RMF's Govern, Map, Measure, and Manage functions. Level 3 corresponds approximately to NIST AI RMF "Manage" maturity for agentic systems. Level 5 corresponds to continuous AI risk management capability.

**OWASP LLM Top 10 coverage:**

| OWASP LLM Threat | Addressed At Level |
|---|---|
| LLM01 — Prompt Injection | 3 (input sanitization, output validation) |
| LLM02 — Insecure Output Handling | 3 (output schema validation) |
| LLM03 — Training Data Poisoning | 4 (model supply chain) |
| LLM05 — Supply Chain Vulnerabilities | 2 (inventory), 4 (model supply chain) |
| LLM06 — Sensitive Information Disclosure | 3 (data handling controls) |
| LLM08 — Excessive Agency | 4 (tool authorization policy, approval gates) |
| LLM09 — Overreliance | 3 (human gate requirements for consequential actions) |

**EU AI Act:** Organizations subject to the EU AI Act should cross-reference AI security level requirements with the Act's risk classification tiers. High-risk AI system requirements align most directly with Level 4 governance controls. See [regulatory-mapping.md](regulatory-mapping.md) for the full control mapping.
