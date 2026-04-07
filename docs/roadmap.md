# AI Security Maturity Roadmap

## Table of Contents

- [Overview](#overview)
- [Level 1 (Months 1–3): AI Inventory and Basic Controls](#level-1-months-13-ai-inventory-and-basic-controls)
- [Level 2 (Months 3–6): Prompt Injection Hardening](#level-2-months-36-prompt-injection-hardening)
- [Level 3 (Months 6–9): Agentic Security](#level-3-months-69-agentic-security)
- [Level 4 (Months 9–12): Model Supply Chain](#level-4-months-912-model-supply-chain)
- [Level 5 (Months 12–18): Continuous Assurance](#level-5-months-1218-continuous-assurance)
- [Maturity Self-Assessment Checklist](#maturity-self-assessment-checklist)
- [Relationship to Existing Maturity Models](#relationship-to-existing-maturity-models)

---

## Overview

This roadmap defines five maturity levels for AI security in DevSecOps pipelines. Organizations progress through levels sequentially — each level's controls depend on the foundation established by earlier levels.

The roadmap assumes that baseline DevSecOps maturity is already established. Organizations that have not yet implemented the baseline controls from the [Techstream DevSecOps Framework](../devsecops-framework/) should prioritize that foundation before advancing beyond Level 1 of this AI security roadmap.

**Time estimates are guidelines, not commitments.** A small team deploying one AI integration point can move faster. An enterprise with dozens of AI integrations across multiple business units will take longer. The level definitions are the stable reference; the timelines are calibrated for a mid-sized engineering organization (100–500 engineers) with 5–15 AI integration points.

---

## Level 1 (Months 1–3): AI Inventory and Basic Controls

**Objective:** Know what AI tools are in use, apply basic protective controls, and establish the organizational foundation for AI security.

### Capability Requirements

An organization at Level 1 has:

- A complete, current inventory of all AI tools integrated into the development and delivery workflow (see [implementation.md](implementation.md) Phase 1 for inventory methodology)
- Published an AI acceptable use policy covering: approved tools, data handling requirements, developer responsibilities for reviewing AI-generated code
- Extended secrets detection (Gitleaks) with AI provider key patterns and deployed as both pre-commit hook and CI gate
- Configured SCA with dependency confusion detection; alerts when packages resolvable from public registries appear in dependency files
- Removed production deployment access from all AI pipeline components that did not explicitly require it
- Dedicated service accounts for each AI pipeline component (not shared with human users)

### Controls at This Level

| Control | Status at Level 1 | Next Level |
|---|---|---|
| AI integration inventory | Complete | Maintained continuously |
| AI acceptable use policy | Published | Includes agentic-specific guidance |
| AI-generated secrets detection | Deployed | Extended with custom patterns |
| Dependency confusion detection | Deployed | Private registry mirror enforced |
| AI component production access | Restricted | Tool authorization policy |
| AI component identity | Dedicated service accounts | OIDC-based session tokens |

### Key Risk Addressed

The most common immediate harm from AI tool adoption: a developer commits an AI-hallucinated package name that an attacker has registered, or an AI pipeline component with excessive permissions is compromised.

### What Level 1 Does Not Cover

Prompt injection, agent authorization beyond basic permission restriction, model supply chain, and continuous assurance. Organizations should not consider Level 1 sufficient for pipelines with agentic components (Level 4–5 AI Integration Layers).

---

## Level 2 (Months 3–6): Prompt Injection Hardening

**Objective:** Identify every injection surface in the delivery pipeline and deploy controls to make AI pipeline components resilient to indirect prompt injection.

### Capability Requirements

An organization at Level 2 has, in addition to all Level 1 requirements:

- Mapped all data sources read by each AI pipeline component, with injection risk ratings
- Deployed input sanitization for all AI pipeline component inputs (external and user-controlled data)
- Verified that all external data is passed as `user` role content in API calls (not `system` role)
- Deployed output schema validation for all AI pipeline components producing structured output
- Deployed prompt canary tokens in all AI pipeline component system prompts with alerting
- Established behavioral baselines and anomaly alerting for all AI pipeline components
- Run the adversarial test suite from [prompt-injection-defense.md](prompt-injection-defense.md) against all AI pipeline components at least once

### Controls at This Level

| Control | Status at Level 2 | Next Level |
|---|---|---|
| Injection surface mapping | Complete for all current components | Maintained on component changes |
| Input sanitization | Deployed for all components | Refined based on detected patterns |
| Instruction hierarchy | Verified for all API integrations | Tested in adversarial exercises |
| Output schema validation | Deployed for all structured outputs | Anomaly detection on validation failures |
| Prompt canaries | Deployed in all system prompts | Integrated with incident response |
| Behavioral monitoring | Baselines established; alerting active | Monthly review of baselines |
| Adversarial testing | Initial run complete | Quarterly schedule established |

### Key Risk Addressed

Indirect prompt injection via PR descriptions, commit messages, CVE descriptions, and other user-controlled data sources that AI pipeline components read.

### What Level 2 Does Not Cover

The controls at Level 2 address injection resilience but do not provide complete agent authorization governance, model supply chain integrity, or the forensic capability needed for sophisticated incident investigation.

---

## Level 3 (Months 6–9): Agentic Security

**Objective:** Apply rigorous authorization, auditing, and approval controls to agentic systems — AI components that can take actions with tool use.

### Capability Requirements

An organization at Level 3 has, in addition to all Level 2 requirements:

- Documented tool authorization policy as YAML in version control for all agent roles, reviewed by security team
- Tool authorization enforced at the execution layer (not just at the LLM configuration layer)
- Human approval gates implemented for all irreversible agent actions (PRs, deployments, deletions, permission changes)
- Immutable tool call audit trail deployed: every tool invocation logged to an external, append-only store with the minimum audit record fields
- System prompts version-controlled with SHA recorded in session initialization audit records
- Session-scoped tokens: agent credentials expire at session end
- Agents cannot modify their own tool authorization policy, system prompt, or audit log configuration

### Controls at This Level

| Control | Status at Level 3 | Next Level |
|---|---|---|
| Tool authorization policy | Deployed; version-controlled | Continuously reviewed; tested adversarially |
| Policy enforcement | At execution layer | Automated policy compliance checking |
| Approval gates | Implemented for all irreversible actions | Approval audit trail integrated with session audit |
| Immutable audit log | Deployed; external append-only store | Sequence integrity monitoring |
| System prompt versioning | All prompts in git with SHA logging | Automated drift detection |
| Session-scoped credentials | Implemented | Continuous monitoring for persistent token use |
| Self-modification prohibition | Verified | Tested in red team exercises |

### Key Risk Addressed

Agent authorization overreach, agent action non-repudiation, and insufficient forensic capability for agentic systems. Organizations with agents that can take deployment or infrastructure actions require Level 3 controls.

---

## Level 4 (Months 9–12): Model Supply Chain

**Objective:** Govern the models used in the delivery pipeline as supply chain components: provenance, integrity, versioning, and deployment controls.

### Capability Requirements

An organization at Level 4 has, in addition to all Level 3 requirements:

- Maintained an approved model registry: all models used in pipeline components are listed with provider, version, use cases, and governance requirements
- Model provenance verification: model versions are pinned by commit SHA or digest; hash verification runs before model load
- Self-hosted model scanning: `modelscan` runs in the model deployment pipeline for all locally-hosted models
- Model version upgrade process: documented, includes adversarial testing and behavioral comparison
- Shadow model policy: technical controls (network egress filtering) and policy controls preventing use of unapproved AI services on organizational systems
- If fine-tuning is used: fine-tuning pipeline security controls applied; training data provenance tracked
- Model deprecation policy: defined process for replacing models with EoL, security, or quality issues

### Controls at This Level

| Control | Status at Level 4 | Next Level |
|---|---|---|
| Approved model registry | Maintained | Automated compliance checking |
| Model provenance verification | Deployed | Continuous (not just at deployment) |
| Model scanning | In deployment pipeline | In CI and deployment pipeline |
| Upgrade process | Documented and followed | Automated testing and comparison |
| Shadow model controls | Policy + technical | Continuous enforcement |
| Fine-tuning pipeline security | Applied (if applicable) | Data poisoning detection |
| Deprecation policy | Defined | SLA-based automated alerting |

### Key Risk Addressed

Model supply chain attacks: fake models, model tampering, fine-tuning pipeline compromise, and shadow model usage that bypasses security controls.

---

## Level 5 (Months 12–18): Continuous Assurance

**Objective:** Transition AI security from project-based implementation to continuous assurance — ongoing testing, monitoring, and improvement driven by operational data.

### Capability Requirements

An organization at Level 5 has, in addition to all Level 4 requirements:

- Quarterly adversarial testing exercises covering prompt injection, agent authorization, and model supply chain (see [implementation.md](implementation.md) Phase 4)
- Continuous behavioral monitoring for all AI pipeline components with automated alerting
- AI-specific incident response procedures defined, documented, and practiced (tabletop or simulation at least semi-annually)
- Session replay capability verified: tested and documented procedure for reconstructing any agent session from audit logs
- AI security metrics reported in security program reporting (alongside traditional vulnerability and compliance metrics)
- AI integration inventory maintained continuously: new AI tools require security review before deployment
- Annual review of this framework and controls against the current threat landscape

### What Level 5 Looks Like Operationally

At Level 5, AI security is not a project that was completed — it is an ongoing operational capability:
- The security team regularly reviews behavioral anomaly alerts from AI pipeline components
- Red team exercises include AI components as primary targets
- Model version upgrades follow the documented process and are treated as change management events
- New AI tool adoption goes through a security review before deployment
- Security incidents involving AI components are investigated with forensic capability comparable to incidents involving traditional systems
- The AI integration inventory is as current and accurate as the software asset inventory

---

## Maturity Self-Assessment Checklist

Use this checklist to assess your current maturity level. Complete each level's requirements before claiming that level.

### Level 1 Checklist
- [ ] AI tool inventory exists and is current (< 30 days old)
- [ ] AI acceptable use policy published and distributed to engineering teams
- [ ] Gitleaks or equivalent deployed with AI provider key patterns, as pre-commit hook and CI gate
- [ ] SCA tool configured with dependency confusion detection
- [ ] AI pipeline components do not have production deployment access without explicit approval
- [ ] AI pipeline components use dedicated service accounts, not shared credentials

### Level 2 Checklist
- [ ] Data source maps completed for all AI pipeline components
- [ ] Input sanitization deployed for all AI pipeline component inputs
- [ ] All LLM API integrations use `system` role for instructions, `user` role for data
- [ ] Output schema validation deployed for all structured AI outputs
- [ ] Prompt canary tokens deployed in all AI pipeline component system prompts
- [ ] Behavioral baselines established; anomaly alerting active
- [ ] Adversarial test suite run for all AI pipeline components

### Level 3 Checklist
- [ ] Tool authorization policy YAML in version control for all agent roles
- [ ] Tool authorization enforced at execution layer (tested by attempting unauthorized invocations)
- [ ] Human approval gates for all irreversible agent actions (tested)
- [ ] Immutable audit log deployed; agent cannot write to its own log (verified)
- [ ] System prompts in version control; SHA in session audit records
- [ ] Session-scoped credentials implemented; persistent standing tokens eliminated
- [ ] Self-modification prohibition verified for all agents

### Level 4 Checklist
- [ ] Approved model registry maintained
- [ ] All model versions pinned; hash verification before model load
- [ ] `modelscan` in deployment pipeline for self-hosted models
- [ ] Model upgrade process documented and followed for last version change
- [ ] Shadow model controls active (network filtering + policy)
- [ ] Fine-tuning pipeline security controls applied (if fine-tuning is used)
- [ ] Model deprecation policy defined

### Level 5 Checklist
- [ ] Quarterly adversarial testing conducted (evidence of last 4 exercises)
- [ ] Behavioral monitoring active for all AI pipeline components
- [ ] AI incident response procedures documented and practiced (tabletop or simulation)
- [ ] Session replay capability tested in last 6 months
- [ ] AI security metrics in security program reporting
- [ ] AI integration inventory maintained continuously (process documented)
- [ ] Annual framework review against current threat landscape conducted

---

## Relationship to Existing Maturity Models

**Techstream DevSecOps Maturity Model (TDMM):** This AI security maturity model is designed to be used alongside the [TDMM](../devsecops-maturity-model/). An organization should be at TDMM Level 2 or higher before advancing beyond AI Security Level 1.

**NIST AI RMF:** This maturity model provides the technical implementation layer for NIST AI RMF's Govern, Map, Measure, and Manage functions. Level 3 corresponds approximately to NIST AI RMF's "Manage" function maturity for agentic systems. Level 5 corresponds to a continuous AI risk management capability.

**OWASP LLM Top 10:** The OWASP LLM Top 10 threats are addressed across this maturity model:
- LLM01 (Prompt Injection): Levels 2–3
- LLM02 (Insecure Output Handling): Level 2
- LLM03 (Training Data Poisoning): Level 4
- LLM05 (Supply Chain Vulnerabilities): Level 4
- LLM06 (Sensitive Information Disclosure): Levels 2–3
- LLM08 (Excessive Agency): Level 3
- LLM09 (Overreliance): Level 2 (pipeline gate controls)
