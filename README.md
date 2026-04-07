# AI and Agentic Systems Security Framework for DevSecOps

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/techstream/ai-devsecops-framework)
[![Documentation](https://img.shields.io/badge/docs-comprehensive-brightgreen.svg)](docs/)
[![Maintained](https://img.shields.io/badge/Maintained-yes-green.svg)](https://github.com/techstream/ai-devsecops-framework)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A framework for securing AI and LLM systems embedded in the software delivery pipeline — covering AI-assisted development, agentic CI/CD pipelines, prompt injection defense, model supply chain security, and agent authorization governance.

---

## Overview

AI and LLM systems are being embedded into the software delivery pipeline at every layer: coding assistants that generate code, agents that review pull requests, orchestrators that trigger deployments, and RAG systems that read internal documentation. Each integration point introduces security risks that existing DevSecOps frameworks do not fully address.

SAST tools do not detect prompt injection. Software composition analysis does not detect model poisoning. IAM policies were not designed for agents that can dynamically request tool access. Non-deterministic LLM outputs cannot serve as authoritative security gates without deterministic validation layers.

This framework provides threat models, controls, and governance patterns specifically for organizations that use AI in their software delivery pipeline. It starts from the assumption that your team already operates a mature DevSecOps program — the [Techstream DevSecOps Framework](../devsecops-framework/) and [Secure CI/CD Reference Architecture](../secure-ci-cd-reference-architecture/) cover the baseline — and extends those controls to the AI integration surface.

The framework is organized around five primary threat areas: AI-assisted development risks (slopsquatting, hallucinated packages, data exfiltration to AI providers), prompt injection in pipeline components, agent authorization and tool permission governance, model supply chain integrity, and AI application security for LLM-powered product features.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Documentation](#documentation)
- [Repository Structure](#repository-structure)
- [Who Should Use This Framework](#who-should-use-this-framework)
- [Contributing](#contributing)
- [License](#license)
- [Learning Resources](#learning-resources)

---

## Quick Start

### Prerequisites

This framework assumes your organization has:

- An existing DevSecOps program with CI/CD pipeline security controls in place (see [Secure CI/CD Reference Architecture](../secure-ci-cd-reference-architecture/))
- At least one AI tool integrated into the development or delivery workflow (coding assistant, AI review bot, LLM-based pipeline component, or AI-powered product feature)
- Basic familiarity with large language model concepts: prompts, context windows, system prompts, tool use

### Recommended Reading Order

For teams encountering AI security for the first time:

1. **[Introduction](docs/introduction.md)** — Understand why AI in DevSecOps requires dedicated security controls beyond what existing frameworks provide, and how this framework relates to OWASP LLM Top 10 and NIST AI RMF.

2. **[Architecture](docs/architecture.md)** — Study the AI Integration Layers model (developer environment through production operations), the agentic pipeline reference architecture, and trust boundaries in multi-agent systems.

3. **[Threat Model](docs/threat-model.md)** — STRIDE applied to AI/LLM systems in DevSecOps, with concrete attack scenarios, detection signals, and mitigations for each threat category. Start here if your team is assessing a specific AI integration.

4. **[Framework](docs/framework.md)** — The core technical document. Six control sections covering AI-assisted development, prompt injection, agent authorization, pipeline security gates, model supply chain, and AI application security.

5. **[Prompt Injection Defense](docs/prompt-injection-defense.md)** — Full treatment of the primary threat to AI pipeline components, including the complete attack surface in a DevSecOps pipeline and a defense-in-depth implementation guide.

6. **[Agent Authorization](docs/agent-authorization.md)** — Principle of Least Authority for agents, agent role definitions, tool authorization policy as YAML, and approval gate requirements.

7. **[Agent Audit Trail](docs/agent-audit-trail.md)** — Minimum viable audit record format, immutable logging implementation, system prompt versioning, and replay capability for incident investigation.

8. **[Pipeline Controls](docs/pipeline-controls.md)** — Concrete controls for AI components in GitHub Actions, GitLab CI, and Jenkins pipelines, including input sanitization examples and the circuit breaker pattern.

9. **[Implementation](docs/implementation.md)** — Phased implementation guide: 30-day foundation through 180-day continuous assurance.

10. **[Best Practices](docs/best-practices.md)** — Operational guidance for teams running AI pipeline components in production.

11. **[Roadmap](docs/roadmap.md)** — 18-month AI security maturity model with five levels from inventory to continuous assurance.

```bash
# Clone this framework locally
git clone https://github.com/techstream/ai-devsecops-framework.git
cd ai-devsecops-framework

# Begin with the threat model to assess your current AI integration points
# See docs/threat-model.md for STRIDE analysis of each AI component type

# Use the implementation guide's Phase 1 checklist for immediate actions
# See docs/implementation.md — Phase 1 (0-30 days)
```

---

## Documentation

| Document | Description | Audience |
|---|---|---|
| [Introduction](docs/introduction.md) | Why AI in DevSecOps requires dedicated controls; scope; relationship to OWASP LLM Top 10 and NIST AI RMF | All stakeholders |
| [Architecture](docs/architecture.md) | AI Integration Layers model; agentic pipeline reference architecture; trust boundaries; model as supply chain component | Architects, Platform Engineers |
| [Threat Model](docs/threat-model.md) | STRIDE applied to AI/LLM systems; attack scenarios; detection signals; mitigations; AI-specific threat categories | Security Engineers, Architects |
| [Framework](docs/framework.md) | Core technical controls: AI dev, prompt injection, agent authorization, pipeline gates, model supply chain, AI application security | Security Engineers, DevOps leads |
| [Prompt Injection Defense](docs/prompt-injection-defense.md) | Attack surface in DevSecOps pipelines; defense-in-depth; prompt canaries; adversarial testing; Python examples | Security Engineers, Platform Engineers |
| [Agent Authorization](docs/agent-authorization.md) | POLA for agents; agent role taxonomy; tool authorization policy YAML; approval gate requirements; RBAC implementation | Security Engineers, Platform Engineers |
| [Agent Audit Trail](docs/agent-audit-trail.md) | Audit record format; immutable logging; system prompt versioning; replay capability; retention requirements | Security Engineers, Compliance |
| [Pipeline Controls](docs/pipeline-controls.md) | Per-platform AI security controls; AI pipeline checklist; circuit breaker pattern; audit log format | Platform Engineers, DevOps |
| [Implementation](docs/implementation.md) | Four-phase rollout: 0–30 days through 180+ days with concrete actions per phase | DevOps leads, Platform Engineers |
| [Best Practices](docs/best-practices.md) | Operational guidance for AI pipeline components in production | All engineering roles |
| [Roadmap](docs/roadmap.md) | 18-month maturity model; five levels from AI inventory to continuous assurance | Leadership, Program Managers |

---

## Repository Structure

```
ai-devsecops-framework/
├── README.md                        # This file
├── CHANGELOG.md                     # Version history
├── CONTRIBUTING.md                  # Contribution guidelines
├── LICENSE                          # Apache 2.0 license
└── docs/
    ├── introduction.md              # Why AI requires a dedicated framework
    ├── architecture.md              # AI Integration Layers and agentic reference architecture
    ├── threat-model.md              # STRIDE for AI/LLM systems — primary security reference
    ├── framework.md                 # Core control framework by threat category
    ├── prompt-injection-defense.md  # Full prompt injection treatment
    ├── agent-authorization.md       # Agent POLA, tool policy, approval gates
    ├── agent-audit-trail.md         # Audit record format and immutable logging
    ├── pipeline-controls.md         # Concrete CI/CD platform controls
    ├── implementation.md            # Phased implementation guide
    ├── best-practices.md            # Operational best practices
    └── roadmap.md                   # 18-month maturity roadmap
```

---

## Who Should Use This Framework

**Security Engineers and Architects** will find the threat model and framework documents the most operationally valuable. The STRIDE analysis in [threat-model.md](docs/threat-model.md) provides a structured approach to assessing any AI component being added to the delivery pipeline. The framework's control tables map directly to implementation tasks.

**Platform and DevOps Engineers** responsible for CI/CD infrastructure will use [pipeline-controls.md](docs/pipeline-controls.md) and [agent-authorization.md](docs/agent-authorization.md) to implement concrete security controls for AI components running in pipelines. The GitHub Actions, GitLab CI, and Kubernetes RBAC examples are directly applicable.

**Engineering Leads and CISOs** assessing organizational risk from AI tool adoption will find [introduction.md](docs/introduction.md) and [roadmap.md](docs/roadmap.md) most relevant. The maturity model provides a structured language for planning and communicating AI security investments.

**Developers** using AI coding assistants should understand the risks documented in the [Framework](docs/framework.md) Section 1 (AI-Assisted Development Controls), particularly slopsquatting and AI provider data exfiltration.

**Application Security Engineers** building AI-powered product features should review [framework.md](docs/framework.md) Section 6 (AI Application Security) and the OWASP LLM Top 10 cross-references throughout.

**Compliance and Risk Teams** should review [agent-audit-trail.md](docs/agent-audit-trail.md) for audit trail requirements and [framework.md](docs/framework.md) for control mappings relevant to SOC 2, ISO 27001, and emerging AI governance regulations.

---

## Contributing

Contributions are welcome. The AI security landscape is evolving rapidly, and this framework is maintained as a living document. AI threat research, new attack patterns, tool-specific implementation guidance, and corrections to outdated content are all valuable contributions.

See [CONTRIBUTING.md](CONTRIBUTING.md) for documentation standards, the review process, and what types of contributions are accepted.

---

## License

Copyright 2024 Techstream

Licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for the full license text.

You may use, modify, and distribute this framework freely under the terms of the Apache 2.0 License. Attribution to Techstream is appreciated but not required for internal use.

---

## Learning Resources

- **[Book 5: AI Systems Security for DevSecOps](https://www.techstream.app/learn)** — The Techstream volume aligned with this framework when available. For current pipeline security context, see Book 2.
- **[Book 2: Securing CI/CD and the Software Supply Chain](https://www.techstream.app/learn)** — Provides the pipeline security foundation this framework extends.
- **[Hands-On Labs (techstream-learn/)](https://www.techstream.app/learn)** — Practical exercises aligned with Techstream framework content.
- **[Book Series Overview (VOLUMES.md)](../techstream-books/VOLUMES.md)** — Index of all Techstream volumes.
- **[Techstream Platform](https://www.techstream.app)** — Central portal for all Techstream frameworks, documentation, and learning resources.
