# Changelog

All notable changes to the AI and Agentic Systems Security Framework for DevSecOps are documented here.
Format: `[version] — [date] — [summary of changes]`

---

## [Unreleased]

- [2026-04-07] Integrated into techstream-docs ecosystem index — added to Framework Repository Index table and Mermaid ecosystem map as cross-cutting layer node (AIDF) with edges from devsecops-framework, secure-ci-cd, and supply-chain frameworks; AIDF→FIRF edge added
- [2026-04-07] Added to techstream-docs framework-selection-guide: "Securing AI-assisted development or agentic pipelines" use case path, AI-Native Organization sequence updated (step 1), prerequisites and scope boundaries tables updated
- [2026-04-07] Added "AI agent unauthorized action" incident type and AI/agent systems domain lead to cross-framework-incident-response.md
- [2026-04-07] AI/agentic security terms (Jailbreak, MCP, Model poisoning, Prompt injection, Slopsquatting) added to techstream-books master glossary

---

## [1.0.0] — 2024-01-15

- Initial public release of the AI and Agentic Systems Security Framework for DevSecOps
- Core framework documentation: introduction, architecture, framework, implementation, best-practices, roadmap
- STRIDE threat model applied to AI/LLM systems in DevSecOps pipelines with AI-specific threat categories (jailbreak, slopsquatting, model collapse, specification gaming)
- Six-section control framework: AI-assisted development, prompt injection, agent authorization, pipeline security gates, model supply chain, AI application security
- Full prompt injection defense guide covering the complete DevSecOps pipeline attack surface with defense-in-depth implementation and Python examples
- Agent authorization framework: Principle of Least Authority for agents, tool authorization policy YAML schema, approval gate requirements, Kubernetes RBAC and GitHub Actions implementation
- Agent audit trail specification: minimum viable audit record format, immutable logging patterns for AWS and Kubernetes, system prompt versioning, replay capability
- Pipeline controls: platform-specific guidance for GitHub Actions, GitLab CI, and Jenkins; circuit breaker pattern; AI pipeline security checklist
- 18-month AI security maturity roadmap with five maturity levels
- Apache 2.0 license and contribution guidelines
