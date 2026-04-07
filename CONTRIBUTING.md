# Contributing to the AI and Agentic Systems Security Framework

Thank you for your interest in contributing. The AI security threat landscape evolves rapidly — new attack patterns, emerging tooling, updated model capabilities, and changing attacker techniques mean this framework requires continuous maintenance. Contributions that improve technical accuracy, fill coverage gaps, or add concrete implementation guidance are welcome.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [What We Welcome](#what-we-welcome)
- [What We Do Not Accept](#what-we-do-not-accept)
- [How to Contribute](#how-to-contribute)
- [Documentation Standards](#documentation-standards)
- [Review Process](#review-process)
- [License](#license)

---

## Code of Conduct

All contributors are expected to engage professionally and constructively. Technical disagreements should focus on substance, not individuals. Contributions that are dismissive, personal, or unprofessional will not be reviewed.

---

## What We Welcome

- **New threat scenarios and attack patterns** — the AI attack surface is expanding. If a new prompt injection technique, agent escalation path, model supply chain attack, or AI-specific threat has been documented in research or observed in practice, additions to [threat-model.md](docs/threat-model.md) are highly valuable.
- **Tool-specific implementation guidance** — concrete configuration examples for LLM guardrail tools (Llama Guard, NeMo Guardrails, Presidio), agent frameworks (LangChain, LlamaIndex, AutoGen), and model registries are consistently the most actionable contributions.
- **Platform-specific controls** — implementation guidance for CI/CD platforms not currently covered (Azure DevOps, CircleCI, Tekton), cloud providers not currently covered (Azure, GCP), or agent deployment frameworks.
- **Corrections to outdated content** — AI tooling and APIs change frequently. If a tool has been deprecated, an API has changed, or a configuration example is no longer accurate, corrections are critical.
- **Adversarial testing methods** — specific prompt injection payloads, test cases for agent authorization bypass, and red team exercise formats for AI pipeline components.
- **Compliance mapping additions** — if you can map controls in this framework to FedRAMP, HIPAA, GDPR, or emerging AI governance regulations (EU AI Act, NIST AI RMF), those mappings are valuable.
- **Cross-framework alignment** — if you identify inconsistencies between this framework and the [DevSecOps Framework](../devsecops-framework/), [Secure CI/CD Reference Architecture](../secure-ci-cd-reference-architecture/), or [Software Supply Chain Security Framework](../software-supply-chain-security-framework/), please open an issue.

---

## What We Do Not Accept

- **Vendor promotional content** — tool references must be based on technical merit. This framework references specific tools to illustrate concrete implementations; contributions that read as product marketing will not be accepted.
- **Unverified attack scenarios** — threat model additions must be grounded in documented research, published CVEs, conference presentations, or reproducible proof-of-concept demonstrations. Speculative threats without grounding will not be accepted.
- **Fabricated metrics or case studies** — all examples must be generic and realistic. Do not invent specific performance numbers, client names, or outcome data.
- **AI application security outside the delivery pipeline scope** — this framework covers AI in the software delivery pipeline, not general AI application security for end-user features (beyond the overview in Section 6 of the framework). Contributions in this space should be directed to OWASP LLM Top 10.
- **Breaking changes to the document structure** — major restructuring requires prior discussion in a GitHub Issue before a pull request is opened.

---

## How to Contribute

### Reporting Issues

Use GitHub Issues to report:
- Technical errors or outdated tool/API information
- Missing coverage of important threat scenarios
- Inconsistencies with other Techstream repositories
- Broken links or formatting problems
- Requests for new platform-specific implementation guidance

Include: the specific document and section affected, the problem description, and for technical corrections, a reference or justification.

### Submitting Pull Requests

1. **Fork the repository** and create a branch from `main` with a descriptive name (e.g., `add-langchain-tool-auth-example`, `update-llamaguard-v2-config`, `threat-model-rag-exfiltration`).
2. **Make your changes** following the documentation standards below.
3. **Test your Markdown** — ensure all code blocks are syntactically valid, all internal links resolve, and tables render correctly.
4. **Open a pull request** against `main` with a clear description of:
   - What was changed and why
   - Which section(s) are affected
   - References or sources for new threat scenarios or tool guidance
5. **Respond to review comments** — the core team reviews all pull requests. If changes are requested, please address them or explain your reasoning.

---

## Documentation Standards

All contributions must adhere to the documentation standards maintained across the Techstream framework suite.

### Tone and Style

- Professional, direct, and technical. Avoid marketing language and superlatives.
- Write for a practitioner audience: security architects, DevSecOps engineers, platform engineers, and engineering managers.
- Use active voice and present tense where possible.
- Avoid filler phrases ("It is important to note that...", "As we can see...").
- Be specific: "use Gitleaks with the `--redact` flag" is better than "use a secrets detection tool."

### Technical Accuracy

- All tool names, command syntax, configuration examples, and API references must be accurate for the current stable version of the tool.
- Include version numbers or caveats when guidance is version-specific.
- Code blocks must be syntactically correct and representative of real-world usage. Test your examples.
- For Python examples, specify the Python version and key library versions in comments.

### Markdown Formatting

- Use ATX-style headers (`#`, `##`, `###`).
- Use fenced code blocks with language identifiers (` ```bash `, ` ```yaml `, ` ```python `, ` ```json `).
- Tables should be used for structured comparisons (threat tables, control tables, approval gate matrices). Avoid tables for simple lists.
- Internal links should use relative paths to other files in this repository.
- Cross-repository links should use relative paths to sibling Techstream repositories (e.g., `../devsecops-framework/docs/framework.md`).

### Code Examples

All code examples must meet the following requirements:

- **Executable** — the example should work as written with appropriate credentials/environment.
- **Commented** — non-obvious configuration choices should be explained inline.
- **Minimal** — show only what is necessary to illustrate the security pattern. Strip boilerplate.
- **Safe** — do not include real credentials, internal hostnames, or personally identifiable information. Use `<placeholder>` for values that must be supplied.

### Threat Model Contributions

New entries in [threat-model.md](docs/threat-model.md) must include:

- STRIDE category or AI-specific threat category
- Attack scenario description (concrete, not abstract)
- Detection signals (what observable indicators suggest the attack is occurring)
- Mitigations (specific controls, not general advice)
- Reference to supporting research or documentation where applicable

---

## Review Process

Pull requests are reviewed by the Techstream core team. The review focuses on:

1. **Technical correctness** — is the content accurate and verifiable?
2. **Scope alignment** — does the contribution fit this framework's defined domain (AI in the software delivery pipeline)?
3. **Documentation standards** — does it meet the style, formatting, and code example requirements?
4. **Cross-repository consistency** — does it align with guidance in the [DevSecOps Framework](../devsecops-framework/), [Secure CI/CD Reference Architecture](../secure-ci-cd-reference-architecture/), and [Software Supply Chain Security Framework](../software-supply-chain-security-framework/)?

Most pull requests receive an initial response within 5 business days. Substantive contributions (new threat model entries, major implementation guides) may require multiple review cycles. If a pull request has not received a response within 10 business days, please comment on it to request an update.

---

## License

By contributing to this repository, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE), the same license that covers the existing content. You certify that you have the right to submit the contribution under this license.
