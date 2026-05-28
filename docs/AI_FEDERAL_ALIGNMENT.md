# AI/Agentic Systems — Federal-Standards Alignment

This document maps the patterns in the `ai-devsecops-framework` to current and emerging federal and international standards for AI system security.

## Primary standards

### NIST AI 100-1 — AI Risk Management Framework (AI RMF 1.0, January 2023)

| AI RMF Function | Framework coverage |
|---|---|
| Govern | Agent authorization model (POLA); ownership and accountability matrices |
| Map | Use-case classification; threat modeling for agentic systems |
| Measure | Auditor Agent pattern; deterministic verification; quality metrics |
| Manage | Runtime policy enforcement; incident response (via forensics framework) |

### OWASP LLM Top 10

| OWASP Issue | Framework mitigation |
|---|---|
| LLM01: Prompt Injection | Deterministic input validation at agent boundary |
| LLM02: Insecure Output Handling | Auditor Agent output validation; runtime policy enforcement |
| LLM03: Training Data Poisoning | Model supply chain integrity (Sigstore for models) |
| LLM04: Model Denial of Service | Rate limiting at Auditor layer; resource quotas |
| LLM05: Supply Chain Vulnerabilities | Cross-reference to `software-supply-chain-security-framework` |
| LLM06: Sensitive Information Disclosure | Auditor pattern + tamper-evident logs |
| LLM07: Insecure Plugin Design | Agent tool authorization (POLA); tool inventory |
| LLM08: Excessive Agency | Auditor Agent enforcement; human-in-the-loop for high-consequence actions |
| LLM09: Overreliance | Output validation; advisory-only positioning |
| LLM10: Model Theft | Model artifact signing; access control |

### EU AI Act (2024)

This framework supports compliance with EU AI Act requirements for high-risk AI systems:
- Article 13 (Transparency): tamper-evident decision logs
- Article 14 (Human oversight): Auditor pattern + human approval gates
- Article 15 (Accuracy, Robustness, Cybersecurity): four-property model
- Article 17 (Risk management system): integrates with NIST AI RMF

### CISA AI Roadmap (November 2023)

Aligned with CISA's recommendations for:
- AI system observability
- Vulnerability disclosure for AI systems
- Federal AI deployment safety standards

## Emerging guidance

### NIST AI 600-1 — Generative AI Profile (July 2024)

This framework supports the Generative AI Profile's recommendations for:
- Confabulation mitigation (Auditor pattern)
- Content provenance (signed outputs)
- Data privacy (input validation + logging policies)

### NIST SP 800-218A — Secure Software Development Practices for Generative AI (April 2024)

The framework's patterns extend the practices in SP 800-218 (SSDF) to AI-specific risks:
- PO-AI: AI risk management integrated into governance
- PS-AI: AI model supply chain controls
- PW-AI: AI-aware code review and testing
- RV-AI: AI-specific incident response (cross-reference to forensics framework)

## How to use this matrix

When responding to compliance questions, RFPs, or audits referencing any of the above:
1. Identify the relevant standard and requirement
2. Locate the corresponding row in this matrix
3. Reference the framework's documentation on the relevant pattern
4. Provide implementation evidence (logs, policy configurations, signed artifacts)

## Update cadence

This document is reviewed quarterly as federal AI guidance evolves rapidly. See `CHANGELOG.md` for revision history.
