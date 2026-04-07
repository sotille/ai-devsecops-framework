# Introduction: Why AI in DevSecOps Requires a Dedicated Framework

## Table of Contents

- [The AI Integration Surface](#the-ai-integration-surface)
- [Why Existing Controls Are Necessary But Not Sufficient](#why-existing-controls-are-necessary-but-not-sufficient)
- [The Spectrum of AI Integration](#the-spectrum-of-ai-integration)
- [The Trust Inversion Problem](#the-trust-inversion-problem)
- [Scope of This Framework](#scope-of-this-framework)
- [Relationship to OWASP LLM Top 10 and NIST AI RMF](#relationship-to-owasp-llm-top-10-and-nist-ai-rmf)

---

## The AI Integration Surface

Every place AI touches the software delivery pipeline is a new attack surface. This is not a theoretical concern — it is a direct consequence of how LLMs work and how they are being deployed.

Consider a typical organization that has adopted AI tooling across its engineering function:

- Developers use GitHub Copilot or Cursor to generate code, which is then committed to source repositories
- An AI review bot (CodeRabbit, Codeium, or a custom LangChain agent) analyzes pull requests and posts comments
- A CI/CD pipeline step uses an LLM to generate human-readable summaries of dependency vulnerability scan results
- A security triage agent processes incoming CVE notifications and Dependabot alerts, assigning priority labels
- A monitoring agent reads application logs and Slack messages to identify anomalies and page on-call engineers
- The product itself includes an AI assistant that retrieves context from internal documentation via RAG

Each of these integrations creates what this framework calls an **AI integration point**: a location where LLM inputs or outputs interact with the delivery pipeline. Each integration point has a distinct threat profile:

- What data does the AI component read? (source code, commit messages, issue titles, CVE descriptions, log files)
- What actions can it take? (post comments, merge PRs, trigger deployments, modify labels, send alerts)
- What identities and credentials does it hold? (API keys, cloud IAM roles, GitHub tokens)
- Who or what controls its behavior? (system prompt, tool configuration, orchestrator instructions)

The **AI integration surface** is the union of all these integration points. Unlike the traditional attack surface — which is bounded by network perimeter, authentication systems, and known API endpoints — the AI integration surface includes every data source an AI component reads, because that data can influence the AI's behavior.

An attacker who can write a GitHub issue title, a commit message, a README file, or a CVE description now has a potential vector into your AI pipeline. This is the defining characteristic of the AI integration surface and the primary reason existing DevSecOps controls are insufficient.

---

## Why Existing Controls Are Necessary But Not Sufficient

Existing DevSecOps controls remain required. They are not replaced by AI-specific controls — they are extended. But they do not cover the threats introduced by AI integration:

**Static Application Security Testing (SAST)** analyzes source code for known vulnerability patterns. It cannot detect prompt injection embedded in a commit message that will be read by an AI review bot. It cannot identify that a system prompt has been modified to alter agent behavior.

**Software Composition Analysis (SCA)** identifies known vulnerabilities in declared dependencies. It cannot detect model poisoning — a fine-tuned model with a backdoor introduced into the training process. It does not analyze model weights or model cards.

**Secrets Detection** (Gitleaks, Trufflehog) identifies credential patterns in source code and history. It can partially address AI-generated placeholder secrets that resemble real credentials, but it does not address the risk of secrets being exfiltrated through the context window of an AI coding assistant.

**IAM and RBAC** controls access based on identity. Agents present a new challenge: an agent can be prompted to invoke a tool it is legitimately authorized to use with parameters that produce unauthorized effects. Authorization policy must be enforced at the tool-call level, not just at the identity level.

**Audit Logging** captures user and system actions. It does not capture the reasoning chain of an LLM agent, the system prompt in effect at the time of an action, or the full context window that influenced a decision. Standard audit logs are insufficient for AI forensics.

**CI/CD Security Gates** enforce deterministic pass/fail criteria based on tool outputs. LLM outputs are non-deterministic — the same input can produce different outputs across invocations. A security gate that relies on an LLM's judgment rather than the deterministic output of a SAST or SCA tool can be manipulated or can produce inconsistent results.

The table below summarizes existing control coverage against AI-specific threats:

| Threat | SAST | SCA | Secrets Detection | IAM/RBAC | Audit Logging | Covered by This Framework |
|---|---|---|---|---|---|---|
| Prompt injection in pipeline | No | No | Partial | No | No | Yes |
| Slopsquatting / hallucinated packages | No | Partial | No | No | No | Yes |
| AI provider data exfiltration | No | No | No | No | No | Yes |
| Agent authorization overreach | No | No | No | Partial | No | Yes |
| Model supply chain compromise | No | No | No | No | No | Yes |
| Non-deterministic security gates | N/A | N/A | N/A | N/A | N/A | Yes |
| Agent action non-repudiation | No | No | No | No | Partial | Yes |

---

## The Spectrum of AI Integration

AI integration in software delivery exists on a spectrum from passive assistance to full autonomy. Security requirements differ significantly at each level:

**Level 1 — AI-Assisted Development**
Coding assistants (GitHub Copilot, Cursor, JetBrains AI) suggest code completions and generate function implementations within the developer's IDE. The developer reviews and accepts or rejects every suggestion. The AI has no direct access to the pipeline — its outputs are only as dangerous as the human who commits them. Primary risks: slopsquatting, hallucinated credentials, context sent to external AI providers.

**Level 2 — AI in Code Review**
AI review bots analyze pull requests and post comments, suggestions, or summaries. The AI reads repository content (code diffs, commit messages, PR descriptions, issue links) and writes to the PR. It typically cannot merge, approve, or trigger CI/CD runs. Primary risks: indirect prompt injection via PR content, confidentiality of code sent to AI providers, AI suggestions being accepted without appropriate scrutiny.

**Level 3 — AI in CI/CD Pipelines**
LLM-based components are invoked as pipeline steps. Examples: AI-generated changelog summaries, LLM-powered vulnerability triage, AI-produced release notes. The AI reads pipeline artifacts (SBOM, scan results, test reports) and produces text outputs. Primary risks: non-deterministic outputs used as security gates, injection via scan result content, API key management.

**Level 4 — Agentic Pipelines**
Agents with tool access operate within the delivery pipeline. They can invoke defined tools (create PRs, post comments, update labels, trigger workflows, call external APIs). They may be orchestrated by a parent agent. Primary risks: prompt injection causing unauthorized tool invocations, agent authorization overreach, agent impersonation, inadequate audit trails, approval gate bypass.

**Level 5 — Autonomous Delivery**
Agents operate with significant autonomy — merging PRs, deploying to staging, triggering rollbacks, modifying infrastructure. Human approval gates exist but may be asynchronous. Primary risks: all Level 4 risks amplified; irreversible actions with insufficient controls; autonomous incident response actions with cascading effects.

Most organizations operate across multiple levels simultaneously. Understanding where each AI component sits on this spectrum is the first step toward applying appropriate controls.

---

## The Trust Inversion Problem

In a conventional code review process, a developer writes code and a human reviewer applies skepticism before approving it. The reviewer does not assume the code is correct — they examine it, question it, and often reject it.

When an AI coding assistant generates code, the trust relationship frequently inverts. Developers tend to accept AI-generated code at higher rates than they would accept equivalent code from an unfamiliar external contributor. The cognitive effort of reviewing feels lower because the code appears plausible and is presented inline in the development environment.

This trust inversion has two manifestations:

**Developer trust in AI-generated code**: Developers accept AI-suggested imports, package names, and API calls without verifying that the referenced packages and APIs exist and are legitimate. This is the mechanism behind slopsquatting attacks — the AI suggests a plausible-sounding package name that does not exist, an attacker registers it as a malicious package, and the developer accepts the suggestion and commits it.

**Pipeline trust in LLM outputs**: Automated pipeline components that consume LLM outputs often treat those outputs as authoritative. An LLM that analyzes a vulnerability scan and produces a priority rating may have that rating used to make merge decisions, with no deterministic verification layer. The non-deterministic nature of LLM outputs — and their susceptibility to injection — means they should never be treated as authoritative without deterministic validation.

The framework principle derived from this problem is: **treat AI outputs as advisory, not authoritative, for any security-relevant decision**. LLMs augment human and deterministic tool judgment; they do not replace it.

---

## Scope of This Framework

This framework covers **AI in the software delivery pipeline**: every AI component involved in developing, reviewing, testing, building, deploying, or operating software.

**In scope:**
- AI coding assistants and their integration with developer workflows
- AI-powered code review bots and PR analysis
- LLM-based CI/CD pipeline components (triage, summarization, analysis)
- Agentic systems with tool access operating in the delivery pipeline
- Model supply chain security for models used in pipeline components
- AI-powered incident response and autonomous remediation
- AI application features when they are part of the delivery pipeline infrastructure (internal tooling, developer portals)

**Out of scope:**
- AI application security for end-user-facing product features (see OWASP LLM Top 10 for application-level controls)
- AI model development, training infrastructure, and MLOps security (separate domain)
- General LLM red teaming unrelated to the delivery pipeline
- AI regulation compliance beyond what is relevant to the pipeline security controls described here

The [Techstream DevSecOps Framework](../devsecops-framework/) and [Secure CI/CD Reference Architecture](../secure-ci-cd-reference-architecture/) cover the baseline security controls for pipelines that do not involve AI components. This framework assumes those controls are in place and extends them.

---

## Relationship to OWASP LLM Top 10 and NIST AI RMF

**OWASP LLM Top 10** (https://owasp.org/www-project-top-10-for-large-language-model-applications/) is an application security framework focused on risks in LLM-powered applications exposed to end users. It covers prompt injection, insecure output handling, training data poisoning, model denial of service, supply chain vulnerabilities, sensitive information disclosure, insecure plugin design, excessive agency, overreliance, and model theft.

This framework and OWASP LLM Top 10 are complementary:
- OWASP LLM Top 10 is primarily oriented toward AI as a product feature exposed to external users
- This framework is oriented toward AI as a component within the software delivery infrastructure, used by internal engineering teams and automated pipeline processes
- Concepts like prompt injection (LLM01), training data poisoning (LLM03), model supply chain (LLM05), and excessive agency (LLM08) appear in both frameworks, but the attack scenarios, threat actors, and mitigations differ significantly when the target is a delivery pipeline rather than a customer-facing application

Where OWASP LLM Top 10 coverage is relevant to the delivery pipeline context, this framework provides cross-references.

**NIST AI Risk Management Framework (NIST AI RMF)** (https://www.nist.gov/artificial-intelligence/executive-order-safe-secure-and-trustworthy-artificial-intelligence) provides a broad framework for managing AI risk across four functions: Govern, Map, Measure, Manage. It is governance-oriented and applies across AI use cases.

This framework maps to NIST AI RMF at the implementation layer:
- NIST AI RMF's **Map** function (identifying AI risks) maps to [threat-model.md](threat-model.md) in this framework
- NIST AI RMF's **Measure** function (analyzing and assessing risk) maps to the control assessment approach in [framework.md](framework.md)
- NIST AI RMF's **Manage** function (prioritizing and implementing risk responses) maps to [implementation.md](implementation.md) and [roadmap.md](roadmap.md)
- NIST AI RMF's **Govern** function (organizational practices) maps to the governance controls in [framework.md](framework.md) Sections 3 and 5

Organizations required to demonstrate NIST AI RMF compliance for federal contracts or regulated industries can use this framework's control catalog as the technical implementation layer beneath NIST AI RMF's governance structure.
