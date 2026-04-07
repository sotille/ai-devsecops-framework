# AI Security Architecture for DevSecOps

## Table of Contents

- [The AI Integration Layers Model](#the-ai-integration-layers-model)
- [Security Controls by Layer](#security-controls-by-layer)
- [The Agentic Pipeline Reference Architecture](#the-agentic-pipeline-reference-architecture)
- [The Model as a Supply Chain Component](#the-model-as-a-supply-chain-component)
- [Trust Boundaries in Agentic Systems](#trust-boundaries-in-agentic-systems)
- [Integration with Existing Pipeline Security Controls](#integration-with-existing-pipeline-security-controls)

---

## The AI Integration Layers Model

AI integration in software delivery can be modeled as five layers, each with distinct security characteristics, threat profiles, and required controls. The layers are not strictly sequential — an organization may have AI components at multiple layers simultaneously — but security maturity typically builds from lower layers upward.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 5: Production Operations                                      │
│  AI-driven incident response, autonomous remediation, monitoring     │
│  agents reading logs, metrics, and alerts                            │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 4: Deployment Orchestration                                   │
│  Agents with deploy tool access, approval gate automation,           │
│  environment promotion decisions                                     │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 3: CI/CD Pipeline                                             │
│  AI-invoked security analysis, LLM-generated changelogs,            │
│  vulnerability triage agents, SBOM summarization                     │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 2: Code Review and PR Process                                 │
│  AI review bots reading diffs and PR descriptions,                  │
│  automated suggestion posting, quality gate integration              │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 1: Developer Environment                                      │
│  Coding assistants, IDE plugins, local LLM inference                │
└─────────────────────────────────────────────────────────────────────┘
```

**Layer 1: Developer Environment**

Coding assistants (GitHub Copilot, Cursor, JetBrains AI Assistant, Codeium) operate within the developer's IDE. They receive context from open files, the current project, and recent edits, and return code completions and suggestions. The developer is the human-in-the-loop for every suggestion acceptance.

Security characteristics:
- Context is sent to an external AI provider (or a self-hosted model). That context may include source code, secret values visible in open files, environment variables, and test data.
- The AI suggests package names and API references. Hallucinated package names are an active attack vector (slopsquatting).
- The developer's acceptance behavior determines whether AI-generated code reaches the repository. Trust inversion (accepting AI suggestions at lower scrutiny than equivalent code from an unknown contributor) is a behavioral risk.

**Layer 2: Code Review and PR Process**

AI review bots (CodeRabbit, Codeium Enterprise, custom LangChain agents) receive pull request content — diffs, commit messages, PR titles and descriptions, issue links, linked ticket content — and produce review comments, summaries, and suggestions.

Security characteristics:
- The AI reads user-controlled content (PR descriptions, commit messages) before producing output. This is the primary indirect prompt injection surface at Layer 2.
- Review bots often have repository read access and comment write access. Carefully scoped permissions limit blast radius.
- Code sent to external AI providers during review is a confidentiality concern for proprietary codebases.

**Layer 3: CI/CD Pipeline**

LLM-based components are invoked as pipeline steps. Examples: AI-generated release notes from git history, LLM-powered CVE triage that reads Dependabot output, AI-produced SBOM summaries, context-aware test failure analysis.

Security characteristics:
- AI components receive pipeline artifact content as input (scan results, test output, dependency graphs). These inputs may contain attacker-controlled strings (package descriptions, CVE advisory text).
- Outputs may influence human decisions or feed downstream automated steps. Non-determinism in outputs means they cannot be used as authoritative security gates.
- API keys for model providers are managed as CI/CD secrets and require the same controls as cloud credentials.

**Layer 4: Deployment Orchestration**

Agents with tool access operate within the delivery pipeline. They can invoke deployment tools (Helm, kubectl, Terraform), interact with cloud provider APIs, manage environment promotion decisions, and trigger rollback procedures.

Security characteristics:
- Agents hold credentials sufficient to modify infrastructure. Any compromise of agent behavior — via prompt injection, authorization overreach, or impersonation — can result in unauthorized deployment changes.
- Multi-step agent reasoning chains may execute multiple tool calls before a human reviews the outcome. Each step must be authorized and logged.
- Human approval gates are required before irreversible actions (production deployments, resource deletion, configuration changes).

**Layer 5: Production Operations**

AI-driven monitoring agents read application logs, metrics streams, APM data, and alert feeds. Autonomous remediation agents may restart services, scale resources, modify routing rules, or create incident tickets.

Security characteristics:
- Agents operating in production have the highest blast radius. Authorization boundaries must be strictly enforced.
- Log content and alert messages are attacker-influenced. A threat actor who can write to application logs that a monitoring agent reads has a potential prompt injection vector.
- Autonomous remediation agents must not be able to escalate their own permissions or disable their own audit logging.

---

## Security Controls by Layer

| Layer | AI Component Type | Read Access | Write/Action Access | Key Threats | Required Controls |
|---|---|---|---|---|---|
| L1: Developer Env | Coding assistant | Open files, project context | Code completions (accepted by developer) | Slopsquatting, data exfiltration to provider | SCA with new-package alerting; acceptable use policy; context scoping |
| L2: Code Review | PR review bot | PR diff, commit messages, issue links | Post comments | Indirect prompt injection via PR content | Input sanitization; scoped GitHub token (read+comment only); output anomaly detection |
| L3: CI/CD Pipeline | LLM pipeline step | Scan results, test output, git history | Pipeline logs, generated artifacts | Injection via scan content; non-deterministic gates; API key management | Deterministic validation layer; rate limiting; secrets vault integration |
| L4: Deploy Orchestration | Deployment agent | Environment state, deployment config | Deploy tools, cloud APIs, PRs | Authorization overreach; injection causing unauthorized deploy | Tool authorization policy; human approval gates; immutable audit log; scoped OIDC token |
| L5: Production Ops | Monitoring/remediation agent | Logs, metrics, alerts | Service restarts, scaling, ticketing | Injection via log content; autonomous action blast radius | Strict tool permissions; no self-modification; tamper-evident logging; circuit breaker |

---

## The Agentic Pipeline Reference Architecture

An agentic pipeline is a system where one or more LLM-powered agents take sequences of actions using tools, with an orchestrator coordinating agent activities and a human principal who initiates sessions and approves irreversible actions.

```
┌─────────────────────────────────────────────────────────────────────┐
│  Human Principal                                                     │
│  (Developer / Release Engineer)                                      │
│  Initiates session, approves irreversible actions                    │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ authenticated session (OIDC)
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Orchestrator Agent                                                   │
│  - Holds session context and task instructions                        │
│  - Routes subtasks to specialized agents                              │
│  - Enforces task-scoped authorization policy                          │
│  - Cannot exceed its own tool permission set                          │
└────────┬───────────────────────────┬─────────────────────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────┐        ┌──────────────────────┐
│  Reviewer Agent │        │  Remediation Agent    │
│  (read-only)    │        │  (PR create only)     │
│                 │        │                       │
│  Tools:         │        │  Tools:               │
│  - repo.read    │        │  - pr.create          │
│  - comment.post │        │  - branch.create      │
└────────┬────────┘        └──────────┬────────────┘
         │                           │
         ▼                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Tool Execution Layer                                                 │
│  - Sandboxed execution environment (container per tool invocation)   │
│  - Input validation before tool execution                            │
│  - Output validation after tool execution                            │
│  - Every invocation logged to immutable audit store                  │
└─────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  External Systems                                                     │
│  GitHub API / GitLab API / Cloud Provider APIs / Internal Services   │
│  (accessed via short-lived, scoped credentials per tool)             │
└─────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Immutable Audit Log                                                  │
│  (append-only; agents cannot write to their own audit records)       │
│  Every tool invocation: timestamp, agent_id, tool, input_hash,       │
│  output_hash, duration, policy_version, human_principal              │
└─────────────────────────────────────────────────────────────────────┘
```

Key architectural properties:

**Agent identity is distinct from human identity.** Each agent role has a dedicated service account or OIDC identity. Agents do not share credentials with human users. Agent credentials are scoped to the minimum permissions required for their defined role and expire at session end.

**Tool permissions are declarative and immutable during a session.** An agent's tool access is defined in a tool authorization policy (see [agent-authorization.md](agent-authorization.md)) and cannot be expanded during a session. An agent cannot invoke tools outside its authorized set even if instructed to do so by another agent or by injected content.

**Orchestrator cannot grant subagents more authority than it holds.** The orchestrator's tool permission set is a superset of what it can delegate to subagents. A subagent cannot receive permissions that the orchestrator itself does not have. This prevents privilege escalation via agent-to-agent delegation.

**Irreversible actions require out-of-band human approval.** Before any action that cannot be undone (production deployment, resource deletion, PR merge, configuration change in production), the orchestrator must pause execution, present the pending action to the human principal, and receive explicit approval before proceeding. The approval mechanism is out-of-band from the agent's own tool call chain.

**Every tool invocation is logged to an external, append-only store.** Agents have no write access to the audit log. Log entries include the authorization policy version in effect at the time of the call, enabling forensic reconstruction of what the agent was permitted to do and why it acted as it did.

---

## The Model as a Supply Chain Component

An LLM model used in a pipeline component is a software dependency with a supply chain, and it must be treated with the same rigor applied to other dependencies.

A model has:
- An **origin**: was it published by the original developer? Downloaded from the official registry?
- A **version**: which checkpoint or release was used? Is it pinned?
- A **provenance record**: a model card documenting training data, intended use, known limitations, and evaluation results
- A **hash**: a cryptographic fingerprint that allows verification of model weight integrity
- A **deployment pathway**: how did the model get from the registry to the inference environment?

The model supply chain threat surface includes:

**Model registry compromise** — an attacker who compromises a model registry (Hugging Face, a private registry) can replace a legitimate model with a poisoned version. The poisoned version may produce identical outputs on normal inputs but behave differently when specific trigger inputs are present (backdoor attack).

**Name squatting** — analogous to dependency confusion attacks, an attacker publishes a model with a name similar to a trusted model (e.g., `mistral-7b-security-finetuned` instead of a legitimate fine-tune) to induce downloads of a malicious model.

**Fine-tuning pipeline compromise** — if an organization fine-tunes a base model on internal data, the fine-tuning pipeline itself is a supply chain component. Compromising the training data, the fine-tuning process, or the resulting checkpoint introduces a backdoor into the organization's custom model.

Controls:

```yaml
# Example: model governance policy entry
model_registry:
  approved_models:
    - name: "gpt-4o"
      provider: "openai"
      versions: ["2024-05-13", "2024-08-06"]
      use_cases: ["code-review", "vulnerability-triage"]
      api_endpoint: "https://api.openai.com/v1"
      tls_verification: required
    - name: "meta-llama/Llama-3.1-8B-Instruct"
      provider: "huggingface"
      versions: ["sha256:a1b2c3d4..."]  # Pin to specific commit SHA
      scan_tool: "modelscan"            # https://github.com/protectai/modelscan
      use_cases: ["internal-triage"]
      deployment: "self-hosted"
  governance:
    require_model_card: true
    require_security_scan: true
    scan_tool_version: "modelscan>=0.8.0"
    shadow_model_policy: prohibited     # No personal API keys for unapproved models
    audit_trail: required
```

For self-hosted models, use ProtectAI's `modelscan` tool to scan model weight files for embedded code or serialization exploits before deployment:

```bash
# Install modelscan
pip install modelscan

# Scan a downloaded model before loading
modelscan --path ./models/llama-3.1-8b-instruct/

# Scan a Hugging Face model by repository ID
modelscan --hf_model_id meta-llama/Llama-3.1-8B-Instruct
```

---

## Trust Boundaries in Agentic Systems

An agentic system has multiple trust boundaries, and a security failure at any boundary can compromise the entire chain:

```
Human Principal
    │  (trusted; initiates session; approves irreversible actions)
    │
    ▼  ── Trust Boundary 1: Human → Orchestrator ──────────────────────
Orchestrator Agent
    │  (partially trusted; must not exceed authorized tool set)
    │  (system prompt defines its role and constraints)
    │
    ▼  ── Trust Boundary 2: Orchestrator → Subagent ──────────────────
Subagent
    │  (partially trusted; constrained by delegated permissions)
    │  (subject to indirect injection from data it reads)
    │
    ▼  ── Trust Boundary 3: Agent → Tool ─────────────────────────────
Tool Execution
    │  (sandboxed; validated inputs and outputs)
    │  (credentials scoped to the tool's minimum required access)
    │
    ▼  ── Trust Boundary 4: Tool → External System ────────────────────
External API / Service
    (untrusted; responses must be validated before use in agent context)
```

**Boundary 1 (Human → Orchestrator)** is breached when the orchestrator acts outside its authorized scope without human approval. Mitigation: tool authorization policy enforced at runtime; approval gates for irreversible actions.

**Boundary 2 (Orchestrator → Subagent)** is breached when a subagent receives more permissions than the orchestrator intended or can use injected instructions to exceed its authorization. Mitigation: delegated permissions cannot exceed orchestrator's permissions; policy enforcement is at the tool layer, not just at the agent configuration layer.

**Boundary 3 (Agent → Tool)** is breached when the tool executes with inputs that an attacker crafted (via injection) to produce unintended effects. Mitigation: tool input validation; sandboxed execution; output validation before results are returned to the agent.

**Boundary 4 (Tool → External System)** is breached when external system responses contain adversarial content that the tool passes back into the agent's context without sanitization. Mitigation: treat external system responses as untrusted data; sanitize before including in agent context.

---

## Integration with Existing Pipeline Security Controls

AI security controls extend, rather than replace, the baseline pipeline security controls described in the [Secure CI/CD Reference Architecture](../secure-ci-cd-reference-architecture/).

The relationship between frameworks:

| Concern | Secure CI/CD Reference Architecture | This Framework (Extension) |
|---|---|---|
| Secrets in pipeline | Vault integration, secret scanning, rotation | AI provider API keys; secrets in LLM context window; context exfiltration prevention |
| Pipeline identity | OIDC federation, least-privilege tokens | Agent identity (per-agent OIDC subject); session-scoped tokens; agent cannot share human identity |
| Artifact integrity | Image signing, SBOM, Sigstore | Model signing (emerging); model provenance; model registry controls |
| Audit trail | Pipeline execution logs, job logs | Agent tool call audit trail; system prompt versioning; reasoning chain logging |
| Security gates | SAST/SCA break-the-build criteria | LLM augments deterministic tools; LLM outputs are advisory not authoritative |
| Hardening checklist | secure-pipeline-templates/docs/hardening-checklist.md Section 11 | AI pipeline checklist in pipeline-controls.md |
| Access control | Branch protection, environment protection rules | Tool authorization policy; approval gates for agent actions; agent RBAC |

Teams implementing AI pipeline controls should first ensure the baseline pipeline security controls from the [Secure CI/CD Reference Architecture](../secure-ci-cd-reference-architecture/) are in place. The AI-specific controls in this framework assume that baseline is established and do not repeat it.
