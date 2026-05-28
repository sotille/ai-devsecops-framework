# The Auditor Agent Pattern

This document is the repo-resident reference for the Auditor Agent architectural pattern. The full discussion appears in the May 2026 Medium article *"Why Your AI Agent Is the Next SolarWinds: Supply Chain Security for the Agentic Era."*

## The pattern in one sentence

For every AI agent that proposes an action (Executor Agent), there exists a separate, independently-trusted Auditor Agent that validates the proposed action against deterministic policies BEFORE the action takes effect.

## Why this matters

AI agents are non-deterministic. They can hallucinate, be manipulated via prompt injection, or simply make errors that a human reviewer would catch. Treating an AI agent's output as authoritative without independent verification is the same architectural mistake as treating an unsigned binary as trustworthy because "we built it."

## The four properties of an Auditor Agent system

| Property | What it provides |
|---|---|
| 1. Deterministic input validation | A non-AI verifier ensures the inputs to the Executor Agent are well-formed and within policy bounds |
| 2. Signed agent provenance | The Executor Agent's identity, version, and source are cryptographically verifiable (Sigstore for agents) |
| 3. Tamper-evident decision logs | Every Executor Agent decision is logged in an append-only, transparency-style log (Rekor-like for agent decisions) |
| 4. Runtime policy enforcement | The Auditor Agent rejects any Executor action that violates policy, BEFORE the action is committed |

## Implementation reference

### Property 1 — Deterministic input validation

- Use a non-AI policy engine (OPA/Rego, Cedar, Kyverno) at the agent's input boundary
- Validate: schema, value ranges, allowed operations, resource limits
- Reject input that does not pass deterministic checks BEFORE the agent sees it

### Property 2 — Signed agent provenance

- Sign agent code (the LLM is one input; the prompt, tools, and runtime config are also inputs)
- Use Sigstore-style keyless signing tied to OIDC identity
- Verify signature at agent startup AND at every invocation

### Property 3 — Tamper-evident decision logs

- Every agent decision (input, reasoning chain, output, tool calls, final action) recorded in append-only log
- Log signed by the agent's identity
- Optional: publish to a transparency log analogous to Rekor for cryptographic auditability

### Property 4 — Runtime policy enforcement

- Auditor Agent runs separately from Executor Agent
- Auditor evaluates the Executor's proposed action against policy
- Auditor MUST be able to reject the action (block, not warn)
- High-consequence actions (financial transactions, infrastructure changes, data deletion) require additional human approval gate

## What this is NOT

- It is NOT a second LLM acting as a "judge" — Auditor must use deterministic policy logic, not AI
- It is NOT just logging — Auditor must have enforcement authority
- It is NOT compatible with full agent autonomy — that is the point

## Federal-standards alignment

| Standard | Relevance |
|---|---|
| NIST AI 100-1 (AI RMF) | Govern, Map, Measure, Manage — Auditor pattern operationalizes Measure + Manage |
| OWASP LLM Top 10 | Mitigates LLM01 (Prompt Injection), LLM02 (Insecure Output Handling), LLM07 (Excessive Agency) |
| EU AI Act | Aligns with high-risk AI system transparency and human oversight requirements |
| CISA AI Roadmap | Supports recommendations for AI system observability and verification |

## Related frameworks in this portfolio

- `software-supply-chain-security-framework` — signing infrastructure (Sigstore/Cosign) applicable to agent provenance
- `forensics-and-incident-response-framework` — Five Forensic Questions framework for AI agent post-incident investigation
- `compliance-automation-framework` — OPA/Rego/Kyverno policy expressions used at Auditor decision points
