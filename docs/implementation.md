# Implementation Guide: Phased AI Security Controls

## Table of Contents

- [Overview](#overview)
- [Phase 1 (0–30 Days): Foundation Controls](#phase-1-030-days-foundation-controls)
- [Phase 2 (30–90 Days): Prompt Injection Defense](#phase-2-3090-days-prompt-injection-defense)
- [Phase 3 (90–180 Days): Agentic Pipeline Controls](#phase-3-90180-days-agentic-pipeline-controls)
- [Phase 4 (180+ Days): Model Supply Chain and Continuous Assurance](#phase-4-180-days-model-supply-chain-and-continuous-assurance)
- [Metrics and Success Criteria](#metrics-and-success-criteria)

---

## Overview

This guide provides a phased implementation path for organizations adopting the AI and Agentic Systems Security Framework. The phases are designed to be sequential — later phases build on earlier ones — but the timeline should be adapted to organizational capacity and risk tolerance.

**Prerequisites before starting Phase 1:**
- Baseline DevSecOps controls are in place (see [Techstream DevSecOps Framework](../devsecops-framework/))
- CI/CD pipeline security baseline from [Secure CI/CD Reference Architecture](../secure-ci-cd-reference-architecture/) is established
- At least one AI tool is in active use in the development or delivery workflow

Organizations with no AI tooling should complete Phase 1 immediately upon adopting any AI tool — not after the fact.

---

## Phase 1 (0–30 Days): Foundation Controls

Phase 1 establishes the security baseline: understanding what AI tooling exists, preventing the most common immediate risks (hallucinated packages, AI-generated secrets), and applying basic policy.

### P1-1: AI Tool Inventory

**Why:** You cannot secure what you do not know exists. Shadow AI tool usage (developers using personal API keys to access AI services) is common. The inventory establishes the scope of the problem.

**Actions:**

1. Survey all engineering teams to identify AI tools in use. Include:
   - IDE coding assistants (Copilot, Cursor, Codeium, JetBrains AI)
   - AI review or analysis tools (CodeRabbit, Snyk DeepCode, SonarQube AI)
   - LLM API usage in any pipeline scripts or custom tooling
   - AI-powered product features with pipeline integration
   - Slack/communication bots with AI features

2. Check for API keys for AI providers in existing secrets management systems and in any secrets scanning findings. This reveals unofficial usage.

3. Document each AI integration point with:
   - Tool name and version
   - AI provider and model used
   - What data is sent to the provider (code, issues, logs, etc.)
   - What actions the tool can take (comment, deploy, merge, etc.)
   - Authentication method (API key, OAuth, enterprise license)

4. Classify each integration by the AI Integration Layer (1–5) from [architecture.md](architecture.md).

**Deliverable:** AI integration inventory spreadsheet or CMDB entries for each integration point.

**Tool:** GitHub code search for AI provider patterns:
```bash
# Search for AI provider API key usage in pipeline configurations
gh search code "OPENAI_API_KEY" --owner your-org
gh search code "ANTHROPIC_API_KEY" --owner your-org
gh search code "COHERE_API_KEY" --owner your-org
# Review results for hardcoded keys and unofficial integrations
```

### P1-2: Deploy Scanning for AI-Generated Risks

**Why:** Slopsquatting and hallucinated credentials are exploitable today and require no sophisticated attacker — just a developer who accepts AI suggestions without verification.

**Actions:**

1. Extend Gitleaks configuration to include AI-provider-specific credential patterns (see [framework.md](framework.md) Section 1.2). Deploy as both pre-commit hook and CI gate.

2. Enable dependency confusion detection in your SCA tool:
   ```bash
   # Dependabot: configure in .github/dependabot.yml
   # OWASP Dependency-Check: use --format JSON and check for packages
   # resolvable from public registry but not in your private registry

   # New-package alerting: track first appearances of packages
   # If a package appears in requirements.txt that has never been in your
   # build environment before, alert and require explicit human approval
   ```

3. If not already in place, configure a private registry mirror (Artifactory, Nexus, CodeArtifact) and begin routing package installs through it. Alert on packages not present in the mirror.

4. Add to PR checklist: "Has AI-generated code been reviewed for plausible-but-nonexistent package names?"

**Deliverable:** Gitleaks extended configuration deployed; private registry mirror configured or planned.

### P1-3: Publish AI Acceptable Use Policy

**Why:** Without a policy, developers have no guidance on what AI tool use is permitted, what data can be shared with AI providers, and what security practices are expected. The policy establishes expectations and enables enforcement.

**Policy minimum content:**
- Which AI tools are approved for use (by name and version)
- What categories of data may not be included in AI context (secrets, PII, IP-sensitive source code for non-enterprise plans)
- The requirement that AI-generated code must be reviewed with the same scrutiny as code from an unknown external contributor
- The prohibition on using personal API keys to access unapproved AI services on organizational systems
- The requirement to report any suspected AI-related security incident (e.g., realizing a hallucinated package was committed)

Distribute via the engineering wiki or developer portal; include in onboarding checklist.

### P1-4: Restrict AI Pipeline Tools from Production Permissions

**Why:** Any AI pipeline tool that currently has production deployment permissions creates immediate risk. Even if not exploited today, the blast radius of an injection or compromise is bounded by what the tool can do.

**Actions:**

1. Audit the credentials and permissions of every AI pipeline component identified in the inventory.

2. For each component, identify any permissions that exceed what is strictly required for its documented function.

3. Revoke excess permissions immediately. Document the minimum required permissions.

4. For any AI component that currently has production deployment access: remove that access unless you have a specific business requirement and compensating controls in place.

**Deliverable:** AI pipeline components are documented with their current and revised permission sets. Production deployment permissions are not held by any AI component without explicit approval.

---

## Phase 2 (30–90 Days): Prompt Injection Defense

Phase 2 addresses the primary threat to AI pipeline components: prompt injection via data sources the AI reads.

### P2-1: Map All AI Input Data Sources

**Why:** You cannot defend against injection attacks on data sources you have not identified. This mapping is the input to all subsequent Phase 2 controls.

**Actions:**

For each AI pipeline component in the inventory:
1. List every data source the component reads (PR descriptions, commit messages, issue content, CVE feeds, log files, etc.)
2. For each data source, assess: who can write to it? Is it fully internal, or can external contributors or untrusted parties write to it?
3. Rate the injection risk: High (externally writable, read verbatim by AI), Medium (internally writable, read by AI), Low (system-generated, read by AI)
4. Identify any data sources where the AI reads content as if it were instructions (highest risk)

**Deliverable:** Data source map for each AI pipeline component, with injection risk ratings.

### P2-2: Implement Input Validation for All LLM Pipeline Inputs

**Actions:**

1. For each AI pipeline component, implement the input sanitization wrapper from [pipeline-controls.md](pipeline-controls.md).

2. Ensure all external data is passed as `user` role content, never as `system` role content. Audit existing system prompts for any user-controlled data that has been included in the system prompt.

3. Implement output schema validation for all AI pipeline components that produce structured output.

4. Deploy the prompt canary mechanism from [prompt-injection-defense.md](prompt-injection-defense.md) for all AI pipeline components.

```bash
# Validation gate in GitHub Actions:
# sanitize_pr_inputs.py must pass before AI analysis step runs
- name: Sanitize PR inputs
  run: |
    python scripts/sanitize_pr_inputs.py \
      --pr-title "${{ github.event.pull_request.title }}" \
      --pr-description-file pr_description.txt \
      --diff-file pr.diff \
      --output sanitized_inputs.json
  # Note: --fail-on-injection is NOT set by default — we sanitize and continue,
  # but log detections for monitoring. Set --fail-on-injection for high-risk pipelines.
```

### P2-3: Deploy Output Anomaly Detection

**Actions:**

1. Establish a behavioral baseline for each AI pipeline component: collect 2 weeks of output metrics (finding count distribution, approval rate, schema validation rate, output length distribution).

2. Configure alerting on deviations from baseline. Recommended thresholds:
   - Schema validation failure rate > 5%: alert immediately
   - Finding severity distribution shifts > 2 standard deviations from 30-day average: alert
   - Approval/LGTM rate increase > 2 standard deviations: alert immediately
   - Canary token detected in output: alert immediately, page security team

3. Integrate anomaly alerts into the incident response workflow. Anomalous AI behavior should be treated as a potential security incident.

### P2-4: Implement Agent Identity and Service Accounts

**Actions:**

1. Create dedicated service accounts (GitHub App installations, Kubernetes ServiceAccounts, cloud IAM roles) for each AI pipeline component.

2. Each service account must have a distinct identity not shared with human users or other pipeline components.

3. Migrate existing AI pipeline components from shared pipeline tokens or personal access tokens to dedicated service accounts.

4. Document the service account identity for each AI pipeline component in the AI integration inventory.

---

## Phase 3 (90–180 Days): Agentic Pipeline Controls

Phase 3 addresses organizations that are using or planning to use agents — AI components with tool access that can take actions in the delivery pipeline.

### P3-1: Implement Tool Authorization Policy as Code

**Actions:**

1. Create the tool authorization policy YAML file from [agent-authorization.md](agent-authorization.md) for each agent role in use.

2. Store the policy in a version-controlled repository with required reviewers (security team and platform team must review all policy changes).

3. Add CODEOWNERS rule for the policy file to enforce review requirements.

4. Implement enforcement: the tool execution layer must validate the agent's authorization before executing any tool call. This is not an honor-system policy — it must be enforced at the execution layer.

```bash
# CODEOWNERS entry for tool authorization policy
# .github/CODEOWNERS
/agent-tool-policy.yaml @security-team @platform-team
/prompts/                 @security-team @platform-team
```

### P3-2: Require Human Approval Gates for Irreversible Actions

**Actions:**

1. Identify all irreversible agent actions in the current pipeline (merge PRs, deploy to production, delete resources, modify IAM policies).

2. For each irreversible action, implement a human approval gate using the mechanisms appropriate to the platform:
   - GitHub Actions: environment protection rules (see [agent-authorization.md](agent-authorization.md))
   - GitLab: protected environment approvals
   - Kubernetes: admission webhooks requiring human annotation before agent-triggered changes are applied

3. Test the approval gates by attempting to trigger each irreversible action through the agent path without completing the approval step — verify that the action is blocked.

4. Document the approval requirements in the tool authorization policy.

### P3-3: Deploy Immutable Tool Call Logging

**Actions:**

1. Implement the audit record format from [agent-audit-trail.md](agent-audit-trail.md) in the tool execution layer.

2. Configure log delivery to an external, append-only store:
   - AWS: CloudWatch Logs + S3 with Object Lock (see [agent-audit-trail.md](agent-audit-trail.md))
   - GCP: Cloud Audit Logs + Cloud Storage with retention lock
   - Azure: Azure Monitor + Azure Blob Storage with immutability policy
   - On-premises/Kubernetes: external SIEM (Splunk, Elastic, Datadog)

3. Verify that the agent's service account does not have write access to the audit log store.

4. Test log integrity: attempt to delete or modify a log entry using the agent's credentials — verify that the operation is rejected.

### P3-4: Implement System Prompt Versioning

**Actions:**

1. Migrate all system prompts from inline pipeline configuration to a dedicated, version-controlled prompts repository.

2. Implement the SHA-based prompt retrieval from [agent-audit-trail.md](agent-audit-trail.md) in session initialization.

3. Record the system prompt SHA in every session initialization audit record.

4. Add system prompt changes to the change management process: changes require the same review and approval as production code changes.

---

## Phase 4 (180+ Days): Model Supply Chain and Continuous Assurance

Phase 4 establishes the model governance program and transitions AI security from project-based implementation to continuous assurance.

### P4-1: Implement Approved Model Registry

**Actions:**

1. Define the approved model list (see [framework.md](framework.md) Section 5.4) with: model name, provider, approved versions, use cases, and governance requirements.

2. For self-hosted models, integrate `modelscan` into the model deployment pipeline:
   ```bash
   # Model deployment pipeline gate
   modelscan --path ./models/${MODEL_NAME}/ --exit-code
   # Fail the deployment if scan finds issues
   ```

3. For API-accessed models (OpenAI, Anthropic, etc.): pin the API version and model version in all pipeline configurations. Test and document the upgrade process for model version changes.

4. Document and enforce the shadow model policy: network egress filtering to block unapproved AI provider domains on CI/CD runners.

### P4-2: Fine-Tuning Pipeline Security (If Applicable)

If the organization fine-tunes models on internal data:

1. Apply the fine-tuning pipeline security controls from [framework.md](framework.md) Section 5.3.

2. Implement a required security review before incorporating any new training data source.

3. Establish evaluation gates: model must pass the held-out test suite before the fine-tuned checkpoint can be deployed.

4. Store training data provenance records for all fine-tuned models.

### P4-3: Continuous Behavioral Monitoring

**Actions:**

1. Expand the anomaly detection from Phase 2 to cover all AI pipeline components, including agentic systems with tool access.

2. Establish recurring review of agent behavior patterns:
   - Weekly: review anomaly alerts and false-positive rate
   - Monthly: compare current behavioral distribution against the 90-day baseline; review for systematic drift
   - Quarterly: security team reviews the AI integration inventory for new components and updated risk assessments

3. Define AI-specific incident response procedures:
   - Incident trigger: canary token detected, anomalous approval rate, unauthorized tool invocation attempt
   - Response: session termination, forensic log retrieval, injection vector identification
   - Recovery: update input sanitization rules, update system prompt if needed, re-run adversarial tests

### P4-4: Red Team Exercises for AI Components

Conduct quarterly adversarial testing exercises specifically targeting AI pipeline components:

**Exercise 1: Prompt injection attack simulation**
- Objective: determine whether indirect prompt injection via PR descriptions, commit messages, or CVE descriptions can cause AI pipeline components to take unauthorized actions
- Method: security team crafts injection payloads and submits them through legitimate channels; engineers monitor for anomalous AI behavior
- Success criterion: no injection payload causes an unauthorized action; at minimum, all injection attempts are detected by behavioral monitoring

**Exercise 2: Agent authorization boundary testing**
- Objective: verify that tool authorization policy is enforced at the execution layer
- Method: directly attempt to invoke unauthorized tools using the agent's credentials; attempt to use authorized tools with parameters designed to produce privileged effects
- Success criterion: all unauthorized invocations are blocked; all invocation attempts are logged

**Exercise 3: Model supply chain integrity test**
- Objective: verify that model provenance verification and scanning controls function correctly
- Method: attempt to deploy a modified model checkpoint; attempt to bypass hash verification
- Success criterion: modified checkpoint is detected and deployment is blocked

---

## Metrics and Success Criteria

Track the following metrics to demonstrate progress and identify gaps:

| Phase | Metric | Target | Measurement Method |
|---|---|---|---|
| P1 | AI integration inventory completeness | 100% of AI tools documented | Manual survey + secrets scan cross-reference |
| P1 | AI pipeline components with production deploy access | 0 without explicit approval | Permission audit |
| P2 | AI pipeline components with input sanitization | 100% | Code review |
| P2 | Schema validation failure rate | < 1% in steady state | Monitoring dashboard |
| P2 | Prompt canary coverage | 100% of AI pipeline components | Configuration audit |
| P3 | Agent tool invocations with audit records | 100% | Audit log completeness check |
| P3 | Irreversible agent actions with human approval gate | 100% | Configuration audit |
| P3 | System prompts version-controlled | 100% | Repository audit |
| P4 | Models in approved registry vs. models in use | 100% match | Registry audit + pipeline scan |
| P4 | Red team exercises per year | 4 (quarterly) | Exercise log |
| P4 | Mean time to detect anomalous agent behavior | < 30 minutes | Simulation tests |
