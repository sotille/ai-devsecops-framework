# Developer Environment AI Security Controls

## Table of Contents

- [Overview](#overview)
- [Attack Surface: The Developer Workstation Layer](#attack-surface)
- [Slopsquatting: Detection and Prevention](#slopsquatting)
- [AI Assistant Data Handling Policies](#ai-assistant-data-handling-policies)
- [Secret and Credential Protection](#secret-and-credential-protection)
- [Network Egress Controls for AI Plugins](#network-egress-controls)
- [Pre-Commit Hook Controls](#pre-commit-hook-controls)
- [Organizational AI Usage Policy for Developers](#organizational-ai-usage-policy)
- [MCP Server Security](#mcp-server-security)
- [Developer Tooling Approval Process](#developer-tooling-approval-process)
- [Implementation Checklist](#implementation-checklist)

---

## Overview

The developer environment is the first layer of the AI integration surface in the software delivery lifecycle. IDE plugins, code completion assistants, local LLMs, and AI-assisted debugging tools are deployed at the developer workstation — the point in the pipeline furthest from centralized security controls and closest to the human with the highest level of trust in the codebase.

Developer environment AI security controls address threats that originate at this layer:

- **Slopsquatting:** AI coding assistants generating dependency names that do not exist in public registries but could be registered by an adversary
- **Secret exfiltration:** AI assistant context windows containing API keys, passwords, and credentials transmitted to external model providers
- **Over-trust in AI suggestions:** Developers accepting AI-generated code without security review, normalizing insecure patterns into the codebase
- **Unvetted tool adoption:** Developers installing AI plugins that exfiltrate code, telemetry, or intellectual property without organizational awareness

These threats are distinct from CI/CD pipeline AI threats (see [pipeline-controls.md](pipeline-controls.md)) because they operate before code reaches version control and may not be visible to pipeline security controls.

---

## Attack Surface: The Developer Workstation Layer

The attack surface at the developer workstation layer spans:

```
Developer Workstation AI Attack Surface:
├── Code completion suggestions
│   ├── Generated dependency names (slopsquatting target)
│   ├── Generated import statements
│   └── Generated cryptographic code (may be subtly insecure)
│
├── AI assistant context transmitted to external APIs
│   ├── Open files in IDE (may contain secrets, credentials, proprietary code)
│   ├── Recent clipboard contents
│   ├── Git diff and status (exposes code changes in progress)
│   └── Terminal output (may contain secrets, error messages with sensitive paths)
│
├── AI plugin installation surface
│   ├── Plugins installed outside approved tooling catalog
│   ├── Plugin update supply chain (auto-updates without security review)
│   └── Plugin permissions (file system access, network egress, clipboard access)
│
└── Developer over-trust
    ├── Accepting AI-suggested code without review
    ├── Merging AI-approved PRs without independent human review
    └── Treating AI output as authoritative on security questions
```

Threat actors targeting the developer environment layer can:
1. Register package names that AI assistants hallucinate, poisoning supply chains at the moment code is written
2. Extract intellectual property or credentials through compromised or over-permissioned AI plugins
3. Introduce subtly insecure code patterns through AI suggestions crafted to look correct but contain exploitable weaknesses

---

## Slopsquatting: Detection and Prevention

Slopsquatting is the exploitation of AI coding assistants that generate package names that do not exist in public registries. An adversary monitors AI-generated code (through public code sharing, GitHub Copilot telemetry analysis, or large-scale code scanning) to identify hallucinated package names, registers those package names in public registries with malicious payloads, and waits for developers to install them.

### Package Existence Verification

The primary control is verifying that every package name suggested by an AI assistant exists in the organization's approved package registry before the developer uses it.

**Pre-commit hook: dependency verification**

```python
#!/usr/bin/env python3
"""
Pre-commit hook: verify all dependencies in requirements.txt, package.json,
go.mod, and pyproject.toml exist in the organization's approved package mirror.

Fails the commit if any dependency cannot be verified.
"""

import subprocess
import sys
import json
import urllib.request
import re
from pathlib import Path

PRIVATE_MIRROR_URL = "https://pkg.internal.example.com"
REGISTRY_ENDPOINTS = {
    "pypi": f"{PRIVATE_MIRROR_URL}/pypi/{{package}}/json",
    "npm": f"{PRIVATE_MIRROR_URL}/npm/{{package}}",
}

def get_staged_files():
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip().split('\n')

def extract_python_deps(path: str) -> list[str]:
    """Extract package names from requirements.txt (no version specifiers)."""
    packages = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('-'):
                # Strip version specifiers: package>=1.0,<2.0 → package
                pkg = re.split(r'[>=<!~\[]', line)[0].strip()
                if pkg:
                    packages.append(pkg)
    return packages

def verify_package_exists(package: str, registry: str) -> bool:
    url = REGISTRY_ENDPOINTS[registry].format(package=package)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "dep-verifier/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 200
    except Exception:
        return False

def main():
    staged_files = get_staged_files()
    failed_packages = []

    for f in staged_files:
        if f == "requirements.txt" or f.endswith("/requirements.txt"):
            packages = extract_python_deps(f)
            for pkg in packages:
                if not verify_package_exists(pkg, "pypi"):
                    failed_packages.append(f"  {pkg} (PyPI) — not found in registry mirror")

    if failed_packages:
        print("ERROR: Unverified dependencies detected.")
        print("These package names could not be verified in the organization's registry mirror.")
        print("If AI-generated, this may indicate slopsquatting risk.")
        print("Verify each package manually before committing:\n")
        for p in failed_packages:
            print(p)
        print("\nIf the package is legitimate, add it to the approved registry mirror first.")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
```

### Private Registry Mirror

The most reliable slopsquatting defense is requiring all dependencies to resolve through a private registry mirror that contains only manually approved packages. AI-hallucinated package names fail to resolve at the mirror — they never reach the public registry.

```yaml
# .npmrc — force all npm installs through private mirror
registry=https://pkg.internal.example.com/npm/
always-auth=true

# pip.conf — force all pip installs through private PyPI mirror
[global]
index-url = https://pkg.internal.example.com/pypi/simple/
trusted-host = pkg.internal.example.com
```

### AI-Generated Dependency Review Workflow

For teams that cannot enforce private registry mirroring immediately:

1. Flag all AI-generated code suggestions that include new dependency names (detect via PR description tagging or AI tool telemetry)
2. Require manual verification: does the package exist in the public registry? Does the package have a reasonable history (creation date, download count, maintainer activity)?
3. Block on dependency confusion indicators: package name is a plausible variant of an internal package name; package was registered recently with no activity

---

## AI Assistant Data Handling Policies

AI coding assistants transmit context to external model providers. The data transmitted includes whatever is in the IDE context window at the time of the query: open files, recent edits, clipboard contents, terminal output.

### What Is Transmitted

Default behavior for common AI coding assistants:

| Tool | What is sent by default | Configurable? |
|---|---|---|
| GitHub Copilot | Current file, surrounding context, opened files in IDE | Partial (content exclusions) |
| Cursor | Current file, all open tabs, codebase index | Yes (privacy mode) |
| Cody (Sourcegraph) | Current file, selected text, repository context | Yes |
| Continue (local/remote) | Current file, selected context, optional full codebase | Yes |

### Data Classification Controls

Not all code should be sent to external AI providers. Define explicit data classification rules:

```yaml
# ai-assistant-policy.yaml — defines what may be sent to external AI assistants

allow_external_transmission:
  - classification: public
  - classification: internal_general
  - path_patterns:
      - "tests/**"
      - "docs/**"
      - "examples/**"

require_local_model_only:
  - classification: confidential
  - classification: restricted
  - path_patterns:
      - "**/*.env"
      - "**/*secret*"
      - "**/*credential*"
      - "**/*private_key*"
      - "infrastructure/**"
      - "security/**"

block_all_ai_assistance:
  - path_patterns:
      - ".github/workflows/**"   # CI/CD configuration — injection risk
      - "**/*_test.go"           # Test data may contain real values
```

### Pre-commit Secret Detection

AI assistants may have already received secret material that was in the IDE context. A pre-commit hook provides a last-line defense before secrets reach version control.

```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
        args: ["--baseline-path", ".gitleaks-baseline.json"]
```

---

## Secret and Credential Protection

The developer environment is a high-risk location for credential exposure. Developers handle:
- SSH keys and GPG keys for git authentication
- API tokens for cloud providers, SaaS tools, and internal services
- `.env` files with database passwords and service credentials
- Certificates and private keys

AI assistants that access these files transmit them to external providers.

### Controls

**1. .gitignore enforcement:** Ensure credential files are gitignored and verify the .gitignore is committed before credentials are added.

**2. Pre-commit secret scanning:** Use gitleaks, truffleHog, or detect-secrets as pre-commit hooks. Detect secrets before they enter version control.

**3. AI context exclusion:** Configure AI assistants to exclude credential files from context transmission:
- GitHub Copilot: `.copilotignore` file (follows .gitignore syntax)
- Cursor: Settings > Privacy > Exclude files
- Continue: `.continuerc.json` with `contextProviders` exclusion rules

**4. Secrets manager adoption:** Replace `.env` files with secrets manager integrations (AWS Secrets Manager, HashiCorp Vault, 1Password CLI). When secrets are retrieved programmatically at runtime rather than stored in files, they are not present in files that AI assistants can access.

**5. Developer key rotation policy:** If a developer's workstation runs AI assistant plugins with broad file system access, define a rotation policy for credentials that were present in the workstation environment.

---

## Network Egress Controls for AI Plugins

AI plugins installed in IDEs require network access to reach model providers. This creates an egress channel from developer workstations that may bypass enterprise DLP controls.

### Control Options

| Control | Scope | Overhead |
|---|---|---|
| Approved plugin list enforced via MDM | Prevents unapproved AI plugins | Medium (MDM required) |
| Proxy-all-traffic policy with TLS inspection | Inspects AI assistant traffic | High (TLS inspection complexity) |
| Approved provider allowlist in firewall | Blocks unapproved model endpoints | Low |
| Local-only LLM requirement for confidential work | No external transmission | Medium (local model management) |

### Approved Provider Allowlist

Maintain an organizational list of approved AI model providers and their API endpoints. Block outbound traffic to unapproved model APIs at the network layer. Review the allowlist quarterly — new AI tools emerge frequently, and unapproved usage often precedes formal evaluation.

---

## Pre-Commit Hook Controls

Pre-commit hooks are the primary enforcement layer for developer environment security controls. They run before code enters version control, catching issues that would otherwise reach the pipeline.

**Recommended pre-commit hooks for AI-assisted development:**

```yaml
# .pre-commit-config.yaml

repos:
  # Secret detection
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  # Dependency verification (custom hook)
  - repo: local
    hooks:
      - id: verify-dependencies
        name: Verify dependency existence in registry mirror
        entry: .hooks/verify-dependencies.py
        language: python
        files: "(requirements\\.txt|package\\.json|go\\.mod|pyproject\\.toml)$"
        pass_filenames: true

  # AI-generated code marker (if AI tools support PR tagging)
  - repo: local
    hooks:
      - id: flag-ai-generated
        name: Flag commits with AI-generated dependencies for review
        entry: .hooks/flag-ai-generated.sh
        language: script
        always_run: true
```

---

## Organizational AI Usage Policy for Developers

An organizational AI usage policy defines the rules governing AI tool use by developers. It is distinct from a general AI acceptable use policy — it addresses the specific risks of AI coding assistants in the software development context.

**Required policy elements:**

1. **Approved tools list:** Which AI coding assistants are approved for use? For what environments (development only, not production infrastructure)?

2. **Data classification rules:** What code and data may be sent to external AI providers? What must remain local or use an approved local LLM?

3. **Dependency review requirements:** AI-generated dependency names must be verified in the registry mirror before commit. Developers are accountable for dependencies they commit, regardless of source.

4. **Secret handling:** AI assistants must not be used when credential files are open in the IDE, or the credential files must be excluded from context transmission.

5. **Review requirements for AI-generated code:** AI-generated code that modifies security controls, authentication logic, cryptographic operations, or infrastructure configuration must be reviewed by a security engineer before merge.

6. **Incident reporting:** Developers who discover that secrets may have been transmitted to an AI provider must report to the security team immediately for credential rotation.

---

## MCP Server Security

> **Adoption maturity note:** MCP server adoption in enterprise environments is currently early-stage. The controls in this section are forward-looking guidance for organizations that have already adopted AI agents that invoke tools via MCP — not a prerequisite for initial AI assistant deployment. Organizations at AI Security Maturity Level 1–2 should prioritize the controls in earlier sections (slopsquatting detection, data handling policies, secret protection) before focusing on MCP server security. Apply this section when MCP-enabled AI tooling is in active use or being evaluated for adoption.

The Model Context Protocol (MCP) is an open standard that defines how AI models connect to external tools and services. As AI coding assistants evolve from text completion into agent-like systems that invoke real tools — reading files, executing shell commands, querying databases, interacting with APIs — the MCP server becomes a security boundary that did not exist in earlier assistant architectures.

### What MCP Servers Introduce

An MCP server exposes tools (functions) to an AI model. When a developer's IDE AI assistant connects to an MCP server, the model can invoke those tools on the developer's workstation, against the developer's credentials, and within the developer's network context. This is categorically different from code completion: the AI is not suggesting text for the developer to approve — it is invoking real capabilities in real environments.

The attack surface that MCP servers introduce:

```
MCP Attack Surface at the Developer Workstation:
├── Server authentication and authorization
│   ├── Which AI clients are permitted to connect to this server?
│   ├── Does the server authenticate the calling model/assistant identity?
│   └── Are per-tool permissions scoped, or does connection = full access?
│
├── Tool invocation scope
│   ├── Can the server invoke shell commands? Which ones?
│   ├── Can the server read/write arbitrary file paths?
│   ├── Can the server make network requests? To which destinations?
│   └── Does the server inherit the developer's ambient credentials (AWS, GCP, GitHub token)?
│
├── Supply chain: the MCP server itself
│   ├── Was the server installed from a verified source?
│   ├── Is the server's code reviewed and pinned to a known version?
│   └── Does the server auto-update (accepting unreviewed code changes)?
│
└── Prompt injection via tool results
    ├── Tool results returned to the model can contain injected instructions
    ├── A malicious file or API response read by the model can redirect subsequent actions
    └── The model may act on injected instructions using the same MCP tools
```

### Security Controls for MCP Servers

**1. Inventory and approval**

Apply the same tooling approval process to MCP servers as to AI coding assistants. Before connecting an MCP server to a developer's AI assistant:

- Identify what tools the server exposes and what each tool can do
- Identify what credentials the server needs and whether it uses the developer's ambient credentials or its own scoped credentials
- Review the server's code or confirm it comes from a verified, pinned source
- Add approved servers with required configuration to the team's approved tooling catalog

**2. Scope the server's permissions**

Configure MCP servers to use minimal authority:

```json
// Example: .mcp/config.json — restrict filesystem server to project directories only
{
  "servers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "${PROJECT_ROOT}"],
      "env": {
        "ALLOWED_PATHS": "${PROJECT_ROOT}",
        "DENY_PATHS": "${HOME}/.ssh,${HOME}/.aws,${HOME}/.config/gcloud"
      }
    }
  }
}
```

Never configure MCP servers with access to credential files, SSH keys, or cloud provider configuration directories unless the server's specific function requires it and the access is reviewed.

**3. Treat tool results as untrusted input**

Any data returned to the model by an MCP tool — file contents, API responses, database query results, web search results — is external data that can contain injected instructions. The model may act on those instructions using the same MCP tools it was originally configured with.

This is indirect prompt injection at the developer workstation layer. Mitigations:

- Prefer MCP servers that validate and sanitize tool results before returning them to the model
- Do not configure MCP servers with write access to production systems from developer workstations
- Review AI assistant action logs for unexpected tool invocations that follow large external data retrievals

**4. Pin server versions**

MCP servers that auto-update accept unreviewed code changes that may expand permissions or introduce malicious functionality:

```json
// Pin to a specific version in package.json
{
  "devDependencies": {
    "@modelcontextprotocol/server-filesystem": "1.2.3",
    "@modelcontextprotocol/server-github": "2.1.0"
  }
}
```

Include MCP server packages in SCA scanning and dependency update policy.

**5. Do not expose production credentials to MCP servers**

MCP servers running on developer workstations must not have access to production credentials. Use separate credential profiles for development and production, and ensure the developer's ambient credentials (active AWS profile, GitHub token with org write access) are scoped to development environments only when AI assistants with MCP capability are in use.

### MCP Security Checklist

- [ ] Approved MCP server catalog maintained with permitted tools, version pins, and required configuration
- [ ] MCP server filesystem access restricted to project directories; credential directories excluded
- [ ] MCP servers pinned to specific versions; included in SCA dependency scanning
- [ ] Developers trained on indirect prompt injection risk via MCP tool results
- [ ] Production credentials not accessible to MCP servers on developer workstations

---

## Developer Tooling Approval Process

AI developer tools should go through an approval process before organizational adoption. The process does not need to be heavyweight — but it must exist, because the default is that developers adopt tools before security has evaluated them.

**Lightweight approval process:**

| Stage | Activity | Owner | Timeline |
|---|---|---|---|
| Request | Developer or team submits tool for evaluation | Developer | Day 0 |
| Data handling review | Security reviews what data the tool transmits, to whom, and under what retention policy | Security | Day 1–3 |
| Privacy assessment | Legal/compliance reviews data processing agreement with the tool provider | Legal | Day 1–5 |
| Configuration review | Security defines required configuration (exclusions, privacy mode, proxy settings) | Security | Day 3–5 |
| Approval or rejection | Decision communicated with rationale | Security + Legal | Day 5–7 |
| Catalog entry | Approved tool added to catalog with required configuration | Platform | Day 7–10 |

Tools approved for internal general code may require re-evaluation before use on confidential or restricted classification projects.

---

## Implementation Checklist

### Slopsquatting Controls
- [ ] Private registry mirror configured; all dependency installation routes through it
- [ ] Pre-commit hook verifying dependency existence deployed to all developer workstations
- [ ] AI-generated code PR tagging in place for dependency review tracking

### Data Handling Controls
- [ ] Data classification policy for AI assistant context transmission documented and distributed
- [ ] `.copilotignore` / AI context exclusion files deployed to all repositories containing sensitive code
- [ ] Pre-commit secret scanning (gitleaks or equivalent) deployed and enforced

### Network Controls
- [ ] Approved AI provider allowlist established and enforced at network layer
- [ ] Unapproved AI tool egress blocked

### Policy and Process
- [ ] Developer AI usage policy published and accessible
- [ ] Developer tooling approval process established; backlog of current unapproved tools in use reviewed
- [ ] AI security training included in developer onboarding

### MCP Server Controls
- [ ] Approved MCP server catalog established with version pins and permitted tool scope
- [ ] MCP server filesystem access restricted to project directories; credential directories excluded
- [ ] MCP server packages included in SCA dependency scanning
- [ ] Developers trained on indirect prompt injection risk via MCP tool results

### Monitoring
- [ ] Secret scanning alerts routing to security team
- [ ] Failed pre-commit hook events reported to security dashboard (aggregate, not individual)
- [ ] Unapproved AI provider egress attempts alerted
