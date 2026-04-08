# AI-Specific Threat Intelligence

> Part of the [AI DevSecOps Framework](../framework.md)

---

## Scope and Purpose

Traditional Cyber Threat Intelligence (CTI) programs were designed around a stable threat model: human attackers using known exploitation techniques against software and network infrastructure. AI integration into software delivery introduces a threat category that standard CTI programs systematically miss — not because of gaps in analyst capability, but because the attack surface, attack mechanics, and indicator types are structurally different from what existing collection and analysis pipelines are optimized to detect.

This document defines AI-specific threat intelligence as a distinct discipline, establishes a taxonomy of AI-assisted and AI-targeting attacks, and provides operational guidance for detection, monitoring, and intelligence integration in DevSecOps environments.

**What standard CTI programs miss when AI is in scope:**

- Slopsquatting and hallucinated package attacks do not generate network indicators or file-system artifacts in the traditional sense. The malicious artifact is installed through a legitimate package manager using a legitimate install workflow. There is no exploit; the developer is the unwitting delivery mechanism.
- AI-generated malicious artifacts (commit messages, PR descriptions, code suggestions) pass static analysis and may pass human review. They are designed to look legitimate.
- Model supply chain attacks operate at a layer below the application: the weights of an AI model, which are binary artifacts not subject to standard SAST/DAST tooling.
- Prompt injection attacks are carried through data channels, not code channels. A malicious string in a CVE description, a package README, or a code comment can trigger unintended agent behavior. Standard CTI feeds do not label these as threat indicators.

**Relationship to the Techstream framework:**

- For developer workstation controls against slopsquatting: see [developer-environment-controls.md](./developer-environment-controls.md)
- For model registry security and supply chain for ML artifacts: see [model-supply-chain.md](./model-supply-chain.md)
- For AI-generated PR description attacks and prompt injection defenses: see [prompt-injection-defense.md](./prompt-injection-defense.md)
- For incident investigation when an AI-assisted supply chain attack is detected: see [forensics-and-incident-response-framework/docs/playbooks/ai-supply-chain.md](../../forensics-and-incident-response-framework/docs/playbooks/ai-supply-chain.md)

---

## AI-Assisted Attack Taxonomy

This taxonomy organizes AI-related attacks into three categories based on the role AI plays in the attack chain. The distinction matters for detection strategy: different categories require different monitoring approaches.

### Category 1 — AI-Amplified Traditional Attacks

The attacker uses AI tooling to scale, accelerate, or improve the quality of attacks that would have existed without AI. The underlying attack type is not new; the economics change.

**Examples:**

- **Typosquatting at scale**: Attackers previously registered a handful of typosquatting packages manually. With LLMs, an attacker can generate thousands of plausible-but-incorrect package names for every major library, register them in bulk, and collect installs passively. The attack vector (malicious package in a public registry) is not new; the scale is.
- **Phishing content generation**: AI-generated spear-phishing targeting DevSecOps personas (security engineers, platform engineers) at higher quality and lower cost than human authoring.
- **Vulnerability research acceleration**: AI-assisted code analysis to find exploitable patterns faster. Reduces time-to-exploit for disclosed CVEs.
- **Social engineering of code review**: AI-generated explanations and PR descriptions crafted to make malicious changes appear routine. The description is factually accurate about what the code does but framed to minimize scrutiny.

**Detection implications**: The indicators are the same as traditional attacks (malicious package, phishing email, exploit payload), but volume and velocity are higher. Rate-based alerting thresholds calibrated for human-scale attacks will produce more false negatives.

### Category 2 — AI-Specific Attacks Targeting AI Systems

The attack target is an AI system component: a model artifact, a prompt, a context window, or the inference pipeline. These attacks have no direct analog in traditional CTI.

**Examples:**

- **Prompt injection**: Malicious instructions embedded in data that an AI system processes, causing the system to deviate from its intended behavior. Indirect prompt injection occurs through environmental data sources (CVE databases, package metadata, code being reviewed).
- **Model supply chain attacks**: Malicious modification of model weights during training, fine-tuning, or storage. The model produces subtly incorrect outputs under specific trigger conditions.
- **Training data poisoning**: Injecting adversarial examples into training datasets to introduce behavioral backdoors.
- **Model theft / extraction**: Using adversarial query strategies to reconstruct a proprietary model's parameters or decision boundaries.
- **Context window manipulation**: Injecting data into an agent's context to influence its action selection without direct prompt access.

**Detection implications**: Standard SIEM and EDR tooling has no visibility into these attack vectors. Detection requires AI-specific telemetry: prompt logging, model digest verification, output anomaly detection, and agent action auditing.

### Category 3 — AI-Facilitated Novel Attacks

Attacks that are only possible because AI systems are generating code, configuration, and recommendations that developers act on without verification. The AI is not the attacker's tool; it is an unwitting participant in the attack.

**Examples:**

- **Slopsquatting**: AI assistants hallucinate package names. Attackers register those names in public registries. Developers install the malicious packages because an AI tool told them to. This attack category requires no attacker skill in traditional exploitation; the investment is in package name prediction and package registration.
- **Hallucinated configuration values**: An AI assistant generates a configuration snippet referencing a non-existent service endpoint or an internal hostname. An attacker who controls DNS for that name can intercept traffic.
- **AI-generated malicious starter code**: Repositories or starter templates generated by AI that contain subtle vulnerabilities or backdoors, either through adversarial prompting of the AI or through the AI generating code based on poisoned training data.

**Detection implications**: Prevention and detection must operate at the AI suggestion layer, before the developer acts on the suggestion. Post-commit detection is often too late if the package is installed in CI.

---

## Slopsquatting: Threat Model and Detection

### Mechanics

Slopsquatting is a supply chain attack that exploits the hallucination behavior of large language models used as coding assistants. The attack proceeds in three phases:

1. **Identification**: An attacker (or an automated system operating on behalf of attackers) prompts AI coding assistants to generate code for common tasks (HTTP client setup, authentication boilerplate, data parsing). They record the package names the AI recommends that do not actually exist in public registries.

2. **Registration**: The attacker registers the hallucinated package names in the target registry (npm, PyPI, RubyGems, etc.) and publishes a package with malicious payload in a post-install script or as runtime code.

3. **Exploitation**: Developers using AI coding assistants receive suggestions to install the now-registered malicious package. Because the package name matches what the AI suggested, the developer installs it without independent verification.

The attack is passive from the attacker's perspective after registration: the AI assistant does the distribution work.

### Attack Surface

AI coding assistants create slopsquatting risk at multiple integration points in the software delivery lifecycle:

**IDE integrations (GitHub Copilot, Cursor, Amazon CodeWhisperer, JetBrains AI, others)**
- Suggest import statements and install commands inline with code
- Developers typically accept suggestions with minimal friction (Tab completion)
- No verification that suggested packages exist before the suggestion appears

**AI-powered code review systems**
- PR analysis agents may suggest adding dependencies to address identified gaps
- The suggestion appears in a comment from an authorized reviewer; developers trust it
- PR description injection (see Category 2 above) can influence what code review AI suggests

**AI-generated starter code and scaffolding**
- Project bootstrap tools (create-react-app equivalents with AI generation) may produce package.json or requirements.txt files with hallucinated dependencies
- These files are committed to version control before anyone installs the packages

**Documentation and tutorial generation**
- AI-generated documentation may include install commands with hallucinated package names
- Developers following AI-generated tutorials install packages without cross-referencing against official docs

### Package Name Patterns

Slopsquatting packages tend to cluster around predictable naming patterns. These patterns are useful for detection heuristics:

**Sub-package patterns**: Libraries that have official namespaced packages frequently hallucinate unofficial sub-packages.
- Official: `@openai/openai`; hallucinated: `openai-utils`, `openai-helpers`, `openai-streaming`
- Official: `langchain`; hallucinated: `langchain-extras`, `langchain-tools`, `langchain-agents`
- Official: `anthropic`; hallucinated: `anthropic-sdk-utils`, `anthropic-claude`

**Version-nonexistent references**: AI models may generate install commands that specify versions that do not exist for real packages, but the hallucinated version string looks plausible.

**Framework integration shims**: Libraries that bridge two frameworks often don't exist but sound like they should.
- `express-prisma-adapter`, `fastapi-langchain`, `nextjs-openai-edge`

**Abbreviated or aliased names**: Common libraries have well-known aliases in AI training data that may not correspond to actual package names.

### Detection Signals

The following signals, individually or in combination, indicate a package may be a slopsquatting target or an active slopsquatting payload:

**Registry-level signals:**
- Package first published within the last 30 days with no prior version history
- Package has zero or very few downloads (< 100 total) despite appearing as a common utility
- Package author has no prior publication history on the registry
- Package name closely matches a high-download package with a plausible sub-package suffix
- Package has a post-install script (`postinstall` in package.json, `post_install` in setup.py) with non-trivial code

**GitHub/code signals:**
- Package repository (if it exists) has 0–5 stars and was created recently
- README is AI-generated boilerplate without substantive documentation
- No release history, changelog, or issue history
- No test suite

**Behavioral signals (post-install):**
- Post-install script makes outbound network connections
- Package binary or module attempts file system access outside expected scope
- Package loads and executes remote code

**Contextual signals:**
- Package was introduced to the codebase immediately after a developer session with an AI coding assistant (detectable via PR metadata timing analysis)
- Package appears in a PR description or AI suggestion but is not listed in the official documentation of the library it purports to extend

### SCA Tool Integration

Software Composition Analysis (SCA) tools provide the primary automated detection layer for slopsquatting. Configuration adjustments are required to cover slopsquatting-specific patterns, as default configurations are optimized for vulnerability detection in known packages.

**Snyk**

Snyk's dependency confusion detection covers private/public namespace collision but does not natively detect slopsquatting (a new package with no known vulnerabilities). Supplement with:
- Enable "new package alerts" if available in your Snyk tier
- Use the Snyk API to query package metadata and flag packages with publish date < 30 days
- Integrate Snyk results with a package age check: any new dependency introduced in a PR should have its publish date verified before merge is permitted

**Grype**

Grype scans SBOMs and container images against vulnerability databases. Slopsquatting packages will not appear in Grype results (no CVE assigned). Use Grype for what it does well (known CVEs) and pair with:
- A pre-commit or CI check that verifies each new dependency exists in an approved registry with minimum age threshold

**Dependabot**

Dependabot monitors existing dependencies for updates and vulnerabilities. It does not prevent introduction of new slopsquatting packages. Configure:
- Require Dependabot approval for all dependency version changes in lock files
- Use Dependabot's `allow` configuration to restrict dependency updates to packages that already exist in an approved internal registry mirror

**Private Registry Mirror Pattern**

The most effective control against slopsquatting and dependency confusion is a private registry mirror that acts as the sole dependency source for CI and developer machines:

1. Mirror approved packages from public registries into an internal registry (Artifactory, Nexus, GitHub Packages, AWS CodeArtifact)
2. Configure package managers (npm, pip, etc.) to use only the internal registry
3. New package approval requires a manual review step: verify package existence, age, author reputation, and code content
4. Slopsquatting packages never enter the approved registry because they do not pass the approval step

This pattern eliminates slopsquatting exposure for packages not yet in the approved registry and shifts the attack to requiring registry admin compromise.

### Pre-Commit Hook for New Dependency Verification

The following pre-commit hook logic (adaptable to any pre-commit framework) provides a developer-workstation control that catches slopsquatting before code is committed:

```python
#!/usr/bin/env python3
"""
Pre-commit hook: verify new dependencies in requirements.txt, package.json, pyproject.toml
Checks: package existence, publish age, download count baseline
"""

import subprocess
import sys
import json
import datetime
import urllib.request

MINIMUM_PACKAGE_AGE_DAYS = 30
MINIMUM_DOWNLOAD_COUNT = 1000  # PyPI weekly downloads threshold

def get_new_dependencies(diff_output: str) -> list[str]:
    """Extract added dependency lines from git diff output."""
    new_deps = []
    for line in diff_output.splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            # Parse package name from requirements.txt format (pkg==version or pkg>=version)
            dep_line = line[1:].strip()
            if dep_line and not dep_line.startswith('#'):
                pkg_name = dep_line.split('==')[0].split('>=')[0].split('<=')[0].strip()
                if pkg_name:
                    new_deps.append(pkg_name)
    return new_deps

def check_pypi_package(package_name: str) -> dict:
    """Query PyPI JSON API for package metadata."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read())
            # Get earliest release date
            releases = data.get('releases', {})
            if not releases:
                return {'exists': True, 'age_days': 0, 'downloads': 0}
            earliest = min(
                (info[0]['upload_time'] for v, info in releases.items() if info),
                default=None
            )
            if earliest:
                pub_date = datetime.datetime.fromisoformat(earliest.replace('Z', '+00:00'))
                age = (datetime.datetime.now(datetime.timezone.utc) - pub_date).days
            else:
                age = 0
            return {'exists': True, 'age_days': age}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'exists': False}
        raise

def main():
    # Get diff of staged changes
    result = subprocess.run(
        ['git', 'diff', '--cached', '--', 'requirements*.txt', 'pyproject.toml'],
        capture_output=True, text=True
    )
    new_deps = get_new_dependencies(result.stdout)

    failures = []
    for dep in new_deps:
        meta = check_pypi_package(dep)
        if not meta.get('exists'):
            failures.append(f"FAIL: Package '{dep}' does not exist on PyPI. Possible slopsquatting target.")
        elif meta.get('age_days', 0) < MINIMUM_PACKAGE_AGE_DAYS:
            failures.append(
                f"WARN: Package '{dep}' was published {meta['age_days']} days ago "
                f"(threshold: {MINIMUM_PACKAGE_AGE_DAYS} days). Verify this is intentional."
            )

    if failures:
        print("[pre-commit] New dependency check failed:")
        for f in failures:
            print(f"  {f}")
        sys.exit(1)

    print(f"[pre-commit] {len(new_deps)} new dependencies verified.")
    sys.exit(0)

if __name__ == '__main__':
    main()
```

This hook should be adapted for npm (`package.json` diff parsing against the npm registry API) and integrated into the organization's pre-commit framework alongside secret scanning and lint checks.

---

## Hallucinated Dependencies at Scale

### Distinction from Slopsquatting

Slopsquatting is the attacker-side exploitation of hallucinated package names: the attacker registers the hallucinated name and waits for installs. This section addresses a distinct but related problem: **detecting the hallucination itself before an attacker has the opportunity to exploit it**.

Organizations with mature AI usage policies and private registry mirrors may block slopsquatting at the install layer, but hallucinated dependencies still reach version control if developers commit lock files or dependency declarations before installation is attempted against the private registry. In organizations without registry controls, the hallucination problem is the same as the slopsquatting problem.

### Detection: AI Suggestion Monitoring

When AI coding assistants are deployed through an enterprise gateway (self-hosted or proxied), suggestion logs can be analyzed for package recommendations:

- Extract package names from AI-suggested import statements and install commands
- Cross-reference against the private registry inventory or PyPI/npm existence check
- Flag suggestions for hallucinated packages before they reach the developer's screen, or immediately after acceptance

This approach requires either an AI gateway that exposes suggestion logs (some enterprise deployments of GitHub Copilot, Amazon CodeWhisperer) or instrumentation at the IDE extension layer.

### Package Inventory Diff Gates in CI

A CI gate that diffs the package manifest between the base branch and the PR branch, then verifies each new package:

```yaml
# Example GitHub Actions step
- name: Verify new dependencies
  run: |
    BASE_PACKAGES=$(git show origin/main:requirements.txt 2>/dev/null || echo "")
    PR_PACKAGES=$(cat requirements.txt)
    NEW_PACKAGES=$(comm -13 <(echo "$BASE_PACKAGES" | sort) <(echo "$PR_PACKAGES" | sort))
    
    if [ -n "$NEW_PACKAGES" ]; then
      echo "New packages detected: $NEW_PACKAGES"
      python scripts/verify_packages.py $NEW_PACKAGES
    fi
```

The `verify_packages.py` script performs registry existence and age checks, returning non-zero exit code for unverified packages. This blocks merges that introduce hallucinated or suspiciously new packages.

---

## AI-Assisted Phishing and Social Engineering in DevSecOps Context

### AI-Generated Commit Messages Designed to Fool Reviewers

An attacker with write access to a repository (compromised developer account, malicious insider, or dependency injection via a compromised upstream repo) can use AI to generate commit messages that describe a change in misleading terms. The commit message may be:

- Factually accurate at a high level ("Fix null pointer dereference in auth handler") while omitting the security-relevant detail ("...by disabling the null check")
- Written to match the style and vocabulary of legitimate commits in the repository (AI can analyze git log to calibrate)
- Timed with a legitimate feature release to appear as a routine fix commit

**Implications for code review AI components**: AI-powered code review tools that incorporate PR descriptions and commit messages into their analysis context are vulnerable to description injection: a malicious commit message can steer the AI reviewer toward a favorable assessment of the accompanying code change. The AI reviewer sees the malicious code AND a plausible explanation for it, increasing the probability of approval.

### AI-Generated PRs with Deceptive Descriptions

The same technique applies at the PR level. A malicious actor (human or automated) can generate a PR description that:

- Accurately describes the PR's stated purpose
- Includes a security review self-attestation ("Reviewed for injection vulnerabilities — no issues found")
- References legitimate ticket numbers or design documents
- Uses technical language calibrated to reduce human reviewer scrutiny

**Mitigations:**

- Enforce separation between PR description content and code review AI analysis inputs: code review AI should not accept the PR description as a trusted summary of the change
- Require code review AI systems to produce their own independent description of the change (what the code does, not what the PR claims it does) and surface discrepancies
- Flag PRs where the AI-generated description of code behavior diverges significantly from the PR author's description
- Do not allow PR descriptions to include security attestations that bypass normal review gates

### Implications for Code Review AI Trust Models

AI-powered code review systems that use PR descriptions as context inputs are operating under a trust assumption that the PR author's description is accurate. This assumption fails in adversarial conditions. Design code review AI to:

1. Generate its own independent characterization of the change from code diff alone
2. Treat PR description content as untrusted input (apply prompt injection defenses per [prompt-injection-defense.md](./prompt-injection-defense.md))
3. Surface mismatches between claimed change purpose and observed code changes as a security signal

---

## Model Supply Chain Threats

> Full treatment: [model-supply-chain.md](./model-supply-chain.md)

This section summarizes model supply chain threats relevant to the threat intelligence context. Investigation guidance for model supply chain incidents is in [forensics-and-incident-response-framework/docs/playbooks/ai-supply-chain.md](../../forensics-and-incident-response-framework/docs/playbooks/ai-supply-chain.md).

### Registry Poisoning

Public model registries (Hugging Face, PyPI for ML packages, npm for ONNX models) are subject to the same supply chain attack patterns as code package registries, with additional attack surface:

- **Malicious serialization payloads**: PyTorch model files serialized with `pickle` can contain arbitrary code executed on deserialization. A model file hosted on Hugging Face that appears to be a legitimate fine-tune of a base model may execute malicious code when loaded.
- **Unsafe model formats**: Some model formats (`.pkl`, legacy `.pt` files) are not safe to deserialize from untrusted sources. Safe formats (SafeTensors) mitigate deserialization attacks.
- **Malicious model cards**: Model card metadata can contain prompt injection payloads that affect AI tools that parse model cards (e.g., automated model evaluation pipelines).

### Fine-Tuning Data Poisoning

An attacker who can influence a fine-tuning dataset can introduce behavioral backdoors: the model behaves normally under most conditions but produces attacker-desired outputs when a specific trigger pattern is present in the input. Fine-tuning data poisoning is particularly concerning for:

- Models fine-tuned on internal codebases (the internal codebase is the attack surface)
- Instruction-tuned models where the instruction dataset is sourced from public or third-party sources

### Model Version Substitution Attacks

A model artifact that has been reviewed and approved at version 1.0.0 may be replaced with a modified version by an attacker with write access to the model registry. Without digest pinning, users of the model will receive the modified version without any indicator of change.

### Detection: Digest Pinning and ModelScan

- Pin all model artifacts to a specific SHA-256 digest in deployment configuration
- Verify the digest at load time and fail closed if the digest does not match
- Run [ModelScan](https://github.com/protectai/modelscan) on all model artifacts before use in CI or production
- For Hugging Face models: use the platform's built-in ClamAV and ProtectAI scanner results as a prerequisite signal, not as a sufficient control

---

## Threat Actor Profiles for AI-Targeting Attacks

### Opportunistic Actors

**Motivation**: Financial gain through credential theft, cryptomining, or data exfiltration via compromised development environments.

**Capabilities**: Low to moderate. Automated tooling to identify hallucinated package names at scale, basic package publishing capability.

**Tactics for AI-targeting attacks**:
- Automated prompting of public AI assistants to collect hallucinated package name candidates
- Bulk registration of candidate names in PyPI and npm
- Malicious post-install scripts targeting developer machine credentials (SSH keys, AWS credentials, `.npmrc` tokens)
- Wide-net approach: register many names and collect installs passively

**Detection signals**: Bulk package registration activity from new accounts, packages with identical post-install script patterns across accounts.

### Targeted Actors

**Motivation**: Access to specific organizations, source code theft, supply chain compromise for downstream targets.

**Capabilities**: Moderate to high. Ability to craft context-appropriate attacks tailored to a target organization's technology stack and AI tool usage.

**Tactics for AI-targeting attacks**:
- Research target organization's AI tool stack (observable from job postings, conference talks, open-source contributions)
- Craft indirect prompt injection payloads placed in data sources the target organization's AI pipelines consume (CVE databases, public GitHub issues, package documentation)
- AI-generated PR descriptions designed to pass code review AI and human review for the target repository's review patterns
- Slopsquatting tailored to the specific libraries the target organization uses (observable from public repositories)

**Detection signals**: Prompt injection payloads in CVE entries or package documentation that are thematically aligned with a specific organization's technology; targeted phishing using accurate organizational detail.

### Nation-State Actors

**Motivation**: Strategic intelligence collection, long-term persistence, supply chain compromise for downstream targeting of the organization's customers or infrastructure.

**Capabilities**: High. Access to resources for sophisticated model supply chain compromise, long-term infrastructure for persistent access.

**Tactics for AI-targeting attacks**:
- Fine-tuning data poisoning of models used in security tooling or code review (introduces subtle behavioral biases in security recommendations)
- Model supply chain compromise via compromise of model hosting infrastructure or model provider
- Long-term credential persistence through developer environment compromise via slopsquatting, used as a staging point for broader network access

**Detection signals**: Model behavior anomalies on specific trigger inputs; unusual model registry access patterns; correlation between compromised developer environments and subsequent lateral movement.

---

## Threat Intelligence Integration

### Relevant External Feeds

**OpenSSF Package Threat Feeds**
- The Open Source Security Foundation maintains security metadata for major open-source ecosystems
- Alpha-Omega project produces security reviews of high-criticality packages
- Package health scoring from OpenSSF Scorecard is a signal for new dependency assessment

**npm and PyPI Suspicious Package Notifications**
- PyPI has a malware reporting mechanism; security researchers report confirmed malicious packages
- npm maintains a list of packages removed for security violations
- Integrate these feeds into the private registry approval workflow: any package flagged in these feeds is ineligible for approval

**Hugging Face Model Scanner Results**
- Hugging Face runs ProtectAI's ModelScan and ClamAV on uploaded model files
- Scanner results are exposed in the model card metadata
- Query the Hugging Face Hub API for scanner results as part of model approval workflow

**CISA Known Exploited Vulnerabilities (KEV) for AI Components**
- Monitor KEV for vulnerabilities in AI infrastructure: inference servers (Triton, vLLM, Ollama), ML frameworks (PyTorch, TensorFlow), and model serving platforms
- These vulnerabilities may be exploitable via model files or inference API requests

### Internal Signals

**New Dependency Introduced via AI Suggestion**

When a developer introduces a new dependency immediately following an AI coding assistant session, this is a risk signal. Detection approach:
- Parse PR metadata for description text indicating AI-assisted development
- Identify AI coding assistant session timing from IDE telemetry (if available)
- Flag PRs where: (a) new dependency is introduced, (b) PR was created within a short window after AI tool use, (c) dependency does not exist in the approved registry

**CI Anomaly Detection on AI Component Outputs**

AI components in CI pipelines (security scanners, code reviewers, test generators) should have their outputs monitored for anomaly patterns:
- Unusual suggestion patterns: an AI code reviewer that suddenly recommends disabling security checks
- Output length or format anomalies that may indicate prompt injection affecting the output structure
- Tool call anomalies from agentic AI components: unexpected tool invocations, unusual parameter values

**Git Blame and PR Description Analysis**

Automated analysis of git blame for newly introduced dependencies cross-referenced with PR descriptions:
- Identify the commit that introduced each new dependency
- Check if the commit was introduced as part of a PR where the description contains indicators of AI-generated content
- This does not block AI-assisted development; it adds a verification gate for the specific risk of unverified AI package suggestions

### Sharing and Disclosure

**Coordinated Disclosure for Slopsquatting Discoveries**

When a slopsquatting package is identified:
1. Do not install or execute the malicious package in a production environment
2. Preserve registry metadata (publish date, author, post-install script) before reporting
3. Report to the affected registry's security team (PyPI security@python.org, npm security@npmjs.com)
4. Report to OpenSSF's malicious packages repository if the package is confirmed malicious
5. If the malicious package was suggested by a specific AI tool: report to that tool's vendor with evidence of the hallucination pattern

**Responsible Disclosure for AI System Vulnerabilities**

Prompt injection vulnerabilities and model behavior anomalies in AI systems used in DevSecOps tooling should be reported through the vendor's security disclosure process. Key considerations:
- Document the injection vector, payload, and observed behavior change
- Assess the blast radius: does the vulnerability affect only the reporting organization, or is it exploitable against any user of the tool?
- Maintain a reasonable disclosure timeline (90 days is standard; 30 days may be appropriate for actively exploited vulnerabilities)

---

## Detection Indicators and Response

### YARA-Style Heuristics for Slopsquatting Package Identification

The following pseudo-YARA rules describe heuristics for identifying slopsquatting packages. These should be implemented as checks in the CI pipeline or private registry approval workflow.

```
rule slopsquatting_candidate_pypi {
    meta:
        description = "Identifies PyPI packages that match slopsquatting risk profile"
        risk = "HIGH"
    condition:
        package.publish_date_age_days < 30
        AND package.total_downloads < 100
        AND (
            package.name matches /-(utils|helpers|tools|extras|adapter|shim|bridge|client)$/i
            OR package.name matches /^(openai|anthropic|langchain|llamaindex|huggingface|transformers)-/i
        )
        AND package.has_postinstall_script == true
}

rule slopsquatting_candidate_npm {
    meta:
        description = "Identifies npm packages that match slopsquatting risk profile"
        risk = "HIGH"
    condition:
        package.publish_date_age_days < 30
        AND package.weekly_downloads < 50
        AND (
            package.name matches /-(utils|helpers|sdk|client|adapter|wrapper)$/i
            OR package.name matches /^(openai|anthropic|langchain|vercel-ai|ai-sdk)-/i
        )
        AND package.scripts.postinstall is not null
}
```

These heuristics will produce false positives on legitimate new packages. The intent is to require human review, not automatic rejection.

### SIEM Query Templates

**Anomalous package install after AI tool interaction**

For SIEM environments with developer endpoint telemetry (EDR agents capturing process events):

```spl
# Splunk SPL
index=endpoint sourcetype=process_events
| where process_name IN ("pip", "pip3", "npm", "yarn", "pnpm")
| where command_line LIKE "% install %"
| join type=left user_id [
    search index=endpoint sourcetype=process_events
    process_name IN ("code", "cursor", "idea", "pycharm")
    | eval ai_session_end = _time
    | stats max(ai_session_end) as last_ai_session by user_id
]
| where _time - last_ai_session < 1800  /* 30 minutes after AI tool session */
| eval new_package = mvindex(split(command_line, "install "), 1)
| table _time, user_id, host, new_package, last_ai_session
| sort -_time
```

**Hallucinated package names in requirements files**

```spl
# Detect commits introducing packages not in approved registry
index=ci_logs sourcetype=pipeline_events event_type="dependency_check"
| where verification_status="NOT_IN_REGISTRY"
| table _time, repo, branch, pr_number, package_name, introduced_by
| sort -_time
```

**Post-install script execution in CI runner**

```spl
index=ci_logs sourcetype=runner_events
| where (
    (process_name="node" AND command_line LIKE "%postinstall%")
    OR (process_name="python" AND command_line LIKE "%post_install%")
)
| where parent_process IN ("npm", "pip", "yarn", "pnpm")
| table _time, runner_id, repo, build_id, process_name, command_line
| sort -_time
```

### Incident Response Handoff

When detection signals indicate a potential AI-assisted supply chain attack:

1. **Triage**: Determine if a malicious package was installed (in developer environment, CI runner, container image, or production artifact) using the package inventory and SBOM from the affected build.

2. **Escalation threshold**: Any confirmed install of a package matching the slopsquatting risk profile warrants activation of the supply chain incident investigation playbook.

3. **Handoff to forensics**: Initiate the investigation procedure in [forensics-and-incident-response-framework/docs/playbooks/ai-supply-chain.md](../../forensics-and-incident-response-framework/docs/playbooks/ai-supply-chain.md). Provide:
   - Package name and version installed
   - Registry metadata snapshot (publish date, author, post-install script content)
   - SBOM from affected builds
   - CI/CD run logs from the affected pipeline execution
   - Git commit hash and PR number where the dependency was introduced
   - Any AI tool interaction logs available

4. **Containment**: Block the package in the private registry mirror before investigation completes. Quarantine affected builds pending forensic determination.

---

## Document Metadata

| Field | Value |
|-------|-------|
| Framework | AI DevSecOps Framework |
| Document type | Threat Intelligence Reference |
| Audience | Security engineers, DevSecOps platform teams, CTI analysts |
| Related documents | developer-environment-controls.md, model-supply-chain.md, prompt-injection-defense.md |
| Incident playbook | forensics-and-incident-response-framework/docs/playbooks/ai-supply-chain.md |
| License | Apache 2.0 |
