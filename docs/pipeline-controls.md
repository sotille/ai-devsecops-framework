# Pipeline Controls for AI Components

## Table of Contents

- [AI Pipeline Security Checklist](#ai-pipeline-security-checklist)
- [Platform-Specific Permission Scoping](#platform-specific-permission-scoping)
- [Input Sanitization for LLM Inputs in GitHub Actions](#input-sanitization-for-llm-inputs-in-github-actions)
- [Tool Execution Sandbox](#tool-execution-sandbox)
- [AI Component Audit Trail: Structured Log Format](#ai-component-audit-trail-structured-log-format)
- [Circuit Breaker Pattern for AI Components](#circuit-breaker-pattern-for-ai-components)
- [Cross-Reference: Pipeline Hardening Checklist](#cross-reference-pipeline-hardening-checklist)

---

## AI Pipeline Security Checklist

This checklist must be completed before any AI component is added to a production pipeline. Each item is binary (complete or incomplete) — partial completion does not satisfy the requirement.

### Identity and Authorization

- [ ] AI component has a dedicated identity (service account, GitHub App installation, OIDC subject) not shared with human users or other pipeline components
- [ ] Tool authorization policy is documented in version-controlled YAML and reviewed by the security team
- [ ] The AI component's credentials do not grant access to any resource not required for its defined role
- [ ] AI component credentials cannot be used to modify the AI component's own authorization policy or system prompt
- [ ] Session-scoped tokens are used; credentials expire at task completion (not persistent standing credentials)

### Prompt Injection Defense

- [ ] All user-controlled and externally-sourced text is passed to the LLM as `user` role content, never as `system` role content
- [ ] Input sanitization is applied before including external content in the LLM context
- [ ] Output validation is applied before using LLM output in downstream pipeline steps
- [ ] A prompt canary token is embedded in the system prompt and monitored for leakage
- [ ] Adversarial tests for injection resistance are included in the AI component's test suite

### Audit and Observability

- [ ] Every tool invocation is logged with the minimum audit record fields (see [agent-audit-trail.md](agent-audit-trail.md))
- [ ] Audit logs are written to an external, append-only store that the AI component cannot modify
- [ ] System prompt is version-controlled and the SHA is recorded in each session initialization record
- [ ] Tool authorization policy version (git SHA) is recorded in every audit log entry
- [ ] Behavioral monitoring is configured with baseline metrics and alert thresholds

### Secrets and Credentials

- [ ] AI provider API keys are stored in a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager), not in environment variables or repository files
- [ ] API keys are rotated on a defined schedule (at minimum, quarterly or on personnel changes)
- [ ] Pipeline does not log raw LLM inputs or outputs to shared log aggregators (secrets may appear in context)
- [ ] Secret redaction is applied before any LLM context is logged

### Security Gates

- [ ] LLM component outputs are not used as the sole decision-maker for security-relevant pass/fail criteria
- [ ] Deterministic tools (SAST, SCA) run independently of AI components and their results are the authoritative gate
- [ ] Circuit breaker is configured: if the AI component is unavailable, the pipeline continues with deterministic-only controls (not blocked, not fail-open on security gates)

### Approval Gates

- [ ] All irreversible actions (merges, deployments, resource deletion) require out-of-band human approval that cannot be bypassed by the AI component
- [ ] Approval gates are implemented via platform mechanisms (environment protection rules, CODEOWNERS) not via LLM instructions

### Dependency and Model Supply Chain

- [ ] The AI model version used by this component is pinned (not `latest`) and recorded in the pipeline configuration
- [ ] The pinned model version is in the approved model registry
- [ ] For self-hosted models: model weights were scanned with `modelscan` before deployment
- [ ] Model provider API keys are included in the secret rotation and audit program

---

## Platform-Specific Permission Scoping

### GitHub Actions

GitHub Actions workflows running AI components should use GitHub App installation tokens with minimum required permissions, rather than personal access tokens or `GITHUB_TOKEN` with elevated permissions.

```yaml
# .github/workflows/ai-review.yml
# Minimal permissions for a PR review AI component

name: AI Security Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  # ONLY the permissions required for the AI review component
  contents: read          # Read PR diff and repository files
  pull-requests: write    # Post review comments
  # All other permissions explicitly absent (defaults to none)

jobs:
  ai-security-review:
    runs-on: ubuntu-latest
    # Environment enforces that this job does not have deploy permissions
    # and isolates secrets to this specific workflow
    steps:
      - name: Checkout PR
        uses: actions/checkout@v4
        with:
          # Shallow clone — only what is needed for the diff
          fetch-depth: 0
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Run AI Security Review
        id: ai_review
        env:
          # API key from secrets manager, not repository secrets
          # Use GitHub OIDC to fetch from AWS Secrets Manager or Vault
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          # Pass PR metadata as structured input, not free-form text
          PR_NUMBER: ${{ github.event.pull_request.number }}
          PR_TITLE: ${{ github.event.pull_request.title }}
          REPO: ${{ github.repository }}
        run: |
          python scripts/ai_security_review.py \
            --repo "$REPO" \
            --pr "$PR_NUMBER" \
            --output-format json \
            --output-file review_output.json

      - name: Validate AI output schema
        run: |
          python scripts/validate_review_output.py review_output.json
          # Non-zero exit if schema invalid or canary detected

      - name: Post review comments (advisory only)
        if: success()
        run: |
          python scripts/post_review_comments.py \
            --input review_output.json \
            --advisory-label "AI-assisted review — not a security gate"
            # Note: this step posts comments but does not approve or block the PR
```

**GitHub App permissions for a reviewer agent GitHub App:**

```json
{
  "permissions": {
    "contents": "read",
    "pull_requests": "write",
    "issues": "read",
    "metadata": "read"
  },
  "events": ["pull_request"]
}
```

### GitLab CI

```yaml
# .gitlab-ci.yml — AI review component with minimal permissions
# Use GitLab CI/CD variables from CI/CD settings (not committed to repository)

ai-security-review:
  stage: review
  image: python:3.12-slim
  # Restrict to protected branches only for the AI component with tool access
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

  # Use a dedicated service account's runner token, not the project's default token
  tags:
    - ai-review-runner  # Dedicated runner with scoped registration

  variables:
    # Prevent GitLab from logging the API key value
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY_SECRET
    GIT_DEPTH: 0

  before_script:
    # Validate that we have the expected environment
    - python --version
    - pip install -r requirements-review.txt --quiet

  script:
    - |
      python scripts/ai_security_review.py \
        --mr-iid "$CI_MERGE_REQUEST_IID" \
        --project-id "$CI_PROJECT_ID" \
        --gitlab-token "$AI_REVIEWER_TOKEN" \
        --output-format json \
        --output-file review_output.json
    - python scripts/validate_review_output.py review_output.json

  artifacts:
    paths:
      - review_output.json
    when: always
    expire_in: 7 days

  # Critical: this job does not affect pipeline pass/fail for security gates
  # Security gates are in separate jobs with deterministic tools (SAST, SCA)
  allow_failure: true
```

### Jenkins

```groovy
// Jenkinsfile — AI review component with credential scoping

pipeline {
    agent { label 'ai-review-agent' }  // Dedicated agent with minimal host permissions

    stages {
        stage('AI Security Review') {
            when {
                changeRequest()  // Only on pull requests
            }
            steps {
                // Use Jenkins Credentials binding — API key never in Jenkinsfile
                withCredentials([
                    string(credentialsId: 'anthropic-api-key', variable: 'ANTHROPIC_API_KEY'),
                    string(credentialsId: 'github-review-token', variable: 'GITHUB_REVIEW_TOKEN')
                ]) {
                    sh '''
                        python scripts/ai_security_review.py \
                            --pr "${CHANGE_ID}" \
                            --repo "${GIT_URL}" \
                            --output-format json \
                            --output-file review_output.json
                        python scripts/validate_review_output.py review_output.json
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'review_output.json'
                }
            }
        }

        stage('SAST Gate') {
            // This is the authoritative security gate — deterministic, not AI
            steps {
                sh 'semgrep --config=p/owasp-top-ten --error .'
            }
        }
    }
}
```

---

## Input Sanitization for LLM Inputs in GitHub Actions

The following Python script implements input sanitization for an AI review component running in GitHub Actions. It should be run before passing any user-controlled or externally-sourced text to the LLM.

```python
#!/usr/bin/env python3
# scripts/sanitize_pr_inputs.py
# Sanitize PR inputs before including them in LLM context.
# Run as a pipeline step before the AI analysis step.
#
# Usage:
#   python sanitize_pr_inputs.py \
#     --pr-title "$PR_TITLE" \
#     --pr-description-file pr_description.txt \
#     --diff-file pr.diff \
#     --output sanitized_inputs.json

import argparse
import json
import re
import sys
import hashlib
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Common injection attempt patterns
# NOTE: This is a heuristic — do not treat this as a complete defense.
# Apply all defense-in-depth layers; this is one of six layers.
INJECTION_PATTERNS = [
    (r'\[SYSTEM[\s\S]*?\]', 'bracket-system-directive'),
    (r'IGNORE\s+(ALL\s+)?PREVIOUS\s+INSTRUCTIONS?', 'ignore-instructions'),
    (r'SYSTEM\s+OVERRIDE', 'system-override'),
    (r'NEW\s+(PRIMARY\s+)?TASK\s*:', 'new-task'),
    (r'DISREGARD\s+(YOUR|ALL)\s+(PREVIOUS\s+|PRIOR\s+)?INSTRUCTIONS?', 'disregard-instructions'),
    (r'YOU\s+ARE\s+NOW\s+(A|AN)\s+', 'role-reassignment'),
    (r'ACT\s+AS\s+(IF\s+YOU\s+ARE\s+)?(A|AN)\s+', 'act-as'),
    (r'<system>[\s\S]*?</system>', 'xml-system-tag'),
    (r'<!--[\s\S]*?(SYSTEM|INSTRUCTION|OVERRIDE)[\s\S]*?-->', 'html-comment-directive'),
    (r'```[\s\S]*?SYSTEM\s*[\r\n][\s\S]*?```', 'code-block-system'),
    (r'REPEAT\s+THE\s+(TEXT|INSTRUCTIONS?|PROMPT)\s+ABOVE', 'repeat-above'),
    (r'PRINT\s+YOUR\s+(SYSTEM\s+)?PROMPT', 'print-prompt'),
    (r'SUMMARIZE\s+YOUR\s+(SYSTEM\s+)?INSTRUCTIONS?', 'summarize-instructions'),
]

MAX_LENGTHS = {
    'title': 256,
    'description': 16384,
    'diff': 65536,
    'commit_message': 1024,
}

def sanitize_text(text: str, field_name: str, max_length: int) -> tuple[str, list[dict]]:
    """
    Sanitize a single text field.
    Returns (sanitized_text, list_of_detections).
    """
    detections = []
    sanitized = text

    for pattern, pattern_name in INJECTION_PATTERNS:
        matches = re.findall(pattern, sanitized, re.IGNORECASE | re.MULTILINE)
        if matches:
            detections.append({
                'field': field_name,
                'pattern': pattern_name,
                'match_count': len(matches)
            })
            sanitized = re.sub(
                pattern,
                f'[filtered:{pattern_name}]',
                sanitized,
                flags=re.IGNORECASE | re.MULTILINE
            )

    # Enforce length limit
    if len(sanitized) > max_length:
        original_length = len(sanitized)
        sanitized = sanitized[:max_length]
        detections.append({
            'field': field_name,
            'pattern': 'length-truncation',
            'match_count': 1,
            'detail': f'Truncated from {original_length} to {max_length} chars'
        })

    return sanitized, detections

def main():
    parser = argparse.ArgumentParser(description='Sanitize PR inputs for LLM context')
    parser.add_argument('--pr-title', required=True)
    parser.add_argument('--pr-description-file', required=False)
    parser.add_argument('--diff-file', required=False)
    parser.add_argument('--output', required=True)
    parser.add_argument('--fail-on-injection', action='store_true',
                        help='Exit with code 1 if injection patterns are detected')
    args = parser.parse_args()

    all_detections = []
    sanitized_inputs = {}

    # Sanitize PR title
    title, detections = sanitize_text(
        args.pr_title, 'title', MAX_LENGTHS['title']
    )
    sanitized_inputs['title'] = title
    all_detections.extend(detections)

    # Sanitize PR description
    if args.pr_description_file:
        description = Path(args.pr_description_file).read_text(encoding='utf-8', errors='replace')
        sanitized_desc, detections = sanitize_text(
            description, 'description', MAX_LENGTHS['description']
        )
        sanitized_inputs['description'] = sanitized_desc
        all_detections.extend(detections)

    # Sanitize diff (less aggressive — must not modify code content)
    # For the diff, we only truncate — do not modify code content
    if args.diff_file:
        diff = Path(args.diff_file).read_text(encoding='utf-8', errors='replace')
        if len(diff) > MAX_LENGTHS['diff']:
            sanitized_inputs['diff'] = diff[:MAX_LENGTHS['diff']]
            all_detections.append({
                'field': 'diff',
                'pattern': 'length-truncation',
                'match_count': 1,
                'detail': f'Diff truncated from {len(diff)} to {MAX_LENGTHS["diff"]} chars'
            })
        else:
            sanitized_inputs['diff'] = diff

    # Compute hashes of sanitized inputs for audit trail
    sanitized_inputs['_audit'] = {
        'title_hash': hashlib.sha256(sanitized_inputs.get('title', '').encode()).hexdigest(),
        'description_hash': hashlib.sha256(sanitized_inputs.get('description', '').encode()).hexdigest(),
        'diff_hash': hashlib.sha256(sanitized_inputs.get('diff', '').encode()).hexdigest(),
        'detections': all_detections,
        'injection_patterns_detected': len(all_detections) > 0
    }

    # Write sanitized output
    Path(args.output).write_text(json.dumps(sanitized_inputs, indent=2))

    # Log detections
    if all_detections:
        logger.warning(f"Injection patterns detected: {len(all_detections)} match(es)")
        for detection in all_detections:
            logger.warning(f"  Field: {detection['field']}, Pattern: {detection['pattern']}")

    # Fail if requested and patterns detected
    if args.fail_on_injection and any(
        d['pattern'] != 'length-truncation' for d in all_detections
    ):
        logger.error("Exiting with error: injection patterns detected and --fail-on-injection set")
        sys.exit(1)

    logger.info(f"Sanitized inputs written to {args.output}")

if __name__ == '__main__':
    main()
```

---

## Tool Execution Sandbox

Each agent tool invocation should run in an isolated container to limit blast radius. If a tool invocation is compromised (via injection that causes it to run with malicious parameters), the sandbox prevents the compromise from propagating to the pipeline host or other pipeline components.

```yaml
# docker-compose.yaml — tool execution sandbox configuration
# Each tool invocation gets a fresh, isolated container

version: "3.9"
services:
  tool-executor:
    image: ghcr.io/techstream/tool-executor:1.2.0
    read_only: true               # Immutable filesystem
    security_opt:
      - no-new-privileges:true    # Prevent privilege escalation
      - seccomp:./seccomp-profile.json  # Restrict syscalls
    cap_drop:
      - ALL                       # Drop all Linux capabilities
    cap_add:
      - NET_CONNECT               # Only capability needed: network connection
    networks:
      - tool-net                  # Isolated network; cannot reach internal cluster
    tmpfs:
      - /tmp:size=64m,noexec      # Writable temp space; no execution from /tmp
    environment:
      # Tool-specific credentials injected per invocation
      # Not persisted; expire after invocation completes
      GITHUB_TOKEN: ""            # Injected at runtime from Vault
    resource_limits:
      cpus: "0.5"
      memory: "256m"
    restart: "no"                 # Never restart; single invocation only

networks:
  tool-net:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: tool-net0
    ipam:
      config:
        - subnet: 172.30.0.0/24
```

---

## AI Component Audit Trail: Structured Log Format

Every AI pipeline component invocation must emit structured JSON logs. These are distinct from the tool invocation audit records — they capture the invocation of the AI component as a whole (one record per pipeline step run) rather than individual tool calls within an agent session.

```json
{
  "schema_version": "1.0",
  "event_type": "ai_pipeline_invocation",
  "timestamp": "2024-01-15T14:23:45.123Z",
  "pipeline": {
    "platform": "github_actions",
    "workflow": "security-review.yml",
    "job": "ai-security-review",
    "run_id": "7654321098",
    "run_attempt": 1,
    "trigger": "pull_request",
    "repository": "org/repo",
    "ref": "refs/pull/456/merge",
    "sha": "a1b2c3d4e5f6..."
  },
  "component": {
    "name": "pr-security-reviewer",
    "version": "2.1.0",
    "model": "claude-3-5-sonnet-20241022",
    "model_provider": "anthropic",
    "system_prompt_sha": "4a5b6c7d8e9f..."
  },
  "input": {
    "source": "github_pull_request",
    "pr_number": 456,
    "pr_author": "developer_name",
    "input_content_hash": "sha256:1a2b3c...",
    "sanitization_applied": true,
    "injection_patterns_detected": false
  },
  "output": {
    "output_content_hash": "sha256:9f8e7d...",
    "schema_valid": true,
    "findings_count": 3,
    "canary_in_output": false,
    "output_used_as": "advisory_comments_only"
  },
  "execution": {
    "duration_ms": 3421,
    "tokens_used": 2847,
    "api_latency_ms": 3105,
    "success": true
  },
  "security": {
    "advisory_only": true,
    "used_as_security_gate": false,
    "deterministic_gate_result": "PASS"
  }
}
```

---

## Circuit Breaker Pattern for AI Components

AI pipeline components can fail for reasons outside the pipeline's control: model provider outages, API rate limiting, network connectivity issues, or unexpected model behavior. The pipeline should not be blocked by AI component failures, nor should it fall back to unsafe defaults.

```python
#!/usr/bin/env python3
# scripts/ai_component_wrapper.py
# Circuit breaker wrapper for AI pipeline components.
# Falls back to non-AI controls when the AI component is unavailable.

import time
import logging
import json
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # AI component unavailable; using fallback
    HALF_OPEN = "half_open" # Testing if AI component has recovered

@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 3       # Failures before opening
    success_threshold: int = 2       # Successes in HALF_OPEN before closing
    recovery_timeout: float = 300.0  # Seconds before attempting recovery
    request_timeout: float = 30.0    # Seconds before considering a request failed

@dataclass
class CircuitBreaker:
    config: CircuitBreakerConfig
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0.0
    component_name: str = "ai-component"

    def call(self, ai_func: Callable, fallback_func: Callable, *args, **kwargs) -> Any:
        """
        Execute ai_func if circuit is closed; fallback_func if open.
        """
        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time > self.config.recovery_timeout:
                logger.info(f"[{self.component_name}] Circuit transitioning to HALF_OPEN")
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
            else:
                logger.warning(
                    f"[{self.component_name}] Circuit OPEN — using fallback",
                    extra={"component": self.component_name, "state": "open"}
                )
                return self._execute_fallback(fallback_func, *args, **kwargs)

        # CLOSED or HALF_OPEN: attempt AI component
        try:
            import signal

            def timeout_handler(signum, frame):
                raise TimeoutError(f"AI component timed out after {self.config.request_timeout}s")

            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(self.config.request_timeout))

            try:
                result = ai_func(*args, **kwargs)
            finally:
                signal.alarm(0)

            self._record_success()
            return result

        except Exception as e:
            logger.error(
                f"[{self.component_name}] AI component failed: {e}",
                extra={"component": self.component_name, "error": str(e)}
            )
            self._record_failure()

            if self.state == CircuitState.OPEN:
                return self._execute_fallback(fallback_func, *args, **kwargs)

            raise  # Re-raise if circuit just opened — caller handles first failure

    def _record_success(self):
        self.failure_count = 0
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                logger.info(f"[{self.component_name}] Circuit CLOSED — AI component recovered")
                self.state = CircuitState.CLOSED

    def _record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.config.failure_threshold:
            if self.state != CircuitState.OPEN:
                logger.warning(
                    f"[{self.component_name}] Circuit OPENING after {self.failure_count} failures",
                    extra={"component": self.component_name, "state": "opening"}
                )
            self.state = CircuitState.OPEN

    def _execute_fallback(self, fallback_func: Callable, *args, **kwargs) -> Any:
        logger.info(f"[{self.component_name}] Executing fallback controls")
        result = fallback_func(*args, **kwargs)
        # Tag result so downstream steps know it came from fallback
        if isinstance(result, dict):
            result["_source"] = "fallback_non_ai"
            result["_ai_component_available"] = False
        return result


# Usage example in a security pipeline step
from dataclasses import dataclass

@dataclass
class ReviewResult:
    findings: list
    advisory_comments: list
    source: str

def ai_security_review(pr_diff: str, pr_metadata: dict) -> ReviewResult:
    """AI-powered security review — may fail or be unavailable."""
    # ... call LLM API ...
    pass

def fallback_security_review(pr_diff: str, pr_metadata: dict) -> ReviewResult:
    """
    Fallback: run deterministic analysis only when AI component is unavailable.
    The pipeline continues without AI augmentation — security gates still enforce
    SAST/SCA results deterministically.
    """
    logger.info("Running fallback security review (deterministic only)")
    # Run Semgrep directly and format output for the pipeline
    import subprocess
    result = subprocess.run(
        ['semgrep', '--config=p/owasp-top-ten', '--json', '.'],
        capture_output=True, text=True
    )
    findings = json.loads(result.stdout).get('results', [])
    return ReviewResult(
        findings=findings,
        advisory_comments=[{
            "body": "AI-assisted review unavailable. Deterministic SAST results shown.",
            "type": "system_message"
        }],
        source="fallback_deterministic"
    )

# Initialize circuit breaker
circuit = CircuitBreaker(
    config=CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=300.0,
        request_timeout=30.0
    ),
    component_name="pr-security-reviewer"
)

# Use in pipeline
review_result = circuit.call(
    ai_security_review,
    fallback_security_review,
    pr_diff="...",
    pr_metadata={"number": 456}
)
```

---

## Cross-Reference: Pipeline Hardening Checklist

The AI pipeline security controls in this document extend the baseline pipeline hardening checklist in the [Secure Pipeline Templates](../secure-pipeline-templates/) repository.

See [secure-pipeline-templates/docs/hardening-checklist.md](../secure-pipeline-templates/docs/hardening-checklist.md) Section 11 for the baseline pipeline security controls that must be in place before AI components are added. The controls in this document are additive — they address the AI-specific attack surface on top of the baseline hardened pipeline.

Specifically, the following sections of the baseline checklist are prerequisite to deploying AI pipeline components:

- Section 5 (Secrets Management): API keys for AI providers must be managed with the same controls as cloud credentials
- Section 7 (Runner/Agent Hardening): AI components may run on shared runners; verify ephemeral runner configuration
- Section 8 (Audit Logging): AI component invocations must appear in the same audit stream as other pipeline events
- Section 11 (Pipeline Access Controls): Confirm that the AI component's credentials are scoped using the baseline least-privilege controls before adding AI-specific tool authorization policy
