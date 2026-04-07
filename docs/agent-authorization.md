# Agent Authorization

## Table of Contents

- [The Principle of Least Authority for Agents](#the-principle-of-least-authority-for-agents)
- [Agent Role Taxonomy](#agent-role-taxonomy)
- [Tool Authorization Policy as YAML](#tool-authorization-policy-as-yaml)
- [Approval Gate Requirements](#approval-gate-requirements)
- [Implementation: GitHub Actions Environment Protection Rules](#implementation-github-actions-environment-protection-rules)
- [Implementation: Kubernetes RBAC](#implementation-kubernetes-rbac)
- [Session Scoping and Token Lifecycle](#session-scoping-and-token-lifecycle)
- [Audit Requirements](#audit-requirements)

---

## The Principle of Least Authority for Agents

The Principle of Least Authority (POLA) states that every component of a system should be able to access only the information and resources that are necessary for its legitimate purpose, and no more.

Applied to AI agents, POLA has implications beyond traditional IAM least-privilege:

**Tool permissions, not just resource permissions.** An agent's authority is defined by which tools it can invoke, not just which cloud resources it can access. Two agents might both have read access to the same S3 bucket, but one is authorized to call the `deploy.production` tool and the other is not. Tool authorization policy must be managed independently of cloud IAM policy.

**Session-scoped authority.** Agent permissions should be scoped to the duration and purpose of a specific session. A remediation agent working on a specific CVE should have permissions scoped to that task — not a persistent standing permission to create PRs for any purpose at any time. When the session ends, the permissions expire.

**Non-delegatable beyond initial grant.** An agent cannot delegate to a subagent more authority than it was granted. If the orchestrator can create PRs but not merge them, it cannot spawn a subagent that can merge PRs. The authority ceiling for any subagent is the authority of its parent.

**Enforced at execution, not at the LLM.** Tool authorization is not enforced by instructing the LLM "only use these tools." It is enforced by the tool execution layer, which validates the agent's authorization token against the policy before executing any tool call. The LLM may attempt to invoke an unauthorized tool (especially if injected); the execution layer rejects the call.

**Self-modification is prohibited.** An agent must not have the ability to modify its own tool authorization policy, system prompt, IAM role, OIDC token claims, or logging configuration. If any of these can be modified by the agent itself, an injected instruction can expand the agent's authority without human oversight.

---

## Agent Role Taxonomy

The following agent roles represent the standard pattern for agents operating in a DevSecOps delivery pipeline. Organizations should adapt this taxonomy to their specific workflow, but the permission boundaries between roles must be maintained.

### Reviewer Agent

**Purpose:** Analyzes pull requests and posts security-relevant review comments.

**Read access:**
- Repository contents (code diff for the current PR)
- PR metadata (title, description, labels, author)
- Issue links referenced by the PR
- Relevant configuration files (security policy, dependency manifests)

**Write access:**
- Post review comments on the current PR
- Post line-level code suggestions on the current PR

**Prohibited:**
- Approve or merge PRs
- Create branches or commits
- Invoke any deployment tool
- Access other repositories
- Read credentials or secrets

**Session duration:** Maximum 2 hours per PR review session.

### Triage Agent

**Purpose:** Processes security alerts and issues; updates metadata to support human prioritization.

**Read access:**
- Security alert feeds (Dependabot, GitHub Security Advisories, SAST findings)
- Issue and ticket content
- CVE data feeds
- Repository metadata (language, team assignments)

**Write access:**
- Update issue labels (priority, component, status)
- Post triage analysis comments on issues
- Create new issues for tracked vulnerabilities

**Prohibited:**
- Modify or dismiss security alerts (requires human confirmation)
- Create PRs or code changes
- Access deployment systems
- Mark findings as false positives without human confirmation

**Session duration:** Continuous (long-running), with per-alert session context.

### Remediation Agent

**Purpose:** Generates automated fixes for well-defined vulnerability classes (e.g., dependency version updates, known insecure function replacements) and submits them for human review.

**Read access:**
- Repository contents (affected files)
- Dependency manifests and lock files
- Relevant security advisories and remediation guidance
- Project build and test configuration

**Write access:**
- Create branches (naming constraint: `fix/ai-remediation-*`)
- Create commits on AI-created branches only
- Create pull requests targeting the main development branch

**Prohibited:**
- Merge PRs (all AI-created PRs require human review and approval before merge)
- Delete branches other than its own AI-created branches
- Access deployment tools
- Modify CODEOWNERS or security policy files

**Session duration:** Maximum 1 hour per remediation task.

### Monitor Agent

**Purpose:** Reads operational data (logs, metrics, alerts) and creates incident tickets or notifications.

**Read access:**
- Application logs (read-only, specified log groups)
- Metrics and APM dashboards (read-only)
- Alert feeds from monitoring systems
- Deployment history (read-only)

**Write access:**
- Create incident tickets (PagerDuty, Jira Service Management)
- Send Slack notifications to designated channels
- Update ticket status on incidents it created

**Prohibited:**
- Modify application configuration
- Scale or restart services (requires human approval)
- Modify routing rules or infrastructure
- Write to log streams it reads (anti-repudiation requirement)
- Silence or acknowledge alerts on behalf of on-call engineers

**Session duration:** Continuous (long-running monitor).

---

## Tool Authorization Policy as YAML

Tool authorization policy is expressed as machine-readable YAML, stored in version control with the same review and approval requirements as production infrastructure code, and enforced by the tool execution layer at runtime. The policy version (git SHA) is recorded in every audit log entry.

```yaml
# agent-tool-policy.yaml
# This file defines the tool authorization policy for all AI agents in the delivery pipeline.
# Changes require review from the security team and the platform team (see CODEOWNERS).
# Policy version is recorded by git SHA in all agent audit log entries.

schema_version: "1.0"

# Global enforcement settings
enforcement:
  default_deny: true          # Any tool not explicitly listed is denied
  policy_version_logging: true # Record policy git SHA in every audit entry
  session_expiry_enforced: true
  self_modification_prohibited: true
  logging_modification_prohibited: true

# Agent role definitions
agents:
  reviewer:
    display_name: "PR Security Reviewer Agent"
    description: "Analyzes pull requests and posts security review comments"
    identity:
      oidc_subject_pattern: "reviewer-agent:session-*"
      service_account: "reviewer-agent"
      kubernetes_namespace: "ai-agents"

    session:
      max_duration: "2h"
      scope: "per-pull-request"  # New session per PR, not shared across PRs

    tools:
      - tool: "github.repo.read"
        operations:
          - "get_file_contents"
          - "get_pull_request_diff"
          - "get_pull_request_metadata"
          - "get_commit_metadata"
        constraints:
          repository_scope: "current_pr_repository_only"
          path_allowlist: null  # Any path in the repository
          path_denylist:
            - ".github/workflows/**"  # Cannot read workflow definitions
            - "**/*.env"
            - "**/secrets/**"

      - tool: "github.comment.write"
        operations:
          - "create_review_comment"
          - "create_line_comment"
          - "update_own_comment"
        constraints:
          target: "current_pr_only"
          max_comments_per_session: 50

    prohibited_tools:
      - "github.pr.merge"
      - "github.pr.approve"
      - "github.branch.*"
      - "github.commit.*"
      - "deploy.*"
      - "iam.*"
      - "secrets.*"
      - "kubernetes.*"

    approval_required_for: []  # Reviewer actions do not require pre-approval

  triage:
    display_name: "Security Alert Triage Agent"
    description: "Processes security alerts and updates issue metadata"
    identity:
      oidc_subject_pattern: "triage-agent:session-*"
      service_account: "triage-agent"
      kubernetes_namespace: "ai-agents"

    session:
      max_duration: "continuous"
      session_per_alert: true  # New session context per alert processed

    tools:
      - tool: "github.issue.read"
        operations:
          - "list_issues"
          - "get_issue"
          - "list_security_alerts"
          - "get_security_alert"
          - "get_dependabot_alert"

      - tool: "github.issue.write"
        operations:
          - "add_label"
          - "remove_label"
          - "create_comment"
        constraints:
          target: "assigned_issues_only"
          labels_allowlist:
            - "priority:critical"
            - "priority:high"
            - "priority:medium"
            - "priority:low"
            - "triage:needs-review"
            - "triage:ai-analyzed"

    prohibited_tools:
      - "github.issue.close"    # Cannot close issues
      - "github.alert.dismiss"  # Cannot dismiss security alerts
      - "github.code.*"
      - "github.pr.*"
      - "deploy.*"

    approval_required_for: []

  remediation:
    display_name: "Automated Remediation Agent"
    description: "Creates fix branches and pull requests for security vulnerabilities"
    identity:
      oidc_subject_pattern: "remediation-agent:session-*"
      service_account: "remediation-agent"
      kubernetes_namespace: "ai-agents"

    session:
      max_duration: "1h"
      scope: "per-cve-or-finding"

    tools:
      - tool: "github.repo.read"
        operations:
          - "get_file_contents"
          - "get_dependency_manifest"
          - "get_lock_file"
          - "get_build_config"

      - tool: "github.branch.write"
        operations:
          - "create_branch"
        constraints:
          branch_name_pattern: "^fix/ai-remediation-[a-z0-9-]{3,50}$"
          base_branch_allowlist: ["main", "develop", "master"]

      - tool: "github.commit.write"
        operations:
          - "create_commit"
        constraints:
          target_branch_pattern: "^fix/ai-remediation-.*$"  # Own branches only
          max_files_per_commit: 10

      - tool: "github.pr.write"
        operations:
          - "create_pull_request"
        constraints:
          target_branch_allowlist: ["main", "develop", "master"]
          pr_title_prefix: "[AI-Remediation]"  # Distinguishable from human PRs
          require_reviewers: true

    prohibited_tools:
      - "github.pr.merge"        # MUST be human-approved and merged by human
      - "github.pr.approve"
      - "github.branch.delete"   # Cannot delete branches (only creates)
      - "github.codeowners.*"    # Cannot modify ownership files
      - "deploy.*"

    approval_required_for:
      - action: "github.pr.write.create_pull_request"
        approver: "human"
        mechanism: "out-of-band notification with explicit confirm/deny"
        timeout: "24h"
        timeout_action: "cancel"  # Cancel if not approved within 24 hours

  monitor:
    display_name: "Production Monitor Agent"
    description: "Monitors logs and metrics; creates incident tickets"
    identity:
      oidc_subject_pattern: "monitor-agent:session-*"
      service_account: "monitor-agent"
      kubernetes_namespace: "ai-agents"

    session:
      max_duration: "continuous"

    tools:
      - tool: "observability.logs.read"
        operations:
          - "query_logs"
          - "get_log_stream"
        constraints:
          log_group_allowlist:
            - "/apps/production/*"
            - "/apps/staging/*"
          max_query_time_range: "24h"

      - tool: "observability.metrics.read"
        operations:
          - "query_metric"
          - "get_dashboard"
          - "list_alerts"

      - tool: "incident.write"
        operations:
          - "create_pagerduty_incident"
          - "create_jira_ticket"
          - "send_slack_message"
        constraints:
          pagerduty_services_allowlist: ["production-alerts", "security-alerts"]
          slack_channels_allowlist: ["#incidents", "#security-alerts", "#on-call"]

    prohibited_tools:
      - "observability.logs.write"  # CRITICAL: cannot write to logs it reads
      - "config.*"                  # Cannot modify application configuration
      - "deploy.*"
      - "kubernetes.scale"
      - "kubernetes.restart"        # Service restarts require human approval
      - "iam.*"
      - "incident.resolve"          # Cannot resolve incidents it did not create

    approval_required_for:
      - action: "incident.write.create_pagerduty_incident"
        severity_threshold: "P1"   # P1 incidents require confirmation before creation
        approver: "automated_policy_check"
        mechanism: "rate_limit_and_dedup"
```

---

## Approval Gate Requirements

The following table defines the approval requirements for actions that agents may request or perform. "Approval level" defines who must confirm the action before it is executed.

| Action | Approval Level | Mechanism | Rationale | Reversible |
|---|---|---|---|---|
| Post review comment | None — automatic | Tool authorization | Low blast radius; human sees before acting | Yes |
| Update issue label | None — automatic | Tool authorization | Low blast radius; metadata change | Yes |
| Create incident ticket | Rate-limit + dedup | Automated policy | Low blast radius; informational | Yes |
| Create fix branch | None — automatic | Tool authorization | Reversible; no effect without PR | Yes |
| Create pull request | Human confirmation | Out-of-band notification | Code change requiring human review | Yes (delete PR) |
| Merge pull request | Human approval required | Branch protection + CODEOWNERS | Code change; affects main branch | Partially |
| Deploy to staging | Team lead approval | Environment protection rule | System state change; consequential | Mostly |
| Deploy to production | Two human approvals | Env protection + CODEOWNERS | Production change; high blast radius | Partially |
| Delete any branch | Human confirmation | Out-of-band | Destroys git history | No |
| Delete any resource | Explicit human authorization | Separate approval workflow | Typically irreversible | No |
| Modify IAM policy | Security team review | Separate approval workflow | High blast radius; privilege change | Partial |
| Dismiss security alert | Security engineer review | Separate approval workflow | Removes visibility; audit trail required | No (creates record) |
| Modify agent tool policy | Policy owner + security review | Git PR with required reviewers | Changes agent authority | Yes (revert PR) |
| Modify system prompt | Platform team review | Git PR with required reviewers | Changes agent behavior | Yes (revert PR) |

---

## Implementation: GitHub Actions Environment Protection Rules

GitHub Actions environment protection rules implement human approval gates for deployment agents operating in GitHub Actions workflows.

```yaml
# .github/workflows/agent-deployment.yml
# This workflow is triggered by the deployment orchestration agent.
# Production deployment requires explicit human approval via environment protection.

name: Deployment Orchestration

on:
  workflow_dispatch:
    inputs:
      target_environment:
        description: "Target deployment environment"
        required: true
        type: choice
        options: [staging, production]
      agent_session_id:
        description: "Agent session ID for audit trail"
        required: true
        type: string

jobs:
  deploy-staging:
    if: inputs.target_environment == 'staging'
    runs-on: ubuntu-latest
    # staging environment requires team lead approval (configured in GitHub settings)
    environment: staging
    permissions:
      id-token: write   # For OIDC federation
      contents: read
    steps:
      - name: Log agent session for audit trail
        run: |
          echo "Agent session: ${{ inputs.agent_session_id }}"
          echo "Deploying to staging at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      - name: Deploy to staging
        run: ./scripts/deploy.sh staging

  request-production-approval:
    if: inputs.target_environment == 'production'
    runs-on: ubuntu-latest
    steps:
      # This job creates a pending approval notification but does not deploy.
      # Deployment only proceeds if an authorized human approves in the
      # GitHub environment protection rule (configured to require N approvers).
      - name: Record pending approval request
        run: |
          echo "Production deployment requested by agent session: ${{ inputs.agent_session_id }}"
          echo "Awaiting human approval..."

  deploy-production:
    needs: [request-production-approval]
    runs-on: ubuntu-latest
    # production environment requires two approvals from CODEOWNERS (configured in GitHub settings)
    environment: production
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Log approval and deploy
        run: |
          echo "Production deployment approved for agent session: ${{ inputs.agent_session_id }}"
          echo "Approver: ${{ github.actor }}"
          echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      - name: Deploy to production
        run: ./scripts/deploy.sh production
```

Configure the GitHub environment protection rules in the repository settings:
- `staging`: Require 1 reviewer from the team `platform-leads`
- `production`: Require 2 reviewers; both must be from `platform-leads` or `security-team`; prevent self-review

---

## Implementation: Kubernetes RBAC

For agents running as pods in Kubernetes, RBAC provides the access control layer. Each agent role has a dedicated ServiceAccount, Role (or ClusterRole for cluster-scoped resources), and RoleBinding. Network policies restrict which external endpoints each agent can reach.

```yaml
# agent-rbac.yaml
# Complete RBAC configuration for all AI agent roles

---
# Namespace for all AI agents
apiVersion: v1
kind: Namespace
metadata:
  name: ai-agents
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted

---
# === REVIEWER AGENT ===
apiVersion: v1
kind: ServiceAccount
metadata:
  name: reviewer-agent
  namespace: ai-agents
  annotations:
    # IRSA: IAM role for AWS Bedrock and Secrets Manager access
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/reviewer-agent-role
automountServiceAccountToken: false  # Disable auto-mount; use projected tokens
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reviewer-agent
  namespace: ai-agents
rules:
  # ConfigMaps: read approved configuration only
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["reviewer-agent-config"]
    verbs: ["get"]
  # Explicitly: no access to Secrets, Deployments, or cluster-scoped resources
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: reviewer-agent
  namespace: ai-agents
subjects:
  - kind: ServiceAccount
    name: reviewer-agent
    namespace: ai-agents
roleRef:
  kind: Role
  name: reviewer-agent
  apiGroup: rbac.authorization.k8s.io

---
# Network policy: reviewer agent can reach GitHub API and model API only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: reviewer-agent-egress
  namespace: ai-agents
spec:
  podSelector:
    matchLabels:
      app: reviewer-agent
  policyTypes:
    - Ingress
    - Egress
  ingress: []  # No inbound connections
  egress:
    # DNS resolution
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-dns
      ports:
        - port: 53
          protocol: UDP
    # HTTPS only (GitHub API + model provider API)
    - ports:
        - port: 443
          protocol: TCP
    # Explicitly block internal cluster access (prevent SSRF)
    - to:
        - ipBlock:
            cidr: "0.0.0.0/0"
            except:
              - "10.0.0.0/8"
              - "172.16.0.0/12"
              - "192.168.0.0/16"
      ports:
        - port: 443

---
# === REMEDIATION AGENT ===
apiVersion: v1
kind: ServiceAccount
metadata:
  name: remediation-agent
  namespace: ai-agents
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/remediation-agent-role
automountServiceAccountToken: false
---
# Remediation agent has same minimal RBAC as reviewer; its authority is
# expressed via the GitHub token it receives from Secrets Manager (scoped to
# branch creation and PR creation only, via GitHub App installation with
# minimal permissions)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: remediation-agent
  namespace: ai-agents
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["remediation-agent-config"]
    verbs: ["get"]

---
# === MONITOR AGENT ===
apiVersion: v1
kind: ServiceAccount
metadata:
  name: monitor-agent
  namespace: ai-agents
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/monitor-agent-role
automountServiceAccountToken: false
---
# Monitor agent: read access to log and metrics ConfigMaps;
# CloudWatch and Datadog access via IAM role (IRSA)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: monitor-agent
  namespace: ai-agents
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["monitor-agent-config", "alert-thresholds"]
    verbs: ["get", "list"]
  # Can read pod status for health checks (read-only)
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  # Explicitly NO: deployments, services, configmaps (write), secrets
```

---

## Session Scoping and Token Lifecycle

Agent tokens must be session-scoped: they are issued at session start, expire at session end, and cannot be reused for a subsequent session. This prevents stolen tokens from being used to create unauthorized sessions and ensures that compromised sessions expire automatically.

```python
# Example: session-scoped token issuance for an agent using GitHub App installation tokens
# GitHub App installation tokens expire in 1 hour by design — use them for session scoping

import jwt
import time
import httpx
from datetime import datetime, timedelta, timezone

class AgentSessionManager:
    """
    Issues session-scoped credentials for AI agents.
    Each agent session receives a fresh, scoped installation token.
    """

    def __init__(self, app_id: str, private_key_pem: str):
        self.app_id = app_id
        self.private_key = private_key_pem

    def _generate_app_jwt(self) -> str:
        """Generate a short-lived JWT for GitHub App authentication."""
        now = int(time.time())
        payload = {
            "iat": now - 60,   # Issued 60 seconds ago (clock skew tolerance)
            "exp": now + 600,  # Expires in 10 minutes
            "iss": self.app_id
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def create_agent_session(
        self,
        agent_role: str,
        installation_id: str,
        session_purpose: str,
        human_principal: str,
        permitted_repos: list[str]
    ) -> dict:
        """
        Create a session-scoped token for an agent.

        The token is scoped to:
        - The minimum repository permissions required for the agent role
        - The specific repositories for this task
        - A maximum lifetime equal to the agent role's max_duration

        Returns session metadata including the token and session_id.
        """
        app_jwt = self._generate_app_jwt()

        # Define permissions per agent role
        permissions_by_role = {
            "reviewer": {
                "contents": "read",
                "pull_requests": "write",  # For posting comments
                "issues": "read"
            },
            "triage": {
                "issues": "write",
                "security_events": "read"
            },
            "remediation": {
                "contents": "write",
                "pull_requests": "write"
            },
            "monitor": {
                "contents": "read"
            }
        }

        permissions = permissions_by_role.get(agent_role)
        if not permissions:
            raise ValueError(f"Unknown agent role: {agent_role}")

        # Request installation token with minimum required permissions
        response = httpx.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json"
            },
            json={
                "repositories": permitted_repos,
                "permissions": permissions
            }
        )
        response.raise_for_status()
        token_data = response.json()

        import uuid
        session_id = f"{agent_role}-{uuid.uuid4().hex[:16]}"

        return {
            "session_id": session_id,
            "agent_role": agent_role,
            "token": token_data["token"],
            "expires_at": token_data["expires_at"],
            "permitted_repos": permitted_repos,
            "permissions": permissions,
            "human_principal": human_principal,
            "session_purpose": session_purpose,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
```

---

## Audit Requirements

Every tool invocation by an agent must be logged with the following information. This data is required for forensic investigation, compliance, and anomaly detection. Audit logging is implemented by the tool execution layer — not by the agent itself.

Minimum required fields per tool invocation:

| Field | Type | Description |
|---|---|---|
| `timestamp` | ISO 8601 | Exact time of tool invocation in UTC |
| `session_id` | String | Unique identifier for the agent session |
| `agent_role` | String | Agent role from the authorization policy |
| `agent_identity` | String | OIDC subject claim or service account name |
| `tool_name` | String | Exact name of the tool invoked |
| `operation` | String | Specific operation within the tool |
| `input_hash` | SHA-256 | Hash of the complete tool input parameters |
| `output_hash` | SHA-256 | Hash of the tool output returned to the agent |
| `duration_ms` | Integer | Milliseconds from invocation to result return |
| `authorization_policy_version` | String | Git SHA of the policy file in effect |
| `human_principal` | String | Identity of the human who initiated the session |
| `parent_session_id` | String | Session ID of the parent agent (if agent-to-agent call) |
| `approval_record` | String/null | Reference to the approval record if an approval gate was traversed |

Full audit record format is specified in [agent-audit-trail.md](agent-audit-trail.md).
