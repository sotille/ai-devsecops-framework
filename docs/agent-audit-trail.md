# Agent Audit Trail

## Table of Contents

- [Why Standard Audit Logs Are Insufficient for AI Agents](#why-standard-audit-logs-are-insufficient-for-ai-agents)
- [Minimum Viable Audit Record](#minimum-viable-audit-record)
- [Full Input/Output Logging vs. Hash-Only Logging](#full-inputoutput-logging-vs-hash-only-logging)
- [Implementing Immutable Audit Logging](#implementing-immutable-audit-logging)
- [System Prompt Versioning](#system-prompt-versioning)
- [Replay Capability](#replay-capability)
- [The Chain of Prompts Audit Trail](#the-chain-of-prompts-audit-trail)
- [Retention Requirements](#retention-requirements)

---

## Why Standard Audit Logs Are Insufficient for AI Agents

Standard CI/CD audit logs record who ran what command at what time. For AI agents, this level of logging is necessary but not sufficient for three reasons:

**The reasoning chain is invisible.** A deployment agent that runs `kubectl apply -f deployment.yaml` produces the same audit log entry whether it was following legitimate instructions from a human principal or was following injected instructions from a malicious commit message. Standard logs record the action; they do not record what caused the agent to take that action. Without logging the reasoning chain — the sequence of inputs the agent received and the reasoning steps it followed — the action is not attributable.

**The authorization context matters.** Two agents performing the same tool invocation may have different authorization policies in effect. If the tool authorization policy has been modified (legitimately or maliciously), understanding which version was in effect at the time of an action is critical for determining whether the action was authorized.

**The session context enables reconstruction.** AI agents may take multiple related actions across a session. A forensic investigation needs to reconstruct the entire session — the initiating human principal, the instructions provided, every tool call and its result, and the agent's reasoning at each step — to understand whether an incident was the result of injection, specification gaming, authorization overreach, or legitimate behavior.

---

## Minimum Viable Audit Record

The following JSON structure represents the minimum viable audit record for a single tool invocation. Every tool invocation by an agent must produce a record of this form in the audit log.

```json
{
  "schema_version": "1.0",
  "event_type": "agent_tool_invocation",

  "timestamp": "2024-01-15T14:23:45.123Z",
  "session_id": "remediation-agent-a3f8b2c1d4e5",
  "sequence_number": 3,

  "agent": {
    "role": "remediation",
    "identity": "remediation-agent@ai-agents.svc.cluster.local",
    "oidc_subject": "system:serviceaccount:ai-agents:remediation-agent",
    "session_token_fingerprint": "sha256:8a4f2b..."
  },

  "principal": {
    "human_principal": "jane.smith@example.com",
    "human_principal_authenticated_at": "2024-01-15T14:20:00.000Z",
    "parent_session_id": null,
    "initiating_event": "dependabot_alert_CVE-2024-1234"
  },

  "tool": {
    "name": "github.branch.write",
    "operation": "create_branch",
    "version": "1.2.0"
  },

  "authorization": {
    "policy_document": "agent-tool-policy.yaml",
    "policy_git_sha": "7d3f8a2b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
    "policy_version_tag": "v1.2.3",
    "authorized": true,
    "authorization_check_duration_ms": 2
  },

  "execution": {
    "input_hash": "sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    "output_hash": "sha256:9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f9e8d7c6b5a4f3e2d1c0b9a8f7e6",
    "duration_ms": 234,
    "success": true,
    "error": null
  },

  "reasoning": {
    "reasoning_step": 3,
    "reasoning_summary": "Creating fix branch for CVE-2024-1234 dependency update",
    "system_prompt_sha": "4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b",
    "context_window_hash": "sha256:2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c"
  },

  "approval": {
    "required": false,
    "approval_record_id": null
  }
}
```

**Field definitions:**

- `session_id`: Unique identifier for the agent session. All tool invocations within the same task share a session ID, enabling session-level forensic reconstruction.
- `sequence_number`: Monotonically increasing integer within the session. Used to detect log tampering (missing sequence numbers indicate deleted entries).
- `oidc_subject`: The cryptographically verified identity of the agent, from the OIDC token subject claim.
- `session_token_fingerprint`: Fingerprint of the OIDC token used for this session — enables correlation with identity provider audit logs.
- `parent_session_id`: If this agent session was spawned by a parent agent, the parent's session ID. Null for sessions initiated directly by a human.
- `policy_git_sha`: The git SHA of the tool authorization policy file in effect during this invocation. Enables policy reconstruction at investigation time.
- `input_hash`: SHA-256 of the serialized tool input parameters. Enables verification that the input recorded at audit time matches the input that was actually executed.
- `output_hash`: SHA-256 of the serialized tool output returned to the agent.
- `reasoning_step`: Which step in the agent's multi-step reasoning chain this tool invocation corresponds to.
- `system_prompt_sha`: SHA of the system prompt version in effect. See [System Prompt Versioning](#system-prompt-versioning).
- `context_window_hash`: SHA-256 of the agent's full context window (system prompt + all messages) at the time of the tool invocation. Used for session replay.

---

## Full Input/Output Logging vs. Hash-Only Logging

There is a tradeoff between forensic capability and security/privacy risks in logging full tool inputs and outputs:

### Hash-Only Logging (Default Recommendation)

Log only the SHA-256 hash of tool inputs and outputs, not the actual content.

**Advantages:**
- No secrets or PII in audit logs
- Smaller log volume (important for long-running agents with many tool invocations)
- Logs can be stored in less restricted systems without data classification concerns

**Disadvantages:**
- Cannot reconstruct what the agent saw without storing the content elsewhere
- Does not enable session replay without a separate content archive

**Implementation:** Hash-only logging is appropriate as the default. Store the actual content in a separate, access-controlled content archive (S3 with SSE, access-controlled to the security team) and retain only the hashes in the primary audit log. This separates the audit integrity function (hash log) from the forensic investigation function (content archive).

```python
import hashlib
import json
from datetime import datetime, timezone

def hash_tool_interaction(tool_input: dict, tool_output: dict) -> tuple[str, str]:
    """
    Compute SHA-256 hashes of tool input and output for audit logging.
    The serialization order is canonical (sorted keys) for reproducibility.
    """
    input_canonical = json.dumps(tool_input, sort_keys=True, ensure_ascii=True)
    output_canonical = json.dumps(tool_output, sort_keys=True, ensure_ascii=True)

    input_hash = hashlib.sha256(input_canonical.encode('utf-8')).hexdigest()
    output_hash = hashlib.sha256(output_canonical.encode('utf-8')).hexdigest()

    return f"sha256:{input_hash}", f"sha256:{output_hash}"

def write_audit_record(session_id: str, tool_name: str, tool_input: dict,
                       tool_output: dict, agent_metadata: dict,
                       content_archive_client=None) -> str:
    """
    Write an audit log entry and optionally archive full content.
    Returns the audit record ID.
    """
    input_hash, output_hash = hash_tool_interaction(tool_input, tool_output)

    audit_record = {
        "schema_version": "1.0",
        "event_type": "agent_tool_invocation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "tool": {"name": tool_name},
        "execution": {
            "input_hash": input_hash,
            "output_hash": output_hash
        },
        **agent_metadata
    }

    # Optionally archive full content for forensics (separate, restricted store)
    if content_archive_client:
        import uuid
        archive_key = f"agent-content/{session_id}/{uuid.uuid4().hex}"
        content_archive_client.put_object(
            Body=json.dumps({
                "audit_record_id": audit_record.get("record_id"),
                "input": tool_input,    # Full input — may contain sensitive data
                "output": tool_output   # Full output — may contain sensitive data
            }),
            ContentType="application/json"
        )
        audit_record["content_archive_key"] = archive_key

    return audit_record
```

### Full Content Logging

Log the full tool inputs and outputs for all invocations.

**Advantages:**
- Complete forensic capability without a separate content archive
- Session replay without additional storage infrastructure

**Disadvantages:**
- Logs will contain secrets if any tool invocations include credentials as parameters
- Logs may contain PII if agents process user data
- Significantly higher log volume
- Requires strict access controls on the audit log store

Full content logging is appropriate only when:
- A dedicated, access-controlled audit log store is in place (not a shared log aggregator)
- A secret redaction pipeline runs before the content reaches the log store
- The log store meets the organization's data classification requirements for the most sensitive data the agent processes

---

## Implementing Immutable Audit Logging

Agent audit logs must be stored in a system that the agent itself cannot modify. The agent's authorized tool set must not include write access to the audit log. The audit log infrastructure must be operated independently of the agent infrastructure.

### AWS: CloudWatch Logs with S3 Export and Object Lock

```python
# Infrastructure as code for immutable audit logging on AWS
# Using CloudTrail-style immutability: CloudWatch Logs + S3 Object Lock

import boto3
import json

def setup_immutable_audit_log_infrastructure():
    """
    Sets up the AWS infrastructure for immutable agent audit logging.
    Run once during platform setup; requires administrator credentials.
    """
    logs_client = boto3.client('logs', region_name='us-east-1')
    s3_client = boto3.client('s3', region_name='us-east-1')

    # Create CloudWatch Log Group with 90-day retention
    logs_client.create_log_group(logGroupName='/ai-agents/audit')
    logs_client.put_retention_policy(
        logGroupName='/ai-agents/audit',
        retentionInDays=90
    )

    # Apply resource-based policy preventing log deletion
    # This prevents even the log-writing principal from deleting entries
    resource_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PreventDeletion",
                "Effect": "Deny",
                "Principal": "*",
                "Action": [
                    "logs:DeleteLogGroup",
                    "logs:DeleteLogStream",
                    "logs:DeleteRetentionPolicy",
                    "logs:PutRetentionPolicy"
                ],
                "Resource": "arn:aws:logs:us-east-1:*:log-group:/ai-agents/audit:*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:PrincipalArn": [
                            "arn:aws:iam::123456789012:role/security-audit-admin"
                        ]
                    }
                }
            }
        ]
    }

    logs_client.put_resource_policy(
        policyName='PreventAuditLogDeletion',
        policyDocument=json.dumps(resource_policy)
    )

    # S3 bucket for long-term archive with Object Lock
    s3_client.create_bucket(
        Bucket='company-ai-audit-archive',
        CreateBucketConfiguration={'LocationConstraint': 'us-east-1'},
        ObjectLockEnabledForBucket=True  # Must be set at creation time
    )

    # Set default retention: COMPLIANCE mode, 365 days
    # COMPLIANCE mode prevents deletion even by the bucket owner
    s3_client.put_object_lock_configuration(
        Bucket='company-ai-audit-archive',
        ObjectLockConfiguration={
            'ObjectLockEnabled': 'Enabled',
            'Rule': {
                'DefaultRetention': {
                    'Mode': 'COMPLIANCE',
                    'Days': 365
                }
            }
        }
    )
```

```json
// IAM policy for the AI agent write role
// Agents can write to the log stream but CANNOT delete or modify entries
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAuditLogWriteOnly",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/ai-agents/audit:*"
    },
    {
      "Sid": "ExplicitDenyLogDeletion",
      "Effect": "Deny",
      "Action": [
        "logs:DeleteLogGroup",
        "logs:DeleteLogStream",
        "logs:DeleteRetentionPolicy",
        "logs:PutRetentionPolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

### Kubernetes: Audit Log to External SIEM

```yaml
# kubernetes audit policy for agent namespace
# /etc/kubernetes/audit-policy.yaml

apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all activity in the ai-agents namespace at RequestResponse level
  - level: RequestResponse
    namespaces: ["ai-agents"]
    verbs: ["create", "update", "delete", "patch"]
    resources:
      - group: ""
        resources: ["pods", "configmaps", "secrets", "serviceaccounts"]

  # Log any access to secrets at Metadata level (without content) cluster-wide
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]

  # Log pod execution and service account token requests
  - level: Request
    namespaces: ["ai-agents"]
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "serviceaccounts/token"]
```

```yaml
# Fluent Bit configuration: forward Kubernetes audit logs to SIEM
# Audit logs must NOT be stored on the cluster — forward to external SIEM only

[INPUT]
    Name              tail
    Path              /var/log/kubernetes/audit.log
    Parser            json
    Tag               kubernetes.audit
    Refresh_Interval  5

[FILTER]
    Name    grep
    Match   kubernetes.audit
    Regex   objectRef.namespace ai-agents

[OUTPUT]
    Name         splunk
    Match        kubernetes.audit
    Host         splunk.internal
    Port         8088
    TLS          On
    TLS.Verify   On
    Splunk_Token ${SPLUNK_HEC_TOKEN}
    # Retain original timestamps from audit log
    Splunk_Send_Raw On
```

---

## System Prompt Versioning

System prompts define an agent's behavior and constraints. They must be versioned and immutable — changes to a system prompt must go through the same review and approval process as changes to production infrastructure.

```bash
# System prompt storage convention:
# Store in version-controlled repository under controlled access
# Reference by SHA in all audit log entries

# Directory structure
# prompts/
#   reviewer-agent/
#     v1.0.0.txt          # Initial version
#     v1.1.0.txt          # Added CVE description handling
#     v1.2.0.txt          # Injection resistance improvements
#   remediation-agent/
#     v1.0.0.txt
#   triage-agent/
#     v1.0.0.txt

# Get the SHA of the current system prompt before starting an agent session
PROMPT_SHA=$(git -C /path/to/prompts-repo hash-object prompts/reviewer-agent/v1.2.0.txt)
echo "System prompt SHA: $PROMPT_SHA"
# Record this SHA in the session initialization record

# Verification: given a SHA from an audit log, retrieve the exact prompt in effect
git -C /path/to-prompts-repo show $PROMPT_SHA
```

```python
import hashlib
import subprocess
from pathlib import Path

def get_system_prompt_with_sha(prompt_path: str, prompts_repo_path: str) -> tuple[str, str]:
    """
    Load a system prompt and return both its content and its git SHA.
    The SHA is recorded in the session initialization audit record.

    Args:
        prompt_path: relative path to the prompt file within the prompts repo
        prompts_repo_path: absolute path to the prompts git repository

    Returns:
        tuple: (prompt_content, git_sha)
    """
    full_path = Path(prompts_repo_path) / prompt_path

    with open(full_path, 'r') as f:
        content = f.read()

    # Get git SHA via git hash-object (content-addressable, matches git's internal hash)
    result = subprocess.run(
        ['git', '-C', prompts_repo_path, 'hash-object', str(full_path)],
        capture_output=True,
        text=True,
        check=True
    )
    git_sha = result.stdout.strip()

    # Cross-verify: git SHA should match SHA-1 of "blob {length}\0{content}"
    expected = f"blob {len(content.encode())}\0{content}"
    computed = hashlib.sha1(expected.encode()).hexdigest()
    assert git_sha == computed, f"Git SHA mismatch: {git_sha} != {computed}"

    return content, git_sha

# Usage at session initialization:
prompt_content, prompt_sha = get_system_prompt_with_sha(
    "reviewer-agent/v1.2.0.txt",
    "/opt/techstream/ai-prompts"
)

session_init_record = {
    "session_id": "reviewer-agent-abc123",
    "system_prompt_sha": prompt_sha,
    "system_prompt_path": "reviewer-agent/v1.2.0.txt",
    "agent_role": "reviewer",
    # ... other session fields
}
```

Changes to system prompts require:
1. A pull request in the prompts repository with the changed prompt file
2. Review from the security team and the owning team
3. A description of what changed and why
4. Testing against the adversarial test suite before merging
5. A CHANGELOG entry documenting the change

---

## Replay Capability

Session replay is the ability to reconstruct an agent's session from audit logs and the content archive for forensic investigation. A complete replay requires:

1. The session initialization record (agent identity, human principal, initiating event, system prompt SHA)
2. The sequence of tool invocations (from the audit log, ordered by sequence number)
3. The full tool inputs and outputs (from the content archive, retrieved by the input/output hashes from the audit log)
4. The system prompt at the recorded SHA
5. The tool authorization policy at the recorded SHA

Given these elements, an investigator can reconstruct the exact sequence of events the agent experienced and verify whether each action was consistent with its inputs and authorization.

```python
def reconstruct_session(session_id: str, audit_log_client, content_archive_client,
                         prompts_repo_path: str, policy_repo_path: str) -> dict:
    """
    Reconstruct an agent session from audit logs and content archive.
    Used for forensic investigation.
    """
    # Retrieve all audit records for this session, ordered by sequence number
    records = audit_log_client.query(
        filter=f'session_id = "{session_id}"',
        order_by="sequence_number ASC"
    )

    if not records:
        return {"error": f"No audit records found for session {session_id}"}

    session_init = records[0]

    # Verify sequence integrity (detect deleted entries)
    sequence_numbers = [r["sequence_number"] for r in records]
    expected = list(range(1, len(sequence_numbers) + 1))
    missing = set(expected) - set(sequence_numbers)
    if missing:
        return {
            "error": f"INTEGRITY FAILURE: Missing sequence numbers {missing}",
            "records": records
        }

    # Retrieve system prompt at recorded SHA
    prompt_sha = session_init["reasoning"]["system_prompt_sha"]
    system_prompt = subprocess.run(
        ['git', '-C', prompts_repo_path, 'show', prompt_sha],
        capture_output=True, text=True, check=True
    ).stdout

    # Retrieve policy at recorded SHA
    policy_sha = records[0]["authorization"]["policy_git_sha"]
    policy = subprocess.run(
        ['git', '-C', policy_repo_path, 'show', f'{policy_sha}:agent-tool-policy.yaml'],
        capture_output=True, text=True, check=True
    ).stdout

    # Retrieve full tool interaction content from archive
    interactions = []
    for record in records:
        archive_key = record.get("content_archive_key")
        if archive_key:
            content = content_archive_client.get_object(Key=archive_key)
            interactions.append({
                "sequence": record["sequence_number"],
                "tool": record["tool"]["name"],
                "operation": record["tool"]["operation"],
                "input": content["input"],
                "output": content["output"],
                "authorized": record["authorization"]["authorized"],
                "success": record["execution"]["success"]
            })

    return {
        "session_id": session_id,
        "human_principal": session_init["principal"]["human_principal"],
        "agent_role": session_init["agent"]["role"],
        "system_prompt": system_prompt,
        "policy": policy,
        "sequence_integrity": "OK",
        "interactions": interactions
    }
```

---

## The Chain of Prompts Audit Trail

For multi-step agent reasoning, each reasoning step that produces a tool invocation should be logged with the reasoning that led to the invocation. This is the "chain of prompts" — the sequence of inputs and intermediate outputs that represents the agent's decision-making process.

```json
// Extended audit record with reasoning chain entry
{
  "session_id": "remediation-agent-a3f8b2c1d4e5",
  "sequence_number": 3,
  "reasoning_chain": [
    {
      "step": 1,
      "type": "initial_context",
      "content_hash": "sha256:...",
      "summary": "Received CVE-2024-1234 alert for lodash 4.17.15"
    },
    {
      "step": 2,
      "type": "tool_result",
      "tool": "github.repo.read.get_dependency_manifest",
      "result_hash": "sha256:...",
      "summary": "Found lodash 4.17.15 in package.json; fix available: 4.17.21"
    },
    {
      "step": 3,
      "type": "tool_invocation",
      "tool": "github.branch.write.create_branch",
      "invocation_hash": "sha256:...",
      "reasoning_summary": "Creating fix branch to update lodash from 4.17.15 to 4.17.21"
    }
  ]
}
```

Logging reasoning summaries (not full reasoning text, which may be verbose and contain sensitive context) provides the forensic context needed to understand why an agent took an action without storing the full context window for every step.

---

## Retention Requirements

| Log Category | Minimum Retention | Rationale |
|---|---|---|
| Tool invocation audit records (hash-only) | 90 days | Operational investigation window |
| Tool invocation audit records (hash-only) | 1 year for security incidents | Forensic and regulatory requirements |
| Full content archive (inputs/outputs) | 30 days operational | High storage cost; investigation typically completed within 30 days |
| Full content archive for security incidents | 1 year | Full forensic reconstruction for serious incidents |
| Session initialization records | 1 year | Identity and authorization context for session-level attribution |
| System prompt versions | Indefinite (in git) | Required to reconstruct session context for any past session |
| Tool authorization policy versions | Indefinite (in git) | Required to determine what was authorized at any past point in time |
| OIDC token issuance records | 90 days | Correlate with identity provider for authentication chain |

Logs related to security incidents (any session flagged by anomaly detection or investigated by security) should be retained for 1 year from the date of the investigation's closure, regardless of the standard retention period.

Log deletion must require a documented business justification and approval from the security team, and must be recorded in the security incident log.
