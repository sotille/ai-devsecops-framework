# Model Supply Chain Security

## Table of Contents

- [Overview](#overview)
- [ML Models as Supply Chain Artifacts](#ml-models-as-supply-chain-artifacts)
- [Threat Model](#threat-model)
- [Model Registry and Inventory](#model-registry-and-inventory)
- [Model Integrity Verification](#model-integrity-verification)
- [Model Scanning](#model-scanning)
- [Model Provenance and Signing](#model-provenance-and-signing)
- [Fine-Tuning Pipeline Security](#fine-tuning-pipeline-security)
- [Shadow Model Controls](#shadow-model-controls)
- [Model Deprecation](#model-deprecation)
- [Implementation Checklist](#implementation-checklist)

---

## Overview

When an organization deploys an AI model in a DevSecOps pipeline — as a code review assistant, vulnerability triage agent, or security scanner — that model is a supply chain artifact with a trust chain that must be verified. Treating models as trusted by default, or loading them without integrity verification, is equivalent to running unverified third-party binaries with production access.

Model supply chain security applies the same principles as software supply chain security (SLSA, SBOM, Sigstore) to ML model artifacts. It addresses the full lifecycle: sourcing, integrity verification, scanning, deployment controls, version management, and deprecation.

Model supply chain security is covered at AI Security Maturity Level 4. Organizations without the Level 3 controls (prompt injection defense, agent authorization policy) should implement those before investing in Level 4 controls.

---

## ML Models as Supply Chain Artifacts

An ML model file is a supply chain artifact with the following characteristics:

**Binary format:** Most model weights are stored in binary formats (GGUF, SafeTensors, pickle-based PyTorch checkpoints). Binary formats cannot be manually reviewed and are opaque to static analysis tools designed for source code.

**Embedded executable logic:** Some model formats (notably pickle-based `.pt` and `.pkl` files) can contain executable code that runs during deserialization. This makes model loading a remote code execution surface if the model source is not trusted.

**Large size:** Model files range from hundreds of megabytes to hundreds of gigabytes. Full hash verification is feasible; deep content inspection requires specialized tooling.

**Third-party provenance:** Most organizations source models from third-party registries (Hugging Face, AWS Bedrock model catalog, Azure AI model catalog) or API providers (Anthropic, OpenAI, Google). The organization does not have full visibility into the model's training pipeline, training data, or fine-tuning history.

**Version-dependent behavior:** Different versions of the same model can exhibit significantly different security-relevant behaviors. A version upgrade that improves capability may also change how the model responds to injection attempts or authorization challenges.

---

## Threat Model

Model supply chain threats fall into four categories:

**1. Malicious model artifacts (pickle deserialization):** An attacker publishes a model that contains malicious executable code embedded in a pickle-serialized object. When loaded by `torch.load()` without safe mode, the malicious code executes with the permissions of the loading process.

*Attack vector:* Hugging Face model hub, compromised model registries, dependency confusion (a model identifier that resembles a legitimate model but is controlled by an adversary).

*Detection:* ModelScan scanning before model load; use of SafeTensors format instead of pickle-based formats; hash verification against a known-good digest.

**2. Maliciously fine-tuned models:** A model is fine-tuned on adversarially crafted data to cause it to exhibit specific behaviors — suppress security findings, generate predictably exploitable code, or respond to specific trigger phrases with dangerous outputs (backdoored models).

*Attack vector:* Compromised fine-tuning pipeline, poisoned training datasets, third-party fine-tuned models sourced without adequate vetting.

*Detection:* Behavioral comparison testing between model versions; red team exercises targeting fine-tuned models; provenance verification of training datasets.

**3. Model version substitution:** An attacker replaces a pinned model version with a different version that exhibits different security-relevant behavior, without the version change being detected.

*Attack vector:* Compromised model registry, TOCTOU (time-of-check/time-of-use) race in model download and deployment, mutable model version tags.

*Detection:* Digest-based version pinning (not name-based); hash verification before model load; immutable model storage.

**4. Shadow models:** Developers or pipeline components use unapproved AI services (personal API accounts, unapproved tools) that bypass the organization's security review and monitoring.

*Attack vector:* Developer convenience, unapproved tools with appealing features, gaps in the approved model registry.

*Detection:* Network egress filtering; secrets scanning for unapproved API key patterns; AI tool inventory reviews.

---

## Model Registry and Inventory

Every model used in the delivery pipeline must be recorded in an approved model registry. The registry is the authoritative source for which models are permitted in organizational systems.

**Minimum required fields per registry entry:**

| Field | Description |
|---|---|
| Model ID | Unique identifier used in deployment configuration |
| Provider | Organization or API service providing the model |
| Version | Specific version or release pinned for use |
| Digest | SHA-256 hash of the model artifact (for locally hosted models) |
| Use cases | Approved use cases for this model in the pipeline |
| Integration points | Which pipeline components use this model |
| Risk classification | Low / Medium / High based on capabilities and blast radius |
| Governance owner | Team responsible for approving version upgrades |
| Last security review | Date of last security assessment |
| Expiry | Date after which the entry requires renewal |

**Registry governance requirements:**
- The registry is stored in version control with access controls equivalent to production infrastructure configuration
- Adding a new model requires a review by the security team and the platform team
- Version upgrades require documentation of behavioral comparison testing results
- Entries that have not been reviewed within their expiry period must be marked as pending review and treated as unapproved until renewed

---

## Model Integrity Verification

**Digest-based version pinning:** Model versions must be pinned by cryptographic digest (SHA-256 of the model file), not by version name alone. Version names are mutable in many model registries — the same name can resolve to different content at different times.

For API-hosted models, pin by the model's API version identifier, which should map to a stable artifact. For locally hosted models, pin by file digest.

**Pre-load hash verification:** Before a model file is loaded by any pipeline component, its digest must be verified against the approved model registry entry. Load is aborted if the digest does not match.

```python
import hashlib
from pathlib import Path

def verify_model_digest(model_path: str, expected_digest: str) -> None:
    """
    Verify a model file's SHA-256 digest before loading.
    Raises ValueError if the digest does not match.
    Called before any torch.load(), transformers.from_pretrained(), or
    llama_cpp.Llama() invocation with a local model path.
    """
    sha256 = hashlib.sha256()
    model_file = Path(model_path)

    if not model_file.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    with open(model_file, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)

    actual_digest = sha256.hexdigest()

    if actual_digest != expected_digest:
        raise ValueError(
            f"Model digest mismatch for {model_path}.\n"
            f"  Expected: {expected_digest}\n"
            f"  Actual:   {actual_digest}\n"
            "Model load aborted. This may indicate tampering or an unauthorized "
            "model substitution. Report to the security team."
        )
```

---

## Model Scanning

**ModelScan** is the primary tool for scanning model files for malicious content. It detects:
- Dangerous Python globals in pickle-serialized models (code execution payloads)
- Unsafe deserialization patterns in `.pt`, `.pkl`, `.npy`, and H5 files
- Blacklisted operator patterns in ONNX models

**Integration into the model deployment pipeline:**

```yaml
# .github/workflows/model-deploy.yml (excerpt)
# Runs on model version updates before any deployment step

- name: Scan model artifact for malicious content
  run: |
    pip install modelscan
    modelscan --path ./models/${MODEL_FILE} --reporting-format json \
      --output-file modelscan-results.json

    # Fail the workflow if any issues are found
    python -c "
    import json, sys
    results = json.load(open('modelscan-results.json'))
    issues = results.get('summary', {}).get('total_issues', 0)
    if issues > 0:
        print(f'ModelScan found {issues} issue(s). Aborting deployment.')
        sys.exit(1)
    print('ModelScan: no issues found.')
    "

- name: Archive scan results
  uses: actions/upload-artifact@v3
  with:
    name: modelscan-results
    path: modelscan-results.json
```

**SafeTensors format preference:** Where possible, use models in SafeTensors format rather than pickle-based formats. SafeTensors is a safe serialization format that does not permit arbitrary code execution during deserialization. When sourcing models from Hugging Face, prefer repositories that publish SafeTensors weights.

---

## Model Provenance and Signing

For organizations that build or fine-tune models, model artifacts should be signed with Sigstore (Cosign) to establish provenance — a verifiable record of where the model came from and what pipeline produced it.

**Signing a model artifact with Cosign (keyless, OIDC-based):**

```bash
# Sign during the model training/fine-tuning pipeline
# Assumes the pipeline runs in GitHub Actions with OIDC token support

cosign sign-blob \
  --output-certificate model-cert.pem \
  --output-signature model.sig \
  model-weights.safetensors

# Store the certificate and signature alongside the model artifact
# in your model registry or artifact store
```

**Verifying before deployment:**

```bash
# Verify model provenance before loading
cosign verify-blob \
  --certificate model-cert.pem \
  --signature model.sig \
  --certificate-identity "https://github.com/your-org/model-pipeline/.github/workflows/train.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  model-weights.safetensors
```

The `--certificate-identity` and `--certificate-oidc-issuer` flags verify that the model was signed by a specific GitHub Actions workflow on a specific branch — binding the model artifact to its production origin.

---

## Fine-Tuning Pipeline Security

Organizations that fine-tune models on their own data introduce an additional attack surface: the training data pipeline. Compromised or poisoned training data can cause the fine-tuned model to exhibit behaviors not present in the base model.

**Training data provenance controls:**
- Training datasets must be sourced from approved data repositories with access logs
- Dataset versions must be pinned by content hash, not by mutable name
- Training data that includes user-generated content or external data requires additional vetting for adversarial content
- Behavioral testing comparing the base model to the fine-tuned model must be run before deployment

**Fine-tuning pipeline authentication:**
- The fine-tuning pipeline must use separate credentials from the production deployment pipeline
- Fine-tuned model artifacts must go through the same scanning and signing process as externally sourced models
- Access to fine-tuning infrastructure must be restricted to the AI platform team

---

## Shadow Model Controls

Shadow models are AI tools used by developers or pipeline components outside the approved model registry. They represent an unmonitored attack surface and a compliance gap.

**Detection controls:**
- Network egress filtering: only approved AI API endpoints should be reachable from organizational systems and CI/CD runners
- Secrets scanning: extend Gitleaks patterns to include API key formats for unapproved AI providers (reference the AI provider API key pattern database in [implementation.md](implementation.md))
- Periodic AI tool inventory reviews: compare the inventory against what is observed in network logs, code repositories, and developer tooling configurations

**Policy controls:**
- The AI acceptable use policy must explicitly list approved AI services and state that unapproved services are not permitted on organizational systems
- Exceptions require security review and approval
- Engineers who discover they are using an unapproved AI service have a defined process to request approval rather than continuing to use it without disclosure

---

## Model Deprecation

Models must be deprecated when:
- The provider announces end-of-life or end-of-support for the version
- A security vulnerability is discovered in the model or its weights
- The model fails behavioral testing or red team exercises in ways that create unacceptable risk
- The model has not been reviewed within its registry entry expiry period

**Deprecation process:**
1. Identify all pipeline components using the model (from the registry's `integration_points` field)
2. Test approved replacement models in the pipeline with behavioral comparison and adversarial testing
3. Update the registry entry for the replacement model
4. Update pipeline configurations to reference the replacement
5. Verify the deprecated model is no longer loaded in any pipeline component
6. Archive the deprecation record with the reason, date, and replacement version

**SLA for deprecation:** Security-motivated deprecations (vulnerability or behavioral failure) must be completed within 30 days of the finding. Provider-announced EoL deprecations must be completed before the EoL date. Quality-motivated deprecations have no mandatory SLA.

---

## Implementation Checklist

This checklist maps to the AI Security Maturity Level 4 requirements for model supply chain:

- [ ] Approved model registry established in version control with minimum required fields
- [ ] All model versions pinned by digest (not by name only)
- [ ] Pre-load hash verification implemented and deployed for all locally hosted models
- [ ] ModelScan (or equivalent) deployed in the model deployment pipeline
- [ ] SafeTensors format used where available; pickle-based formats justified and documented
- [ ] Model signing with Cosign implemented for fine-tuned models (if fine-tuning is in use)
- [ ] Fine-tuning pipeline uses separate credentials and access controls from production
- [ ] Training data provenance tracked for fine-tuned models
- [ ] Shadow model controls deployed: network egress filtering and secrets scanning for unapproved AI providers
- [ ] Model deprecation process documented and practiced

---

*Cross-references:* [agent-authorization.md](agent-authorization.md) — agent identity and authorization controls that complement model supply chain security; [implementation.md](implementation.md) — phase-by-phase implementation guide including AI provider API key patterns for secrets scanning; [roadmap.md](roadmap.md) — Level 4 maturity checklist.
