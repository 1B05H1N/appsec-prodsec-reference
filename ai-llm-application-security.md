# AI and LLM Application Security

> **Note**: This is based on ***my personal experience/recommendations*** and does not represent the required/official methodology used at any organization I've worked for or currently work at.

---

## Overview

AI features add models, data pipelines, and sometimes autonomous tools to an application's attack surface. Prompt injection is one concern; unauthorized data access, unsafe actions, compromised model artifacts, and resource exhaustion also need controls outside the model.

This reference covers LLM applications, retrieval, agents, and common security concerns for other machine learning systems. Use it with [`secure-design-reference.md`](secure-design-reference.md), [`application-security-assessment-template.md`](application-security-assessment-template.md), and [`software-supply-chain-security.md`](software-supply-chain-security.md).

---

## Authoritative references

- [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) and its [published list and source](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md). Identifiers and rankings changed from the 2025 edition.
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and [Securing Agentic Applications V2](https://genai.owasp.org/resource/securing-agentic-applications-v2/).
- [Model Context Protocol (MCP) specification, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/) and its [security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices). Check the version actually used by the integration.
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) and its [Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence).
- [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final) for secure development of generative AI and foundation models; [NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) for adversarial machine learning terminology and mitigations.
- [OWASP AI Exchange](https://owaspai.org/) and the [OWASP Machine Learning Security Top Ten](https://owasp.org/www-project-machine-learning-security-top-10/) (a draft project).
- [MITRE ATLAS](https://atlas.mitre.org/) for adversarial AI techniques, and the [Cloud Security Alliance AI working group](https://cloudsecurityalliance.org/research/working-groups/artificial-intelligence) for AI control guidance.

---

## Threat modeling extensions for LLM features

Start with the intended use and the impact of failure. Inventory the feature owner, users, models and versions, data sources, tools, providers, and deployment environments. Record which parts are built in-house and which are operated by a provider.

| Boundary or asset | Questions to answer |
|---|---|
| Inputs | Can users, external documents, web pages, emails, images, audio, repositories, or tool results influence the model? Who can change that content? |
| Identity | Which user requested the operation? Which workload identity performs it? Can either access data or perform actions beyond its intended scope? |
| Retrieval and memory | Which documents, embeddings, caches, and saved memories are available to each user and tenant? How are changes and deletions propagated? |
| Actions | What can each tool read, change, send, or execute? What is the worst individual action or sequence of actions? |
| Providers and infrastructure | Where do prompts, data, and results travel? Who hosts each component, and what are the retention, training, and deletion terms? |
| Operations | How would the team detect, contain, and investigate abuse? What happens if a model, tool, or authorization service is unavailable? |

Use the existing [threat modeling methods](secure-design-reference.md#popular-methodologies) and map applicable risks to the relevant version of a framework. A Top 10 list is a starting point, not evidence that the system is secure.

## OWASP LLM Top 10 - what to look for in review

The identifiers below refer to the **2026** OWASP LLM release. The scenarios group related risks; use the [published list](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md) for a complete mapping.

| Scenario | Review focus | 2026 reference |
|---|---|---|
| Instructions embedded in user or retrieved content change model behavior | Identify all input channels and enforce permissions outside the model. | LLM01 |
| Retrieval, embeddings, or caches expose or distort data | Enforce user and tenant access; protect indexes and trace source changes. | LLM09 |
| A tool acts with excessive privileges | Limit capabilities and verify identity, authorization, and approval at execution. | LLM03 |
| Output is inaccurate or reaches an unsafe interpreter | Verify consequential claims; validate and handle output for its actual destination. | LLM07, LLM10 |
| Sensitive data or hidden application context is disclosed | Minimize context, protect data flows, and keep secrets and authorization outside prompts. | LLM02, LLM08 |
| A model, dependency, or dataset is compromised | Verify provenance and integrity; control what is loaded, trained on, or promoted. | LLM04, LLM05 |
| Requests or agent loops exhaust capacity or budget | Enforce limits across users, tenants, requests, and downstream tools. | LLM06 |

---

## Design principles for LLM-integrated applications

### Instructions and output

- Treat user messages, retrieved documents, tool results, memory, and multimodal inputs as untrusted. Internal systems can contain attacker-supplied content too.
- Separate system, user, and tool messages and label external content. This helps the model interpret context, but neither message roles nor delimiters prevent prompt injection.
- Never rely on a prompt, model refusal, output classifier, or hidden instruction as the sole authorization or security control. Assume anything sent to the model could be disclosed.
- Keep credentials and authorization decisions in trusted application components, not in prompts, tool descriptions, or other model context.
- Treat model output as untrusted input. Use parameterized SQL, context-appropriate browser encoding and HTML sanitization, and allowlisted operations. Avoid passing generated text to a shell or `eval`; if code execution is necessary, isolate it and restrict its filesystem, network, and credentials.
- Disable automatic loading of remote images and previews in generated content unless required; otherwise use origin allowlists and browser or network controls. Validate URLs and destinations before any server-side fetch.
- Validate structured output locally for type, size, allowed values, and business rules. A valid JSON schema does not establish that an action is authorized or that a claim is true. Fail closed on malformed output, refusals, and tool errors.

### Retrieval, context, and memory

Retrieval-augmented generation (RAG) brings external content into a model's context. Retrieval improves access to information; it does not make that information trustworthy or guarantee a correct answer.

- Derive tenant and document or chunk permissions from the authenticated requester on the server. Enforce those permissions in the retrieval query or an equivalently isolated index, and independently check results before sending them to a reranker, model, or user. Do not rely on a client-supplied tenant filter.
- Scope conversation history and memory to the appropriate user and tenant. For cached answers or memory derived from protected sources, retain the contributing resource identifiers and recheck access before reuse. Deny reuse when provenance or current permissions cannot be established.
- Track the source, owner, ingestion time, and version of indexed content. Restrict who can add or modify it; quarantine suspicious sources and make it possible to remove and rebuild affected indexes.
- Treat persistent memory updates as untrusted writes: restrict who can create them, retain their provenance, and provide review and deletion. Do not silently turn retrieved instructions into persistent policy.
- Enforce current access and deletion decisions while index updates are pending; fail closed if they cannot be verified. Propagate changes to derived chunks, embeddings, caches, and memory within a defined interval. Account for backup retention and prevent restored content from bypassing current permissions.
- Treat embeddings and their backups as potentially sensitive. Limit access and protect them according to the source data's classification.
- Use source metadata for attribution rather than trusting model-invented citations. For consequential answers, verify the cited material supports the claim and is current; otherwise abstain or escalate.

### Agents and tool calls

An agent can select or chain tools. A model's choice of tool or arguments is a proposal, not authority to execute it.

- Expose only the capabilities needed for the task. Prefer narrow read-only tools over general shell, filesystem, or unrestricted network access; separate read and write privileges.
- Authenticate the requester and use least-privilege delegated or workload identities. Enforce the requester's effective permissions on every resource and action at the tool or downstream service, including across multi-agent handoffs.
- Validate tool names, argument schemas, target resources, and business rules in trusted code. Deny requests when identity, authorization, or policy checks fail or are unavailable.
- Require explicit approval for material actions such as sending data externally, changing access, deleting records, or spending money. Show the operation, target, destination, amount, and data to be sent or changed from the actual action; make full arguments available and indicate any truncation. Do not rely only on a model-generated summary.
- Bind approval to the authenticated user, tenant, exact action and arguments, and an expiration. Enforce single use atomically, reject replay or changed arguments, and recheck authorization immediately before execution. Use idempotency controls for retries. Approval does not override policy or permissions.
- Restrict outbound destinations and network access independently of the model. Account for redirects, DNS resolution, private and metadata addresses, and data sent through tools or rendered links.
- Bound tool calls, execution time, recursion, concurrency, and cost for each run. Provide cancellation and a way to disable a tool or agent without disabling unrelated services.

### MCP and integrations

MCP connects an AI host to external tools and data. It does not by itself establish that a server, tool description, or result is trustworthy.

- Inventory and approve servers, their owners, versions, tools, permissions, and data destinations. Review changes to server code, tool definitions, or permissions before allowing them; treat descriptions and returned content as untrusted.
- Follow the consent requirements of the MCP version in use. For material actions, also apply the action-specific approval and authorization controls above.
- For remote HTTP servers, use TLS and an approved authentication flow. Validate token issuer, audience, expiry, and scope through signature verification or introspection. Accept only tokens intended for the MCP server; obtain separate, appropriately scoped credentials for downstream APIs rather than passing MCP tokens through.
- Review OAuth client registration, consent, and redirect handling. Restrict metadata discovery and redirects to prevent server-side request forgery.
- Local stdio servers run as processes with the host's available privileges. Restrict their filesystem, network, and environment access; do not expose production credentials unnecessarily.

### Resource and cost controls

- Enforce server-side limits for users, tenants, and workloads on request rate, input and output size, concurrency, and cost. Include multimodal inputs, retries, tool calls, agent steps, and execution time.
- Reserve estimated usage against shared budgets before starting concurrent work, reconcile actual usage, and stop scheduling work when limits are reached. Test exhaustion, cancellation, and recovery.
- Use provider-side spending limits where available; alerts alone are not a cap. Document whether limits are hard or approximate, and account for in-flight requests and billing delays.

---

## Model, data, and infrastructure lifecycle

- Inventory model providers and versions, weights, adapters, tokenizers, serving libraries, plugins, and training or evaluation datasets where applicable. Record provenance, license terms, and owners; document unknowns when a hosted provider does not expose a version or artifact.
- Pin artifacts to immutable versions or digests where possible. Verify a digest against a trusted expected value and verify publisher signatures or attestations when available. Integrity and provenance checks do not prove an artifact is safe.
- Do not load untrusted serialized models or run custom model-loading code in a privileged environment. Prefer non-executable formats where available, review loaders and dependencies, and isolate inspection of unfamiliar artifacts.
- Track dataset origin and changes; restrict ingestion and review feedback before it is used for training or fine-tuning. Keep evaluation data separate and retain a way to roll back a model or remove a poisoned corpus.
- For predictive or other non-generative ML, assess evasion, data poisoning, model extraction, and inference of training-data membership where relevant. Test with representative inputs, limit API access and information exposure as appropriate, monitor for drift, and define a rollback path. No single model-level defense eliminates these risks.
- For hosted services, confirm the applicable contract and technical settings for data use, training, retention, deletion, regions, and subprocessors. Minimize data sent to providers and reassess fallbacks or provider changes. Record unverified provider commitments and the residual risk.
- Protect self-hosted inference endpoints, storage, and GPU hosts as production infrastructure: authenticate access, patch runtimes, limit network exposure, and enforce quotas.

See the [AI/model supply-chain checklist](software-supply-chain-security.md#ai--model-components-when-applicable) for related evidence.

---

## Evaluation and regression tests

Test in an authorized environment with synthetic data, canary records, and controlled destinations. Check observable access, tool, network, and audit events rather than relying only on the model's reply.

| Scenario | Expected evidence |
|---|---|
| A document or tool result instructs the agent to disclose data or call an unapproved destination. | No unauthorized data leaves the system and no unauthorized action occurs, even if the model follows the instruction. |
| One user requests another user's or tenant's document, including a cached answer and a document whose access was revoked. | Unauthorized chunks do not reach the reranker, model, or response; stale cached or saved results are denied. |
| A tool request has invalid arguments, insufficient permissions, or a changed, expired, or replayed approval. | The request is denied without side effects; an authorized, unchanged request succeeds under the intended identity. |
| Generated output contains hostile HTML, SQL, commands, or a remote image link. | The relevant sink treats it as data or blocks it; it does not execute or initiate an unauthorized fetch. |
| Concurrent requests or a tool loop exceed a configured limit. | The enforcement point stops further work, records the outcome, and isolates the affected user or tenant as designed. |
| A model artifact fails verification or a poisoned source is identified. | Promotion or ingestion is blocked or quarantined; the affected component can be removed or rolled back. |
| A legitimate user performs a normal retrieval and an approved action. | The authorized workflow still works, with the expected permissions and audit events. |

Record each scenario's attacker objective, model and application versions, policy configuration, inputs, attempts, outcomes, and evidence. Define valid attempts before testing, record exclusions and reasons, and repeat probabilistic tests. Report the attack success rate: attempts that achieve the defined attacker objective divided by valid attempts. Require zero unauthorized access or actions in the tested cases and track failures of legitimate workflows separately. Retest after changes to models, prompts, tools, data, permissions, or provider settings. Passing tests reduces uncertainty; it does not prove prompt injection is eliminated.

---

## Observability and incident response

- Log security-relevant metadata by default: time, request or run ID, user and tenant identifiers, model and version when available, retrieval or policy decisions, tool and approval outcomes, and usage or limit events. Correlate a proposed action with its authorization, approval, and execution. Protect and retain this metadata according to its sensitivity.
- Do not log full prompts, completions, retrieved documents, or tool payloads by default. When content is necessary for a documented purpose, minimize and redact it, restrict access and retention, and audit access. Never put credentials in logs.
- Alert on useful signals such as repeated authorization denials, unexpected external destinations, approval replay, or unusual tool and token consumption. Investigate against the workload's baseline; an anomaly alone is not proof of an attack.
- Prepare a runbook to disable a compromised tool or integration, revoke credentials, preserve appropriate evidence, identify affected users and data, remove poisoned content, and restore a known-good model or index. Test the runbook and escalation path.

For general telemetry validation and detection practices, see [`security-operations-detection-engineering.md`](security-operations-detection-engineering.md).

---

## Assessment checklist additions

Use the applicable items below alongside the [application security assessment template](application-security-assessment-template.md). Record evidence, owners, exceptions, and residual risk; mark components that are not present as not applicable.

- [ ] Data flows, providers, models, users, tools, and trust boundaries are documented.
- [ ] Data access and tool actions are authorized for the requester at the resource boundary, including across tenants and agent handoffs.
- [ ] Retrieval, memory, and caches enforce permissions and handle revocation and deletion.
- [ ] Tool capabilities are limited; material actions have transaction-specific approval and are reauthorized at execution.
- [ ] MCP servers and other integrations are inventoried, reviewed, and constrained where used.
- [ ] Model output is validated and handled safely for each destination; sensitive decisions have an independent verification path.
- [ ] Model and dataset provenance, artifact integrity, provider data handling, and applicable license terms are reviewed.
- [ ] Per-user, tenant, and run limits cover model usage, tools, time, and cost; enforcement and cancellation are tested.
- [ ] Adversarial and authorized-path tests have reproducible results and owners for remediation.
- [ ] Privacy-preserving telemetry, incident response, and rollback or disablement are tested.
- [ ] Privacy, contractual, and AI-specific obligations are assessed for the product and jurisdictions involved.

For example, California's [automated decisionmaking regulations](https://cppa.ca.gov/regulations/ccpa_updates.html) and [AB 2013 training-data transparency provisions](https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202320240AB2013) are separate requirements with different scopes. Confirm applicability and current obligations with legal and privacy teams; this reference is not legal advice.

---

## Code-generation tooling (Copilot-class) used by your developers

- Approve tools and providers based on what repository content, prompts, and telemetry they can access or transmit. Apply organization policy to customer data, confidential material, and secrets.
- Review the permissions of IDE extensions, agents, and MCP servers. Repository files, issues, and dependency documentation can contain instructions intended to steer an assistant.
- Review and test generated changes as human-written code, especially authentication, authorization, and cryptography. Verify suggested dependencies and licenses; run the normal secret, dependency, and security checks.
- Do not assume a secret scanner or provider setting catches every sensitive value. Limit context and tool access before data leaves the environment.

---

## AI assistance in security work itself

LLMs can help summarize evidence or draft a review, but they do not replace the reviewer's judgment.

1. Read the underlying evidence and verify material claims, citations, and recommendations.
2. Keep the named reviewer accountable for the final record and disclose AI assistance where policy requires it.
3. Use approved services and data-handling controls; do not submit customer data, confidential material, or sensitive indicators to an unapproved service.

---

## What "good" looks like for an LLM feature review

The review leaves an owner, applicable risks, control evidence, test results, and documented decisions on unresolved risks. Use the [assessment checklist](#assessment-checklist-additions) to capture them.
