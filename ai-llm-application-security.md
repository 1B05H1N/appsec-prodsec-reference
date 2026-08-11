# AI and LLM Application Security

> **Note**: This is based on ***my personal experience/recommendations*** and does not represent the required/official methodology used at any organization I've worked for or currently work at.

---

## Overview

LLM features are now embedded in nearly every product. The patterns that put applications at risk are recognizable from older application security work - untrusted input concatenated into a privileged context, output passed to a sensitive sink without validation, excessive automation without human checks. The vocabulary is new; most of the failure modes are not.

This document is a working reference for application and product security teams reviewing LLM-integrated systems. It pairs with [`secure-design-reference.md`](secure-design-reference.md) and [`application-security-assessment-template.md`](application-security-assessment-template.md).

---

## Authoritative references

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) - the working language for LLM-specific risk classes.
- [OWASP AI Exchange](https://owaspai.org/) - broader AI security reference covering training, deployment, and lifecycle.
- [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/) - for traditional ML pipelines.
- [NIST AI Risk Management Framework (AI RMF 100-1)](https://www.nist.gov/itl/ai-risk-management-framework) and the [Generative AI Profile (NIST AI 600-1)](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-600-1-generative-ai-profile).
- [NIST SP 800-218A - Secure Software Development Practices for Generative AI and Dual-Use Foundation Models](https://csrc.nist.gov/pubs/sp/800/218/a/final).
- [Cloud Security Alliance AI Controls Matrix](https://cloudsecurityalliance.org/research/working-groups/artificial-intelligence).
- [MITRE ATLAS](https://atlas.mitre.org/) - adversarial threat landscape for AI systems.
- For California: [CCPA/CPRA](https://oag.ca.gov/privacy/ccpa) automated-decision-making rules and [California AB 2013](https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202320240AB2013) training-data disclosure obligations on the timeline published by the California Privacy Protection Agency.

---

## OWASP LLM Top 10 - what to look for in review

| Class | What to look for |
|---|---|
| **LLM01 Prompt Injection** | Untrusted input concatenated into the prompt; tool calls invoked from user content; no isolation between system and user prompts; indirect injection via documents, web pages, or email content the model processes. |
| **LLM02 Sensitive Information Disclosure** | Prompts containing customer PII; completions echoing other tenants' data; no PII redaction on the way in; no DLP on the way out. |
| **LLM03 Supply Chain** | Model weights, base images, adapters, and embeddings from unverified sources; no signing or attestation; pinned by reference, not by hash. |
| **LLM04 Data and Model Poisoning** | Public datasets used for fine-tuning without provenance; user-supplied training data; backdoored embeddings. |
| **LLM05 Improper Output Handling** | Model output passed to a shell, SQL engine, or browser without sanitization; markdown/HTML output rendered without sanitization. |
| **LLM06 Excessive Agency** | Tool calls with broad scope; agents that can write files, execute code, or transfer money without confirmation; tools chained without intermediate review. |
| **LLM07 System Prompt Leakage** | System prompt containing secrets, jailbreak instructions, or sensitive policy that is recoverable by the user. |
| **LLM08 Vector and Embedding Weaknesses** | Cross-tenant leakage in shared vector stores; metadata-based exfiltration; embedding inversion attacks. |
| **LLM09 Misinformation** | Model used as the source of truth for decisioning without human verification; hallucination as a customer-visible failure. |
| **LLM10 Unbounded Consumption** | No rate limit, no spend cap, no per-user quota; model used as an oracle for fan-out scraping. |

---

## Design principles for LLM-integrated applications

1. **Treat all model input as untrusted, including content fetched on the model's behalf.** Indirect prompt injection is the dominant real-world attack today. A web page, a PDF, or an email summarized by the model is an attacker-controlled string.
2. **Separate system intent from user content.** Use the API's distinct system / user / tool message channels rather than concatenating user content into a single prompt string.
3. **Treat tool outputs as untrusted.** A tool call result that contains "ignore previous instructions" must not steer the model.
4. **Minimize agency.** Make actions advisory by default. Require explicit confirmation for material actions (file writes, network calls to internal hosts, money movement, identity changes, data deletion).
5. **Sanitize at the sink, not at the source.** Output that goes to a shell, SQL, or browser sink is escaped at that sink. Do not trust regex-based "safety" prompts to keep dangerous strings out of the output.
6. **Constrain output shape.** Use structured output (JSON schema, function calling) when the downstream code needs structure. Reject malformed responses rather than trying to clean them.
7. **Bound consumption.** Per-user rate limits, per-tenant spend caps, per-request token caps. Implement at the API gateway, not inside the application code.
8. **Log everything that matters.** Prompt, completion, tool calls, tool results, model identity, model version. Treat these as sensitive logs with the same access controls as production application logs.
9. **Plan for the model to lie.** If a customer-visible answer must be correct, design a verification step (retrieval grounding, source citation, human review) before the answer ships.
10. **Plan for the model to be replaced.** Vendor models change, deprecate, and reprice. Decouple the application from any single model so a switch is operational, not architectural.

---

## Threat modeling extensions for LLM features

Add to the existing [STRIDE / PASTA](secure-design-reference.md#popular-methodologies) work:

| Decomposition addition | Question |
|---|---|
| Trust boundaries | Where does untrusted content reach the prompt? Where does model output reach a privileged sink? |
| Data flows | What flows to the model provider? Where (region, legal entity)? With what retention? Used for training? |
| Tools and agents | What tools can the model invoke? What is the worst single tool call? What is the worst chain of tool calls? |
| Memory | What persists across conversations? Per-user? Per-tenant? Cross-tenant? |
| Output sinks | What downstream system trusts the output? What happens if the output is hostile? |

The MITRE ATLAS framework is useful for naming attacker techniques (e.g., LLM Prompt Injection, LLM Data Leakage) once the threats are identified.

---

## Assessment checklist additions

For an existing assessment template (see [`application-security-assessment-template.md`](application-security-assessment-template.md)), add the following items when reviewing LLM-integrated functionality.

### Architecture and data flow

- [ ] Documented data flow showing user -> application -> model provider -> response -> application -> user.
- [ ] Named legal entities and regions at every hop (model provider, hosting provider, vector store provider, embedding provider).
- [ ] Documented training-data use, retention, and deletion behavior on the model provider's side.
- [ ] Subprocessor disclosure aligned to the application's DPA / privacy notice.

### Prompt construction

- [ ] System / user / tool messages segregated by message channel, not by string concatenation.
- [ ] Untrusted content (RAG sources, tool outputs, user uploads) clearly delimited and labeled.
- [ ] System prompt does not contain secrets, API keys, or sensitive policy that an attacker could recover.

### Output handling

- [ ] Model output to shell / SQL / OS commands is rejected by default; if used, escaped at the sink.
- [ ] Model output to a browser is sanitized for HTML / markdown / inline scripts.
- [ ] Structured output enforced via schema or function calling where downstream code requires structure.
- [ ] Output validation rejects malformed responses rather than attempting to repair them.

### Tools and agency

- [ ] Inventory of tools the model can call, with scope and allowed arguments documented.
- [ ] Material actions (write, delete, transfer, identity change) require human-in-the-loop confirmation.
- [ ] Tool calls fail closed when arguments are out of expected shape.
- [ ] Tool call audit log retained for incident response.

### Authentication, authorization, and tenancy

- [ ] Model calls authenticated by the application, not by client-supplied credentials.
- [ ] Per-tenant isolation in vector stores; cross-tenant retrieval impossible by design.
- [ ] OAuth scopes for any IdP-integrated AI features reviewed; admin consent only for sensitive scopes.

### Rate, cost, and observability

- [ ] Rate limits per user and per tenant at the gateway.
- [ ] Spend caps enforced and alerted on.
- [ ] Token usage telemetry available to security and finance.
- [ ] Prompt and completion logs retained with appropriate access control.

### Privacy and compliance

- [ ] PII detection / redaction on prompts where the application processes customer data.
- [ ] DPA covers the model provider as a subprocessor; DPIA / impact assessment performed where required.
- [ ] CCPA / CPRA automated-decision-making and California AB 2013 obligations evaluated where applicable.

### Self-hosted models (when in scope)

- [ ] Model weights provenance recorded (publisher, hash, source URL).
- [ ] Model card and license reviewed (commercial-use restrictions, dataset attribution).
- [ ] Inference runtime treated as a normal application: full IS technical review.
- [ ] GPU host hardened; output-handling controls equivalent to hosted.
- [ ] Quotas and observability at the gateway, not inside the application.

---

## Code-generation tooling (Copilot-class) used by your developers

Treat code-generation tools like any other developer-installed software, with additions:

- Vendor's data-handling policy for code context shipped to the model.
- Telemetry on suggestion acceptance and on the resulting CVE / SAST findings.
- IP and license-attribution risk on suggested snippets.
- DLP / secret-detection on the IDE side to prevent secrets being shipped to a vendor model.
- Written guidance to developers: do not paste customer data, do not paste vendor-confidential material, do not blindly accept security-sensitive code (cryptography, authentication, authorization).

---

## AI assistance in security work itself

Using LLMs to summarize sandbox reports, draft IS Review Records, explain manifests, or read decompilation output is fine when bounded.

Practical guardrails:

1. The reviewer reads the underlying evidence; the LLM does not replace reading the report.
2. LLM-drafted text is treated as a starting draft; the named reviewer is responsible for the record.
3. Do not paste customer data, vendor-confidential material, or proprietary IOCs into a public LLM. If the organization runs an internal LLM with appropriate controls, use that.
4. Disclose AI assistance on the record where it materially shaped the output.

---

## What "good" looks like for an LLM feature review

- Data flow diagram with named entities and regions.
- OWASP LLM class mapping and per-class mitigations.
- Tool inventory and worst-case action analysis.
- Prompt / completion logging and observability.
- Rate and spend caps in place.
- Per-tenant isolation evidence for vector stores.
- DPA covering the model provider.
- Sign-off by application security with a documented residual risk statement.
