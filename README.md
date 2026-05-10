# AppSec/ProdSec Reference

Curated notes on **application** and **product** security: design, assessment, operations-adjacent engineering, supply chain, and LLM risks. Written for practitioners who want checklists and patterns, not a vendor pitch.

> **Goal:** If this helps someone ship safer software or pass a better interview loop, it did its job.

---

## Disclaimer

> **Important notice:**  
> This repository reflects **personal study and practice**, not the policies, standards, or requirements of any employer, client, or school - past or present.

Material is provided **as-is**. Security changes daily; errors and stale detail are possible. **Use at your own risk** and validate against your own context. Nothing here is legal, regulatory, or HR advice.

---

## License

**Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0).** See [LICENSE](LICENSE).

---

## Career context

Hiring is uneven, timelines are long, and many teams run on tight budgets. If you are navigating that while reading technical references, see [career-outlook.md](career-outlook.md). For resume layout ideas and a **fictional** anonymized example, see [resume-guide-and-generic-example.md](resume-guide-and-generic-example.md).

---

## Repository name

**`appsec-prodsec-reference` still fits** this collection: it is about securing what you **build** (AppSec) and how security shows up in the **product** lifecycle (ProdSec). You do **not** need a new repository for that scope.

Rename only if you want a **broader umbrella** (for example personal blog, non-security topics, or multiple programs in one repo). Renaming on GitHub preserves redirects for a time but breaks bookmarks eventually - prefer a stable name and use the [companion repo](#companion-repository) for intake.

---

## Contents

- [secure-design-reference.md](secure-design-reference.md) - Secure design, Zero Trust, threat modeling, secure coding, IAM.
- [application-security-assessment-template.md](application-security-assessment-template.md) - Assessment template with pre-, during-, and post-assessment checklists.
- [security-engineer-architect-questions-with-answers.md](security-engineer-architect-questions-with-answers.md) - Interview questions with worked answers.
- [when-interviewing-methodology.md](when-interviewing-methodology.md) - Methodology for evaluating security candidates.
- [ai-llm-application-security.md](ai-llm-application-security.md) - LLM/AppSec addendum (OWASP LLM Top 10, NIST AI RMF, agents).
- [software-supply-chain-security.md](software-supply-chain-security.md) - Supply chain (SBOM, signing, SLSA, OpenSSF, SCVS).
- [security-operations-detection-engineering.md](security-operations-detection-engineering.md) - SecOps and detection engineering (logging, validation, automation).
- [career-outlook.md](career-outlook.md) - Job market and budget context (non-advice).
- [resume-guide-and-generic-example.md](resume-guide-and-generic-example.md) - Resume tips and a fictional example.
- [PUBLISHING.md](PUBLISHING.md) - Optional git steps for a clean public history and tags.

### Companion repository

- [software-approval-reference](https://github.com/1B05H1N/software-approval-reference) - Software you **bring in** (extensions, agents, installers, inventory, intake). Includes [DISCLAIMER](https://github.com/1B05H1N/software-approval-reference/blob/main/DISCLAIMER.md) and tooling for triage.

This repo centers on software you **build**; the companion centers on software you **run**.

---

## Usage

Fork or clone, then **adapt**. No single reference fits every org, regulator, or stack. Prefer small, verifiable changes over copying long policies wholesale.

---

## Publishing

If you mirror this work to GitHub with a scrubbed history and release tags, see [PUBLISHING.md](PUBLISHING.md).
