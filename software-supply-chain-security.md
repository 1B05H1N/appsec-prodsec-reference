# Software Supply Chain Security

> **Note**: This is based on ***my personal experience/recommendations*** and does not represent the required/official methodology used at any organization I've worked for or currently work at.

---

## Overview

Application security used to focus mainly on the code your team wrote. Today most of the code shipping in your product was written by someone else - open-source maintainers, vendors, language ecosystems, container base images, model providers. The Log4Shell, SolarWinds, xz-utils, and various npm-takeover events are all expressions of the same underlying issue: a dependency you did not write reached production with insufficient scrutiny.

This document is a working reference for the supply chain side of an application security program. It pairs with [`secure-design-reference.md`](secure-design-reference.md), [`application-security-assessment-template.md`](application-security-assessment-template.md), and the companion [`software-approval-reference`](https://github.com/1B05H1N/software-approval-reference) repository which covers third-party software brought **into** the environment.

---

## Authoritative references

- [NIST SSDF SP 800-218](https://csrc.nist.gov/projects/ssdf) - Secure Software Development Framework, the working US baseline cited in [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/).
- [NIST C-SCRM SP 800-161r1](https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final) - Cybersecurity Supply Chain Risk Management for federal-aligned programs.
- [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/www-project-software-component-verification-standard/) - practical levels of supply chain verification.
- [OWASP Dependency-Track](https://dependencytrack.org/) - open-source SBOM analytics and continuous monitoring.
- [OWASP CycloneDX](https://cyclonedx.org/) - SBOM standard.
- [OpenSSF SLSA](https://slsa.dev/) - Supply-chain Levels for Software Artifacts; build-integrity framework.
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) - automated security health checks for open-source repos.
- [SPDX](https://spdx.dev/) - alternative SBOM standard widely used by Linux distributions.
- [CISA Secure by Design](https://www.cisa.gov/securebydesign) - vendor practices that organizations should expect.

---

## Scope of "supply chain"

The term covers more than `npm install` outputs:

- **Source dependencies** - open-source and commercial libraries linked into your code.
- **Build dependencies** - compilers, linters, packagers, container builders.
- **Build environment** - CI runners, build agents, secrets used during build.
- **Artifact distribution** - registries, package repositories, signing infrastructure.
- **Runtime dependencies** - base images, OS packages, system libraries.
- **Vendor-furnished code** - third-party agents, drivers, browser extensions, embedded SDKs.
- **AI components** - model weights, embeddings, fine-tuned adapters.

Each layer has its own provenance, its own attack surface, and its own attestation pattern.

---

## SBOM - what it is, what it is not

A Software Bill of Materials is a machine-readable inventory of components in a build. It is the prerequisite for every other supply chain control: you cannot patch what you cannot see.

What an SBOM provides:

- A list of components with versions and (usually) licenses.
- A way to map a published CVE to whether your build is affected.
- Evidence for customers, regulators, or compliance reviewers.

What an SBOM does **not** provide on its own:

- Confirmation that the components are unmodified.
- Confirmation that the build environment was clean.
- Continuous monitoring - an SBOM is a snapshot.

The two common formats are CycloneDX (OWASP) and SPDX (Linux Foundation). CycloneDX is more security-focused and integrates well with [OWASP Dependency-Track](https://dependencytrack.org/). SPDX is the older format and is required in some federal contexts.

### Generating SBOMs with open-source tools

| Use case | Tool |
|---|---|
| Repository / source tree | [Syft](https://github.com/anchore/syft), [Trivy](https://github.com/aquasecurity/trivy) |
| Container image | Syft, Trivy, [Docker SBOM CLI](https://github.com/docker/sbom-cli-plugin) |
| Filesystem of a built artifact | Syft, Trivy |
| Language-specific (Go, Python, npm, Java, Rust, etc.) | [OSV-Scanner](https://github.com/google/osv-scanner), Trivy, language-native tools |
| Continuous SBOM analytics | [OWASP Dependency-Track](https://dependencytrack.org/) |

---

## Component analysis (vulnerability scanning of dependencies)

Once an SBOM exists, scan it against vulnerability feeds. Use multiple scanners - they pull from different feeds and have different blind spots.

| Tool | Feeds |
|---|---|
| [Grype](https://github.com/anchore/grype) | NVD, GitHub Advisory, distro feeds |
| [Trivy](https://github.com/aquasecurity/trivy) | NVD, GitHub Advisory, distro feeds |
| [OSV-Scanner](https://github.com/google/osv-scanner) | OSV.dev (Google's open-source vulnerability DB) |
| [Dependency-Track](https://dependencytrack.org/) | NVD, OSS Index, Snyk (with key), GitHub Advisory |

Cross-reference findings with the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - KEV-listed CVEs are the prioritized work.

[VEX (Vulnerability Exploitability eXchange)](https://cyclonedx.org/capabilities/vex/) is the mechanism for vendor-asserted "this CVE in this build is not exploitable because..." Useful when the vulnerability scanner is loud and the actual exploit path is closed.

---

## Build provenance and attestation (SLSA)

The [SLSA framework](https://slsa.dev/) defines build-integrity levels, from "no expectations" to "fully reproducible builds with attested provenance." For most application teams the practical destination is SLSA Level 3, which requires:

- Hosted build platform that produces unforgeable provenance (e.g., GitHub Actions with [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance), GitLab CI with appropriate features, Google Cloud Build).
- Provenance signed and stored alongside the artifact.
- Verification at deploy time.

Tooling:

- [Cosign](https://github.com/sigstore/cosign) and the broader [Sigstore](https://www.sigstore.dev/) ecosystem for keyless signing using OIDC identity from your CI provider.
- [in-toto](https://in-toto.io/) for chain-of-custody attestations across multi-step builds.
- [SLSA verifier](https://github.com/slsa-framework/slsa-verifier) at deployment.

---

## Open-source repository hygiene

Use [OpenSSF Scorecard](https://github.com/ossf/scorecard) on the third-party repos you depend on. A repository with low scores in branch protection, code review, signed releases, and pinned dependencies is itself a finding.

For your own repos, the same Scorecard checks are reasonable targets:

- Two-factor authentication required for maintainers.
- Branch protection on default branches.
- Code review on pull requests.
- Pinned action versions in CI (commit SHA, not tag).
- Signed releases.
- Token permissions minimized in CI.
- Secret scanning enabled.
- Dependabot / Renovate or equivalent active.

---

## CI / CD security

The build pipeline is where attackers move because it has the highest leverage - one compromised CI run can poison every artifact downstream. Common controls:

- Ephemeral build runners. No long-lived state on shared runners.
- Workload identity (OIDC) for cloud and registry access; no long-lived keys in CI variables.
- Pinned third-party CI actions to commit SHAs (`actions/checkout@v4` is a tag; pin to the SHA).
- Fail closed on vulnerability scans above a defined threshold for production builds.
- Signed artifacts pushed to registries; unsigned artifacts rejected at the deployment gate.
- Audit logs from CI shipped to your SIEM and retained per records schedule.
- Separation of build and deploy credentials.

---

## Container image hygiene

- Pin to digests, not tags. `nginx:1.27` is mutable; `nginx@sha256:...` is not.
- Use minimal base images ([distroless](https://github.com/GoogleContainerTools/distroless), [Chainguard images](https://images.chainguard.dev/), Alpine carefully due to glibc differences, Wolfi).
- Sign images with Cosign.
- Scan with Trivy / Grype at build and at admission.
- Admission control (e.g., [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper), [Kyverno](https://kyverno.io/)) to refuse unsigned or unscanned images.
- Re-scan periodically. New CVEs land against existing images every week.

---

## Third-party (vendor-furnished) software

Most application security programs cover what the team builds. They often miss what the team **runs** - agents, drivers, browser extensions, mobile apps, vendor-managed appliances, SaaS clients registered in the IdP. The companion repository [`software-approval-reference`](https://github.com/1B05H1N/software-approval-reference) covers this end-to-end:

- Intake and tiering for software brought into the environment.
- IS technical review with a single sandbox plus open-source tooling.
- Unified Threat / Operations / Detection lane for analyst capacity-constrained organizations.
- TPRM and AIM gating with explicit trigger conditions.
- Inventory reconciliation across CrowdStrike, Defender for Endpoint, KACE, Lookout, Intune, and Entra ID.
- Browser extension and driver review specifics.
- AI/LLM-integrated SaaS handling.

If your application security program does not have a counterpart for "third-party software running on our endpoints and in our cloud," that is a gap regulators routinely find.

---

## Assessment checklist additions

For an existing assessment template (see [`application-security-assessment-template.md`](application-security-assessment-template.md)), add the following items.

### SBOM and dependency analysis

- [ ] SBOM generated for every shipped artifact (CycloneDX or SPDX).
- [ ] SBOM stored alongside the artifact and shipped to customers when contracts require.
- [ ] Continuous SBOM analytics in place (Dependency-Track or equivalent).
- [ ] Vulnerability scanning runs on every build with a defined fail-closed threshold.
- [ ] KEV-listed CVEs prioritized; SLA defined.
- [ ] VEX statements published for false positives that customers will see.

### Build integrity

- [ ] Build provenance generated and signed for every release artifact.
- [ ] Signing keys managed via KMS or keyless (Sigstore / OIDC).
- [ ] CI runners ephemeral; no long-lived state.
- [ ] Workload identity for cloud and registry access; no long-lived secrets in CI.
- [ ] Third-party CI actions pinned to commit SHAs.

### Repository hygiene

- [ ] OpenSSF Scorecard run against own repositories with documented target scores.
- [ ] Two-factor authentication required for maintainers.
- [ ] Branch protection and required code review on default branches.
- [ ] Secret scanning and dependency update automation enabled.

### Container and runtime

- [ ] Images pinned to digests in production manifests.
- [ ] Minimal base images used.
- [ ] Image signing and admission control in place.
- [ ] Re-scan cadence defined and met.

### Third-party vendor and agent software

- [ ] Inventory reconciliation across endpoint and identity tools (see companion repo).
- [ ] AIM CI exists for every persistent agent, browser extension, and driver.
- [ ] TPRM gates triggered on the documented matrix.
- [ ] Reassessment cadence active for drivers and extensions on every version change.

### AI / model components (when applicable)

- [ ] Model weights provenance and hash recorded.
- [ ] Model card and license on file.
- [ ] Embeddings and adapters from trusted sources; signed where the publisher provides signing.
- [ ] Inference runtime treated as a normal application - see [`ai-llm-application-security.md`](ai-llm-application-security.md).

---

## Common pitfalls

- **An SBOM that nobody reads.** Generation without continuous analytics is paperwork. Wire the SBOM into Dependency-Track or an equivalent.
- **Vulnerability fatigue.** Hundreds of low / medium CVEs in transitive dependencies drown out the few that matter. Prioritize by KEV, exploitability, and reachability - not raw CVSS.
- **Pinning to tags.** `:latest` and floating semver ranges in production are a supply chain compromise waiting to happen.
- **Assuming the vendor's SBOM is enough.** Vendor-supplied SBOMs are a good starting point but rarely complete; supplement with your own analysis of installed artifacts.
- **Treating the model provider as if it were any other SaaS vendor.** Model providers are deeply privileged - they see every prompt and every uploaded document. The DPA, the subprocessors, and the training-data clauses matter more than the marketing copy suggests.
