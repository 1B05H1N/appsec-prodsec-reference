# Security Operations, Detection Engineering, and Practical Security Automation

> **Note**: This is based on ***my personal experience/recommendations*** and does not represent the required/official methodology used at any organization I've worked for or currently work at.

---

## Overview

Security operations programs fail for predictable reasons:

- They ingest too much data and still miss what matters.
- They alert on everything and investigate nothing well.
- They automate fragile logic that nobody trusts.
- They write clever code that one person understands.

A practical program does the opposite:

- Define what must be logged and why.
- Verify that required telemetry is actually present.
- Build a small set of high-value detections first.
- Automate repeatable work only after the process is stable.
- Keep code and playbooks simple enough that the next person can run them.

This guide is for that practical path.

---

## Authoritative references

- [NIST SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) and [SP 800-92 Rev.1 (draft)](https://csrc.nist.gov/pubs/sp/800/92/r1/ipd) for log management planning and operations.
- [NIST SP 800-61 Rev.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) and [NIST SP 800-61 Rev.3](https://www.nist.gov/publications/computer-security-incident-handling-guide-3) for incident lifecycle and detection-to-response integration.
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) for Govern/Identify/Protect/Detect/Respond/Recover alignment.
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet) for secure logging design and event content.
- [MITRE ATT&CK](https://attack.mitre.org/) and [CISA MITRE ATT&CK Mapping Best Practices](https://www.cisa.gov/sites/default/files/2023-01/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf) for use-case design and coverage measurement.
- [OpenTelemetry specification](https://opentelemetry.io/docs/specs/otel/) for telemetry consistency across logs, metrics, and traces.
- [CISA SIEM/SOAR implementation guidance](https://www.cisa.gov/resources-tools/resources/guidance-siem-and-soar-implementation) for implementation order and operational pitfalls.
- [Sigma rules](https://sigmahq.io/) for portable detection content.

---

## Core principles

1. **Coverage before cleverness**: if you cannot prove required events are logged, detection quality is secondary.
2. **Signal over volume**: one accurate alert with a runbook is better than 50 noisy alerts.
3. **Human-centered automation**: automate repetitive tasks, not risk decisions.
4. **Readable engineering**: hard-to-read code is operational debt, not technical excellence.
5. **Admit uncertainty early**: no one knows everything; asking for help is a control, not a weakness.

---

## Build logging as a policy requirement

Logging cannot be an implementation detail left to each team. It needs policy backing.

### Minimum policy statements

Define and approve a logging and monitoring standard with these statements:

- Critical systems must produce required security events as defined in the event catalog.
- Logs must include source identity, timestamp, outcome, and correlation identifier.
- Sensitive fields must be redacted or tokenized before storage.
- Clock synchronization is mandatory for all systems sending telemetry.
- Log retention and access controls must align with legal, regulatory, and incident response requirements.
- Logging controls are tested quarterly for both coverage and integrity.

### Event catalog (required)

Build a shared event catalog per system type. Example categories:

- Authentication success/failure, MFA challenge outcomes, session issuance and revocation.
- Authorization decisions, privilege changes, policy denials.
- Data access to restricted datasets, bulk export events, unusual query patterns.
- Process execution, script interpreter launches, service creation, scheduled task creation.
- Endpoint security control events (tamper, quarantine, policy bypass attempts).
- Cloud control plane changes, secret access, key management operations.
- Application security events from server-side validation and abuse controls.

If an event category matters for an alert or investigation, it belongs in the catalog and in policy.

---

## Verify "what should be logged" is actually logged

Stated logging requirements are meaningless without verification.

Use a recurring telemetry validation process:

1. Pick a required event from the catalog.
2. Trigger it in a controlled test.
3. Confirm event appears in source log.
4. Confirm event reaches the log pipeline.
5. Confirm parsed fields are correct in the SIEM.
6. Confirm retention and queryability are as expected.

Track pass/fail as a control metric. Missing telemetry should create engineering work items with due dates.

Suggested KPIs:

- Event catalog coverage rate = validated required events / total required events.
- Parser health rate = normalized events / raw ingested events.
- Timestamp integrity rate = events with valid time and source identity.

---

## Detection engineering lifecycle

Treat detections like product features with ownership and quality gates.

### 1) Use-case definition

Each use case should have:

- Threat statement tied to ATT&CK tactic/technique.
- Required telemetry fields.
- Detection logic (what qualifies as suspicious).
- False positive expectations.
- Triage steps and escalation criteria.
- Containment and response playbook link.
- Owner and review cadence.

### 2) Data readiness check

Before writing logic, verify telemetry is present and trustworthy.

### 3) Rule implementation

Prefer simple and explicit logic first. Add complexity only when needed by measured false positives.

### 4) Test and tune

Use controlled simulations, replayed logs, and purple-team scenarios where possible.

### 5) Deploy with guardrails

- Phased rollout: observe mode -> low-impact notify -> full alerting.
- Add suppression only with documented rationale.
- Set expiry on temporary suppressions.

### 6) Operate and review

Measure precision, recall proxy metrics, triage time, and incident conversion rate.

---

## Alert quality standards

An alert is only useful if an analyst can act on it quickly.

Minimum alert content:

- What happened.
- Why it fired (rule logic summary).
- Who/what is impacted.
- ATT&CK mapping.
- Confidence and severity.
- Immediate triage checklist.
- Suggested containment actions.

Poor alert examples:

- "Suspicious activity detected."
- "Rule matched threshold."

Good alert examples:

- "Three failed admin logins from new ASN followed by one success and privileged role assignment within 10 minutes for account X."

---

## Automation strategy that reduces manual effort

Automation should remove toil, not hide process gaps.

### Automate first

- Data quality checks (missing logs, parser failures, schema drift).
- Alert enrichment (asset owner, vulnerability context, identity context, known good baselines).
- Case creation and routing.
- Deduplication and grouping.
- Repeatable evidence collection.

### Automate later

- High-impact containment actions (disable account, isolate host, revoke tokens) unless confidence is high and rollback is clear.

### Never automate blindly

- Actions with customer impact.
- Actions with irreversible data impact.
- Actions where confidence is low or telemetry is incomplete.

The [CISA SIEM/SOAR guidance](https://www.cisa.gov/resources-tools/resources/guidance-siem-and-soar-implementation) is clear on this sequence: stabilize SIEM fundamentals before aggressive SOAR playbook expansion.

---

## Logging and monitoring architecture (practical baseline)

You do not need a perfect architecture on day one. You need one that works and is maintainable.

Baseline layers:

1. **Producers**: endpoints, identity provider, cloud services, applications, network controls.
2. **Collection**: agents, syslog, API pulls, message bus.
3. **Normalization**: common schema with strict field naming.
4. **Storage**: hot searchable + warm/archive with retention controls.
5. **Detection layer**: correlation rules, behavioral analytics, Sigma-based reusable content.
6. **Case management**: ticketing, triage ownership, SLA tracking.
7. **Automation**: enrichment and low-risk response actions.

Use [OpenTelemetry](https://opentelemetry.io/docs/specs/otel/) where possible for consistent telemetry semantics. It will reduce parser complexity and lower long-term maintenance cost.

---

## Engineering standards for detection code and automation code

Complex code that only one engineer can understand is not a strength in operations.

Set coding standards for detection and automation:

- Favor explicit logic over compact tricks.
- Keep functions small and single-purpose.
- Use descriptive names.
- Include examples in unit tests for expected and edge-case behavior.
- Require peer review for rule and playbook changes.
- Document assumptions and known blind spots.
- Include rollback instructions for every automated action.

If code needs a long explanation to be safe to run, simplify it.

---

## Operating model and role clarity

A practical team model:

- **Detection engineer**: builds and tunes use cases.
- **SOC analyst**: triages alerts and executes playbooks.
- **Security automation engineer**: builds enrichment and SOAR workflows.
- **Platform/data engineer**: owns telemetry pipeline reliability.
- **Threat analyst**: drives ATT&CK mapping and threat-priority alignment.

One person may hold multiple roles in small teams. The role names still matter because they clarify ownership.

---

## Culture and professionalism

Technical humility is part of operational maturity.

Expected behaviors:

- Say "I do not know" when uncertain.
- Ask for peer review before pushing risky changes.
- Escalate early when data is missing.
- Write playbooks so someone else can execute them under pressure.
- Treat post-incident reviews as learning work, not blame work.

Strong teams are not teams that never make mistakes. Strong teams identify gaps quickly and improve in public.

---

## Practical maturity path (90/180/365)

### First 90 days

- Build event catalog and approve logging policy statements.
- Validate top 20 required events end-to-end.
- Deploy 10-15 high-value detections with runbooks.
- Establish weekly detection tuning review.
- Automate basic enrichment and case routing.

### By 180 days

- Expand telemetry validation coverage to >= 70 percent of catalog.
- Add ATT&CK mapping coverage dashboard by tactic.
- Add parser/schema drift monitoring.
- Introduce phased automated containment for high-confidence cases.
- Measure alert precision and analyst toil reduction.

### By 365 days

- Telemetry validation coverage >= 90 percent.
- Detection engineering release process with tests and peer review.
- Mature SOAR playbooks with rollback patterns.
- Quarterly purple-team exercises mapped to ATT&CK.
- Demonstrable reduction in MTTD/MTTR and manual analyst workload.

---

## Suggested metrics

Detection quality:

- Precision proxy: true-positive investigations / total investigations.
- Alert-to-incident conversion rate.
- Mean time to triage (MTTT).

Pipeline quality:

- Event catalog coverage.
- Parser success rate.
- Schema drift incidents per month.

Automation quality:

- Manual steps removed per use case.
- Automation success rate.
- Automation rollback frequency.

Team quality:

- Runbook completeness rate.
- Peer review coverage.
- Post-incident action closure rate.

---

## Final reality check

No framework, SIEM, or SOAR product will compensate for undefined logging requirements, weak ownership, or unreadable automation code.

Start with clear requirements.
Validate telemetry.
Build a small set of reliable detections.
Automate the boring parts.
Keep it readable.
Ask for help when needed.
Repeat.

