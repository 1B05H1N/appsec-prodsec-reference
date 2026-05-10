# Resume guide and generic example

This is **not** career coaching or legal advice. It is a concise checklist plus a **fully fictional** resume you can use as a layout model. The sample body uses names and employers that **nod to** "JoJo's Bizarre Adventure" as obvious fiction, not real companies or real people.

If you maintain a private `*_master_generic.pdf`, keep it out of version control unless you intend it to be public; add it to `.gitignore` if needed.

---

## Practical tips (short)

- **Target one role per version** - AppSec IC, detection lead, and GRC-adjacent engineering read differently; swap bullets and keyword emphasis instead of one mega-resume.
- **Lead with outcomes** - what changed (risk, time, cost, coverage), how you measured it, and who benefited (customers, regulators, operators).
- **Stack depth honestly** - tools you operated in production beat a long list you only demoed.
- **Avoid unexplained acronyms** - spell out once, then abbreviate if space is tight.
- **PDF for submission** - Markdown is for editing; export a stable PDF for applications.
- **ATS** - simple headings, standard section titles, avoid text in images for the primary body.
- **Privacy** - redact internal codenames, unreleased products, and anything export-controlled; genericize employer details when posting publicly.

---

## Generic example resume (fictional, JoJo-inspired labels)

Organizations below are **invented** labels for a formatting demo. Do not imply you worked for anime licensors, studios, or any real firm with a similar name.

---

### JOSEPH JOESTAR

Metro area | (555) 010-0199 | joseph.joestar@example.com | linkedin.com/in/your-profile

---

### SECURITY ENGINEERING AND OPERATIONS LEADER

Hands-on leader with experience building detection, application security, and vulnerability programs in regulated and high-volume environments. Comfortable owning cross-functional roadmaps (SOC, IT, development) and reporting measurable improvements in detection performance, analyst workload, and exposure reduction.

---

### SELECTED IMPACT

- Re-established a dispersed security engineering function with a written charter, RACI, and operating cadence across operations and development.
- Improved mean time to detect through SIEM migration, higher-signal detections, and telemetry quality work.
- Cut recurring analyst toil with automation tied to case management and repeatable response paths.
- Reduced outstanding vulnerability backlog using threat-informed prioritization and clearer SLAs.

---

### EXPERIENCE

#### Speedwagon Foundation - Principal Security Engineer, Security Operations  
**20XX - Present** | Metro area

- Owns a multi-discipline engineering pod spanning threat intelligence, detection content, attack simulation, and vulnerability coordination within PCI/SOX/GLBA-style expectations.
- Led SIEM transition and authored detections mapped to MITRE ATT&CK; published coverage metrics for leadership.
- Ran purple-team exercises; tracked findings to owners with retest evidence.
- Partnered with application security on scanning, gates, and critical-release review.

#### Passione International Trading - Senior Application Security / Product Security Engineer  
**20XX - 20XX** | Metro area

- Operated edge protections and fraud-adjacent detections for high-volume web and API traffic.
- Ran coordinated disclosure and bug bounty pipelines with clear SLAs and engineering partnerships.
- Embedded SAST/DAST/SCA into delivery pipelines; reduced repeat classes of defects pre-release.

#### Sacred Heart Hospital Network - Technical Specialist, platform security  
**20XX - 20XX** | Metro area

- Operated application delivery controllers and WAF policies for clinical-facing services under HIPAA-oriented controls.

#### SPW Financial Group - Security Engineer  
**20XX - 20XX** | Metro area

- Tuned WAF and bot defenses; automated application scanning and SLA reporting.

#### Higashikata Commerce Company - Application Security Analyst  
**20XX - 20XX** | Metro area

- Scaled secure SDLC assessments and reusable standards across a broad application portfolio.

#### Zeppeli Technical Services - Systems Administrator  
**20XX - 20XX** | Metro area

- Windows/Linux/AD, networking, and scripting for internal infrastructure.

---

### SKILLS (illustrative groupings)

- **SIEM / XDR / SOAR:** example platforms you have actually administered
- **Detection:** ATT&CK mapping, hunting, purple team, validation
- **AppSec / exposure:** SAST/DAST/SCA, API testing, threat modeling
- **Edge / identity / cloud:** WAF, IdP, CSPM (as applicable)
- **Automation:** Python, Bash, PowerShell, ticketing APIs
- **Governance:** frameworks you supported in audits or exams (name the ones you can defend in an interview)

---

### EDUCATION

- **M.S., Cyber Security Engineering** - University (In progress or year)
- **M.C.I.S., Information Systems** - University (year)
- **B.S., Biology** - University (year) *(optional if space-constrained for pure security roles)*

---

### CERTIFICATIONS

- CISSP (Active)  
- Security+ ce (Active)  
*(List only what you will renew and can speak to.)*

---

## Mapping from your own master resume

When you maintain a private `*_master_generic.pdf`:

1. Export a **redacted** PDF with neutral employer wording for anything you might share broadly; keep JoJo-flavored labels for private drafts only if you want.
2. Keep a **separate** tailored PDF per job family with keywords from the posting mirrored in good faith.
3. Store PII-bearing sources outside the public git tree.
