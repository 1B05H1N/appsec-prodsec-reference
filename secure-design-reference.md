# Overview

> **Note**: This is based on ***my personal experience/recommendations*** and
> does not in any way represent the required/official methodology used
> at anywhere I've worked or currently work.

Secure design principles are foundational guidelines that can be used when designing and building applications to ensure they are resilient to threats and vulnerabilities. In the context of application security, these principles are used to reduce risk by ensuring software is designed, developed, and maintained securely. This document describes some key secure design concepts in the context of application security.

## General Web Application/Product Security Checklist

1. Ensure data encryption both at rest and in transit.
2. Adopt a "Zero Trust" approach: Always validate data, even if sourced from your own database. Sanitize data under specific conditions.
3. Encode all outputs, and escape when necessary.
4. Regularly scan libraries and third-party components for vulnerabilities. Stay updated with new vulnerabilities and versions.
5. Implement all relevant security headers.
6. Set secure cookie configurations.
7. Categorize and tag all data processed by the application.
8. Use salted hashes for user passwords with a minimum salt length of 28 characters.
9. Store application-specific secrets in a dedicated secret vault.
10. Utilize service accounts exclusively within the application.
11. Encourage employees to use password managers and avoid password reuse.
12. Activate Multi-Factor Authentication (MFA) wherever feasible.
13. Avoid hardcoding and refrain from placing sensitive details in comments.
14. Leverage built-in security features of your framework, such as encryption, session management, and input sanitization. Avoid custom solutions if the framework offers them.
15. Regularly update your framework. Remember, technical debt equates to security debt.
16. Log all errors (excluding sensitive data). Trigger alerts for security-related errors.
17. Conduct server-side input validation and sanitization using an allowlist approach.
18. Mandate security testing prior to application release.
19. Undertake threat modeling before application deployment.
20. Design the application to handle errors gracefully, ensuring it defaults to a safe state.
21. Clearly define role-based access within project specifications.
22. Use parameterized queries exclusively, avoiding inline SQL/NOSQL.
23. Refrain from passing critical variables via URL parameters.
24. Adhere to the principle of least privilege, especially when interfacing with databases and APIs.
25. Continuously aim to reduce the application's attack surface.
26. A code security bug arises from coding errors, allowing users to exploit the application maliciously or in unintended ways.

## The Zero Trust Model

The Zero Trust model is a security concept centered on the belief that organizations should not automatically trust anything inside or outside their perimeters and instead must verify anything and everything trying to connect to its systems before granting access. In the context of application security, this approach is crucial to ensure that applications are protected from both external and internal threats.

### Core Principles

At its core, Zero Trust means that no one, whether inside or outside the organization, is trusted by default. Every access request is treated as if it originates from an untrusted network. In general:

- Users, systems, and applications should only have access to the resources they absolutely need and nothing more.
- Dividing the network into smaller zones ensures that even if an attacker gains access to one area, they can't easily move laterally to other parts of the network.
- Rely solely on server-side validated data for access control decisions.
- Default to denial: Ensure user authorization before executing functions.
- Always default to a safe state in case of failures. Ensure transactional integrity.
- Prioritize user authentication, followed by access authorization.
- Continuously verify access across all application pages and features, including page reloads.
- Ensure bidirectional authentication and authorization for APIs.
- Restrict access to unused protocols, ports, HTTP methods, etc., on your server, PaaS, or container.
- If feasible, deploy one application per server, PaaS, or container.

#### Application

- Authentication and Authorization: Every user or entity trying to access an application must be authenticated, and their access rights should be strictly defined and enforced. This often involves multi-factor authentication (MFA) and strict role-based access controls (RBAC).
- Continuous Monitoring and Validation: Even after initial access is granted, the behavior of users and entities should be continuously monitored. Any anomalies or deviations from expected patterns should trigger alerts or automatic revocations of access.
- End-to-End Encryption: Data, both at rest and in transit, should be encrypted. This ensures that even if data is intercepted, it remains confidential and secure.
- API Security: As applications increasingly rely on APIs for communication, ensuring secure API endpoints is crucial. Every API call should be authenticated and authorized, and data validation should be rigorous.
- Device Validation: In addition to user validation, the devices from which access requests originate should also be validated to ensure they meet security standards.

#### Benefits

- Reduced Attack Surface: By limiting access and continuously monitoring behavior, the potential points of vulnerability that an attacker can exploit are minimized.
- Enhanced Data Protection: With strict access controls and encryption, sensitive data is better protected against breaches.
- Improved Compliance: Many regulatory frameworks require stringent data protection measures. Adopting a Zero Trust model can aid in meeting these requirements.
- Flexibility and Scalability: As organizations adopt cloud services and remote working becomes more prevalent, Zero Trust offers a flexible and scalable approach to security that doesn't rely on traditional network perimeters.

#### Challenges and Considerations

- Complexity: Implementing a Zero Trust model, especially in large or legacy systems, can be complex and requires careful planning.
- Potential Performance Impact: Rigorous checks and continuous monitoring can introduce latency. It's crucial to implement Zero Trust in a way that balances security with user experience.
- Cultural Shift: Moving to a Zero Trust model can be a significant change for organizations used to a more open internal network. Training and awareness are essential to ensure that employees understand and adhere to the new protocols.

## Threat Modeling

Threat modeling is a structured approach used to identify, quantify, and address security risks associated with an application or system.

By understanding potential threats, developers and security experts can design systems that are resilient against known vulnerabilities and anticipate potential future threats.

### What is it?

- At its core, threat modeling is about understanding and categorizing potential threats to a system. It's a proactive approach to identify vulnerabilities and design countermeasures.
- The primary goal is to provide a systematic analysis of the potential threats that could compromise the security of a system and to define strategies to mitigate those threats.

#### Components

- Before identifying threats, it's crucial to understand what you're protecting. Assets can be tangible, like databases or servers, or intangible, like reputation or intellectual property.
- These are entities that might want to harm your assets. Understanding who might want to attack your system and their motivations can help in designing effective defenses.
- The paths or means by which an adversary can gain access to a system. Recognizing these can help in sealing off vulnerabilities.

### The Process

- Break down the system into its core components. This can be done using data flow diagrams, architectural diagrams, or any other method that provides a clear view of all system parts and their interactions.
- Using techniques like STRIDE or attack trees, enumerate the possible threats to each component.
- Not all threats have the same impact or likelihood. Tools like the Common Vulnerability Scoring System (CVSS) can help prioritize threats based on their potential impact and exploitability.
- For each identified threat, devise strategies or controls to mitigate or eliminate the risk.

#### Popular Methodologies

- STRIDE: Developed by Microsoft, it categorizes threats into six types - Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
- PASTA (Process for Attack Simulation and Threat Analysis): A seven-step, risk-centric methodology. It focuses on business-centric impacts and aligns the threat model with enterprise risk management.
- Trike: A risk-based approach that starts by defining a system's assets and then models threats against those assets.

### Benefits

- Instead of reacting to incidents, threat modeling allows organizations to proactively address vulnerabilities.
- By understanding potential threats, organizations can make informed decisions about where to allocate resources.
- Threat modeling provides a clear framework for discussing security concerns, making it easier for different teams to collaborate on security.

#### Challenges and Considerations

- The world of cybersecurity is dynamic. New vulnerabilities and attack vectors emerge regularly, requiring continuous updates to threat models.
- As systems grow in complexity, so do potential threats. Keeping up can be challenging, especially for large or legacy systems.
- No system is immune to human error. Even with a perfect threat model, mistakes can happen, leading to potential vulnerabilities.

#### Example Process

1. Sketching a system diagram highlighting your API's primary logical components.
2. Marking trust boundaries within the system, indicating areas under a single owner's control.
3. Illustrating data flow across the system components.
4. Analyzing each component and data flow for potential threats, especially across trust boundaries.
5. Documenting identified threats for tracking and management.

### Key Components

Definition: It's a proactive exercise to understand the potential threats your application or system might face. The goal is to review the design and code to ensure that identified threats are addressed and aligned with the project's security requirements.

Risk Acceptance: Any decision to accept a vulnerability should be documented. This acceptance should be endorsed by individuals with the requisite authority, such as management, C-level executives, or project stakeholders. The documentation should elucidate the rationale behind the acceptance.

Stakeholder Involvement: A holistic threat model requires input from various stakeholders, including business representatives, customers, security experts, tech architects, operations, and development teams.

1. Discussion Points: The team should collaboratively discuss potential risks, considering questions like:
    1. What potential security concerns keep you awake?
    2. How would you exploit the application if you were an adversary?
    3. Which threat actors should we be wary of?
    4. How can we safeguard users, including ourselves?
    5. What's the worst-case scenario?
2. Approach: The session can range from being casual, like creating attack trees, to being formal.
3. Abuse Stories: Transform project user stories into "abuse stories" or negative scenarios. This helps in visualizing what could go wrong if the application behaves unexpectedly.
4. Threat Modeling Techniques: Common methodologies include:
    1. Attack Trees: A graphical representation of threats, with the primary goal at the top and potential attack vectors branching out as leaves.
    2. STRIDE: Focuses on authentication, authorization, confidentiality, integrity, availability, and non-repudiation.
    3. PASTA: A comprehensive approach that considers business requirements, user stories, and data diagrams.
5. Objective: The primary goal is to generate pertinent questions that ensure a comprehensive understanding of potential threats.
6. Risk Evaluation: After listing concerns, assess their likelihood and potential impact. Not all risks are of equal consequence. Disregard any that are implausible or inconsequential.
7. Risk Rating: Classify the identified risks as high, medium, or low based on their probability and potential damage. Alternatively, use the CVE rating system or a scale of 1-10.
8. Action Plan: Decide on the next steps:
    1. Mitigate certain risks by addressing them.
    2. Monitor some risks for potential escalation.
    3. Accept some risks with proper documentation.
9. Documentation: The entire process, especially the final decisions, should be well-documented and endorsed by the management or authorized personnel.

Threat modeling is an essential component of a robust security posture. It not only helps in identifying potential threats but also in devising strategies to address them effectively. Proper documentation and stakeholder involvement are crucial for its success.

## Secure Coding

Secure coding practices are paramount to safeguarding applications from potential threats. By diligently validating, sanitizing, and managing untrusted data and sessions, developers can significantly reduce vulnerabilities and enhance system security.

### Sanitize Your Code

Automated code validation can help identify and rectify common memory management or concurrency issues. Incorporate these checks into your development process, either before submitting changes or as part of continuous integration. Key points include:

- Memory Management: One of the most common sources of vulnerabilities, such as buffer overflows and use-after-free errors, stems from improper memory management. Automated tools can detect these issues, allowing developers to address them before they become exploitable vulnerabilities.
- Concurrency Issues: Concurrency problems, like race conditions, can lead to unpredictable behavior, data corruption, or security vulnerabilities. Automated validation can spot potential synchronization issues or shared resource conflicts.
- Integration with Development Lifecycle: By integrating these tools into the development process, you ensure that code is checked regularly. This can be done pre-commit (before changes are submitted) or as part of a continuous integration (CI) pipeline, ensuring that vulnerabilities are caught and addressed promptly.

### Handling Untrusted Data

Untrusted data refers to any input from external sources. It's essential to validate and sanitize this data to ensure system security.

1. Validation: Always validate input for its type, size, format, and source. Ensure it aligns with the business context.
    1. Server-side validation is mandatory; client-side validation is insufficient.
    2. Reject inappropriate input and provide clear error messages indicating the expected input.
    3. Special characters should be treated with caution. Log any suspicious input for security analysis.
2. Escaping: If special characters are essential, escape them diligently. Utilize built-in functions or trusted third-party tools.
3. Transaction Security: For input-driven transactions, verify against CSRF attacks using tokens, captchas, or re-authentication.
4. Output Encoding: If the input is displayed back to the user, apply proper encoding to prevent cross-site scripting attacks.
5. Database Queries: Use parameterized queries or stored procedures to prevent SQL injection attacks. Avoid inline SQL.
6. Redirects and Forwards: Validate and whitelist URLs to prevent untrusted redirects.
7. HTTP Verbs: Disable unused HTTP verbs to minimize potential attack vectors.

### Identity Management

Identity Management refers to the processes, technologies, and policies involved in managing user identities and controlling access to resources within a system or network. It ensures that the right individuals access the right resources at the right times for the right reasons. Two critical components of Identity Management are Authentication and Authorization.

#### Authentication (AuthN)

Authentication is the process of confirming the identity of a user, system, or application. It's essentially answering the question, "Are you who you claim to be?"

##### Key Concepts

- Credentials: These are pieces of information that users provide to prove their identity. Common credentials include usernames and passwords, but they can also encompass more secure elements like biometric data (fingerprints, facial recognition) or smart cards.
- Multi-Factor Authentication (MFA): This is an enhanced security measure that requires users to provide two or more verification factors to gain access. Common factors include something you know (password), something you have (a smart card or mobile device), and something you are (biometric verification).
- Single Sign-On (SSO): A user authentication process that allows a user to access multiple applications or services with one set of credentials. It simplifies the user experience by reducing the number of times a user has to log in to access connected applications.

###### Challenges to AuthN

- Credential Management: As the number of digital services we use increases, managing multiple usernames and passwords becomes challenging for users, leading to poor practices like password reuse.
- Phishing and Attacks: Attackers often try to steal authentication credentials through deceptive means, such as phishing emails.

#### Authorization (AuthZ)

Once a user's identity is verified, the next step is to determine what they're allowed to do. Authorization is the process of granting or denying access to specific resources based on a user's identity.

##### Key Concepts

- Access Control Lists (ACLs): These are lists that specify which users or groups of users are granted or denied access to specific system resources.
- Role-Based Access Control (RBAC): Instead of assigning permissions to specific users, RBAC assigns permissions to specific roles. Users are then assigned roles, ensuring that they have the necessary permissions to perform their job functions but no more.
- Policy-Based Access Control (PBAC): Access decisions are made based on policies, which can consider context, such as the current time, the location of access, or the type of resource being accessed.
- Tokens: In many modern systems, after authentication, a user is provided with a token (like a JWT - JSON Web Token). This token can then be used to prove authentication and determine authorization without repeatedly checking the user's credentials.

###### Challenges to AuthZ

- Granularity: Determining the right level of granularity for permissions can be challenging. Too coarse, and you risk giving users access to things they shouldn't see. Too fine, and the system becomes complex and hard to manage.
- Drift: Over time, as people change roles or responsibilities, they might accumulate permissions that they no longer need, leading to potential security risks.

Ensuring that users are who they say they are (Authentication) and that they can only access what they're supposed to (Authorization) is crucial for maintaining the security, integrity, and functionality of digital systems.

As cyber threats continue to evolve, robust Identity Management practices will remain a critical defense line. Choose a trusted identity management system tailored to your needs. Avoid building custom systems unless absolutely necessary. If custom solutions are required, adhere to established protocols like OAUTH.

### Session Management

Sessions maintain user state and interactions. They are managed using session tokens or session IDs.

Session Tokens: These tokens, often interchanged with session IDs, are exchanged between the browser and server to maintain session continuity.

Session IDs: Session IDs should be a minimum of 128 characters and unpredictable. Use trusted random number generators like the RandomNumberGenerator.Create Method in the System.Security.Cryptography Namespace in .NET 7.

General recommendations:

- Always use the framework's built-in session management if available.
- Session IDs should have a defined expiration. They must be transmitted over encrypted channels and regenerated upon user login.
- Destroy sessions after logout and never accept externally generated session IDs. Treat any such occurrence as suspicious.
- Regenerate session IDs during significant events like authentication or privilege changes.

- Tokens maintain user state and interactions. They should be unpredictable, secure, and have a defined expiration.
- Session IDs should be transmitted securely, regenerated upon significant events, and destroyed after logout.
- Never accept externally generated session IDs and always ensure they're used securely.

### Bounds and Memory Management

#### Bounds Checking

When working with non-memory-safe languages, it's crucial to ensure that data stays within its intended boundaries to prevent buffer overflows and related vulnerabilities.

- Consistent Input Validation: Always check the bounds of every input. Rigorously and repeatedly test this functionality.
- Utilize Frameworks: If available, use frameworks or dependencies that automatically handle bounds checking.
- Type Checking: Ensure every input matches the expected data type. Test this thoroughly.
- Automated Testing: Implement unit tests for bounds checking to ensure continuous validation during development.
- Code Review: Regularly review code to ensure every input undergoes proper bounds checking.
- Penetration Testing: Engage penetration testers to specifically evaluate the robustness of your input bounds.
- Compiler Options: Use compiler options that help detect potential bounds issues.

#### Advanced Memory Protections

Consider adding runtime memory protections such as:

- Address Space Layout Randomization (ASLR)
- Data Execution Prevention (DEP)
- Stack Canary

#### Memory Safe Languages

If feasible, opt for memory-safe languages to inherently reduce the risk of memory-related vulnerabilities.

#### Strong Typing and Static Type Checking

Strongly typed languages enforce type compatibility, ensuring that data types match their intended use. This reduces errors and enhances security.

- Benefits: Strong typing and static type checking can catch a wide
