# Project Initiation Document (PID)

*Organization: WAUIG Bank
*Project Name: Enterprise Security Discovery Orchestration Framework
*Document Version: 1.0
*Document Date: 2025-11-18

---

## 1. Project Overview

WAUIG Bank is initiating the development of an **agentless, non-exploitative Security Discovery Orchestration Framework** designed to assess network, identity, host, application, and telemetry exposure from a low-privilege vantage point.

The framework will be used by Security Engineering and Red Team functions to:

* Understand externally and internally observable exposure
* Validate the effectiveness of security hardening initiatives
* Produce auditable, repeatable discovery results suitable for review and comparison

This project explicitly excludes exploitation, credential abuse, persistence mechanisms, or any activity that alters target system state.

---

## 2. Business Need

WAUIG Bank requires a controlled and auditable mechanism to evaluate security exposure without introducing operational or regulatory risk. Many existing tools:

* Rely on exploit-style techniques
* Require elevated credentials or agents
* Produce opaque or non-deterministic results

This project addresses these gaps by providing **discovery-only visibility** aligned with enterprise security governance and Secure Development Lifecycle (SDLC) controls.

---

## 3. Project Objectives

The primary objectives of this project are to:

* Develop a modular and extensible discovery framework
* Ensure all discovery actions are agentless, observable, and non-destructive
* Normalize findings to enable reporting, comparison, and auditability
* Support validation of security configuration changes through repeatable discovery output

---

## 4. Project Scope

### In Scope

* Python-based discovery orchestration framework
* Modular discovery domains, beginning with Network Discovery
* Structured and normalized discovery output
* Lab-based validation using Kali Linux to Windows systems

### Out of Scope

* Exploitation techniques or payload delivery
* Credential harvesting, brute-force attempts, or authentication abuse
* Persistence mechanisms or lateral movement
* Deployment to production banking infrastructure

---

## 5. Assumptions and Constraints

* The tool will be executed only by authorized security personnel
* All discovery actions must be attributable, observable, and repeatable
* Development will adhere to WAUIG Bank SDLC governance requirements
* Any changes in scope must follow formal change control procedures

---

## 6. Key Stakeholders and Roles

| Role                       | Name           | Responsibility                                |
| -------------------------- | -------------- | --------------------------------------------- |
| CEO                        | Chad Hemsworth | Executive sponsorship and strategic oversight |
| CISO                       | Chris Boseman  | Security governance and authorization         |
| Project Manager            | Dana Whitlock  | Schedule, scope, and delivery management      |
| Security Architecture Lead | Marcus Hale    | Architecture and design governance            |
| Developer                  | Sean Santiago  | Framework design and implementation           |

---

## 7. High-Level Timeline (Estimated)

| SDLC Phase             | Target Completion   |
| ---------------------- | ------------------- |
| Formation              | November 2025       |
| Requirement / Planning | December 2025       |
| Design                 | January 2026        |
| Construct              | February–March 2026 |
| Test                   | April 2026          |

---

## 8. Rough Order of Magnitude (ROM) Estimate

This Rough Order of Magnitude (ROM) estimate represents a **high-level internal cost projection** for development and validation.

### Estimated Effort

* Design and Development: ~320 hours
* Testing and Validation: ~120 hours
* Documentation and Reviews: ~80 hours

**Total Estimated Effort:** ~520 hours

### Cost Estimate (Internal Rate Model)

* Average blended engineering rate: **$120/hour**

**Estimated Total Cost:** **$62,400 USD**

> This estimate is preliminary and will be refined during the Requirement and Design phases.

---

## 9. Risks and Mitigations

| Risk                             | Mitigation                                             |
| -------------------------------- | ------------------------------------------------------ |
| Scope creep into exploit tooling | Enforce discovery invariants and formal change control |
| False confidence in findings     | Evidence attribution and confidence scoring            |
| Tool misuse                      | Restricted execution and clear documentation           |

---

## 10. Approval

Approval of this document authorizes the project to proceed to **Phase 2: Requirement / Planning** of the WAUIG Bank SDLC.

| Name           | Role            | Signature | Date       |
| -------------- | --------------- | --------- | ---------- |
| Chad Hemsworth | CEO             | ________  | 2025-11-20 |
| Chris Boseman  | CISO            | ________  | 2025-11-20 |
| Dana Whitlock  | Project Manager | ________  | 2025-11-20 |
