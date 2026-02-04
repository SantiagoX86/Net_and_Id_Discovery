# Project Management Plan (Charter)

*Organization: WAUIG Bank
*Project Name: Enterprise Security Discovery Orchestration Framework
*Document Version: 1.0
*Document Date: 2025-12-05

---

## 1. Purpose

This Project Management Plan (Charter) formally authorizes the **Enterprise Security Discovery Orchestration Framework** and establishes the management structure, authority, and controls governing execution during the **Requirement / Planning, Design, Construct, and Test** phases of the WAUIG Bank SDLC.

This charter translates the approved Project Initiation Document into an executable management plan.

---

## 2. Project Description

The project will deliver a **Python-based, agentless, non-exploitative discovery framework** that provides auditable visibility into exposed network and system surfaces from a low-privilege vantage point.

The framework will be modular, extensible, and governed by strict discovery invariants to ensure alignment with WAUIG Bank security policy and regulatory expectations.

---

## 3. Project Objectives (Management View)

* Deliver an approved Network Discovery domain within the agreed schedule and budget
* Maintain strict adherence to SDLC governance and change control
* Ensure clear separation of discovery and exploitation capabilities
* Produce complete and reviewable documentation at each SDLC phase gate

---

## 4. Project Authority

This charter grants authority to the Project Manager to:

* Allocate approved project resources
* Schedule and conduct SDLC reviews
* Enforce scope boundaries and discovery invariants
* Escalate risks and issues to executive stakeholders

Development work may not proceed outside the scope defined in approved requirements documents.

---

## 5. Roles and Responsibilities

| Role                       | Name           | Responsibilities                               |
| -------------------------- | -------------- | ---------------------------------------------- |
| CEO                        | Chad Hemsworth | Executive sponsorship and funding approval     |
| CISO                       | Chris Boseman  | Security oversight and risk acceptance         |
| Project Manager            | Dana Whitlock  | Project execution, schedule, and scope control |
| Security Architecture Lead | Marcus Hale    | Architecture governance and design approval    |
| QA Lead                    | Natalie Chen   | Test planning and validation oversight         |
| Developer                  | Sean Santiago  | Design and implementation of framework         |

---

## 6. Project Scope Control

### In Scope

* Network Discovery domain implementation
* Core orchestration and normalization components
* Lab-based testing and validation
* Documentation required for SDLC compliance

### Out of Scope

* Exploit development or delivery
* Credentialed scanning or authentication attempts
* Production deployment to WAUIG Bank infrastructure
* Continuous or unattended execution

---

## 7. Schedule Summary

| SDLC Phase             | Planned Dates |
| ---------------------- | ------------- |
| Requirement / Planning | Dec 2025      |
| Design                 | Jan 2026      |
| Construct              | Feb–Mar 2026  |
| Test                   | Apr 2026      |

Milestone completion requires formal review and documented approval.

---

## 8. Budget Summary

The project will operate within the **ROM-approved budget** defined in the Project Initiation Document.

* Total Estimated Effort: ~520 hours
* Blended Engineering Rate: $120/hour
* **Total Estimated Cost:** $62,400 USD

Any forecasted variance greater than ±10% requires executive review.

---

## 9. Risk and Issue Management

| Risk                             | Impact | Mitigation                                      |
| -------------------------------- | ------ | ----------------------------------------------- |
| Scope expansion beyond discovery | High   | Formal change control enforcement               |
| Schedule overruns                | Medium | Phase-based milestones and reviews              |
| Misinterpretation of findings    | Medium | Evidence-based reporting and confidence scoring |

Issues will be tracked and escalated according to WAUIG Bank project governance standards.

---

## 10. Change Control

All changes to scope, requirements, or architecture must:

1. Be documented in a **Change Request**
2. Include impact analysis (cost, schedule, risk)
3. Receive approval from the Change Control Board (CCB)

### Change Control Board (CCB)

* Project Manager
* Security Architecture Lead
* CISO or Delegate

---

## 11. Communication Plan

| Audience               | Communication         | Frequency |
| ---------------------- | --------------------- | --------- |
| Executive Stakeholders | Status Summary        | Monthly   |
| Project Team           | Working Sessions      | Weekly    |
| Security Leadership    | Risk & Design Reviews | Per Phase |

---

## 12. Approval

Approval of this Project Management Plan authorizes execution of **Phase 2: Requirement / Planning** activities under the WAUIG Bank SDLC.

| Name           | Role            | Signature | Date       |
| -------------- | --------------- | --------- | ---------- |
| Chad Hemsworth | CEO             | ________  | 2025-12-08 |
| Chris Boseman  | CISO            | ________  | 2025-12-08 |
| Dana Whitlock  | Project Manager | ________  | 2025-12-08 |
