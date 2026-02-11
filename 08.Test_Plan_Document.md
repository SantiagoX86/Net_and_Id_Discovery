# Test Plan

**Enterprise Security Discovery Orchestration Framework**

* **Organization:** WAUIG Bank
* **Project Name:** Enterprise Security Discovery Orchestration Framework
* **Document Version:** 1.0
* **Document Date:** 2025-12-12
* **Author:** Sean Santiago
* **Phase:** SDLC Phase 5 – Test

---

## 1. Purpose

This Test Plan defines the **repeatable, auditable test cases** used to validate the Enterprise Security Discovery Orchestration Framework against a controlled lab environment. It operationalizes the Test Strategy by specifying **preconditions, steps, and expected results**.

---

## 2. References

* Test Strategy – Enterprise Security Discovery Orchestration Framework (v1.0)
* Implementation Plan (dated 2026-01-08)
* Architecture Design Document (v1.0)

---

## 3. Test Scope

### 3.1 In Scope

* M1: Core Framework (contracts + orchestrator behavior)
* M2: Network Discovery domain (host presence + TCP connect probing)
* M3: Output & Reporting (JSON + Markdown generation)

### 3.2 Out of Scope

* Exploitation, credentialed discovery, persistence, lateral movement
* Performance/load testing
* Production deployment validation

---

## 4. Test Environment

### 4.1 Lab Configuration

* **Source:** Kali Linux VM
* **Target:** Windows Sandbox VM
* **Virtualization:** VMware
* **Network Mode:** Host-Only
* **Credentials:** None

### 4.2 Tooling / Commands

* Framework harness: `testing_testing.py`
* Kali validation tools: `ping`, `nc`
* Windows validation tools: PowerShell `Get-NetTCPConnection`, `Get-NetFirewallProfile`, `Get-NetConnectionProfile`

---

## 5. Roles and Responsibilities

* **Developer / Test Executor:** Sean Santiago
* **Project Manager:** Dana Whitlock
* **CISO:** Chris Boseman
* **Approver (QA / Engineering Manager):** Taylor Nguyen

---

## 6. Entry Criteria

* M1–M3 implemented and accessible in the lab environment
* Kali and Windows VMs powered on and reachable at Layer 2/3 on the same subnet
* Developer harness available and able to execute without runtime errors

---

## 7. Exit Criteria

* All Priority 1 test cases pass
* Any failed test case has a documented defect or accepted risk
* Test Results Summary completed and reviewed by Project Manager + CISO

---

## 8. Test Data

* **Primary Targets:**

  * Windows VM IPv4 address on Host-Only subnet (dynamic)

* **Ports in Scope:**

  * 21, 22, 53, 80, 88, 135, 139, 389, 443, 445, 3389, 5985, 5986

---

## 9. Test Cases

> **Note:** Each test case is designed to validate **external exposure** rather than internal configuration.

### TC-NET-001 — Baseline Connectivity (Layer 2/3)

* **Priority:** P1
* **Objective:** Verify Kali can reach the Windows VM at the network layer before discovery runs.
* **Preconditions:** Both VMs on VMware Host-Only network.
* **Steps:**

  1. On Windows, run `ipconfig` and record IPv4.
  2. On Kali, run `ip route` and confirm route exists for the Windows subnet.
  3. On Kali, run `ip neigh show | grep <windows_ip>`.
  4. On Kali, run `ping -c 1 <windows_ip>`.
  5. On Kali, re-run `ip neigh show | grep <windows_ip>`.
* **Expected Results:**

  * Route exists for the subnet.
  * Neighbor table contains `<windows_ip>` with `lladdr` and state `REACHABLE` or `STALE`.
  * `ping` may succeed or fail depending on firewall posture, but ARP resolution must succeed.

---

### TC-NET-002 — Host Presence Output (ICMP Blocked)

* **Priority:** P1
* **Objective:** Validate host presence behavior when ICMP is blocked.
* **Preconditions:** Windows firewall enabled; ICMP echo replies blocked (default hardened posture acceptable).
* **Steps:**

  1. On Kali, run harness: `python3 testing_testing.py`.
  2. Review findings for `category = host_presence`.
* **Expected Results:**

  * A `host_presence` finding exists.
  * Evidence indicates ICMP method and `reachable: false`.
  * Harness completes without crash.

---

### TC-NET-003 — Filtered Ports (Timeout Behavior)

* **Priority:** P1
* **Objective:** Ensure filtered ports are not falsely reported as open.
* **Preconditions:** Windows firewall enabled; no inbound allow rules for 445/5985.
* **Steps:**

  1. From Kali, run:

     * `nc -n -v -z -w 2 <windows_ip> 445`
     * `nc -n -v -z -w 2 <windows_ip> 5985`
  2. Confirm both commands time out.
  3. Run harness: `python3 testing_testing.py`.
  4. Review findings for `category = open_port`.
* **Expected Results:**

  * `nc` shows `Connection timed out` for both ports.
  * Framework produces **no** `open_port` findings for 445/5985.
  * (Optional) Framework may emit `port_probe_error` for other ports.

---

### TC-NET-004 — Controlled Exposure Delta (Open Port Detection)

* **Priority:** P1
* **Objective:** Confirm the framework detects exposure changes after a single controlled firewall rule change.
* **Preconditions:** TC-NET-003 executed; ports 445/5985 filtered.
* **Steps:**

  1. On Windows (Admin PowerShell), set profile to Private:

     * `Set-NetConnectionProfile -InterfaceAlias "Ethernet0" -NetworkCategory Private`
  2. On Windows (Admin PowerShell), allow SMB inbound on Private:

     * `New-NetFirewallRule -DisplayName "Lab-Allow-SMB-In" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Profile Private`
  3. From Kali, run: `nc -n -v -z -w 2 <windows_ip> 445`.
  4. Run harness: `python3 testing_testing.py`.
  5. Review findings for `open_port`.
* **Expected Results:**

  * `nc` reports port 445 as open.
  * Framework produces an `open_port` finding for 445 with `service_hint: SMB`.
  * No unrelated ports become open unless explicitly configured.

---

### TC-NET-005 — Orchestrator Resilience (Module Error Containment)

* **Priority:** P1
* **Objective:** Ensure orchestrator continues execution if a module errors.
* **Preconditions:** Developer provides a temporary stub module that raises an exception (local-only test).
* **Steps:**

  1. Add a temporary module to the orchestrator list that raises an exception in `execute()`.
  2. Run harness.
  3. Review `events` output.
* **Expected Results:**

  * Run completes.
  * `events` contains an `event_type = module_error` entry.
  * Findings from non-failing modules are still returned.

---

### TC-REP-001 — Markdown Report Generation

* **Priority:** P1
* **Objective:** Ensure M3 generates a readable Markdown report.
* **Preconditions:** Harness writes `network_report.md`.
* **Steps:**

  1. Run harness: `python3 testing_testing.py`.
  2. Open `network_report.md`.
  3. Verify presence of sections: Header, Host Reachability, Exposed Services, Analyst Notes, Appendix.
* **Expected Results:**

  * Markdown file exists and is readable.
  * Exposed Services section accurately reflects `open_port` findings.
  * Appendix includes raw JSON blocks for each finding.

---

### TC-REP-002 — JSON Artifact Generation

* **Priority:** P2
* **Objective:** Ensure JSON run output is written and structurally valid.
* **Preconditions:** Harness writes `run_results.json`.
* **Steps:**

  1. Run harness.
  2. Validate JSON syntax: `python3 -m json.tool run_results.json`.
  3. Confirm JSON includes `context`, `findings`, and `events` keys.
* **Expected Results:**

  * JSON validates successfully.
  * Required keys exist.

---

## 10. Defect Management

* **Severity Guidelines:**

  * **S1:** False positive open port; crash preventing execution
  * **S2:** Missed detection of confirmed open port; reporting incorrect
  * **S3:** Minor formatting, non-critical noise, optional enhancements

* **Defect Recording:**

  * Document defects in a running Test Results Summary and link to repro steps.

---

## 11. Approvals

* **Prepared By:** Sean Santiago (Developer)
* **Reviewed By:** Dana Whitlock (Project Manager)
* **Approved By:** Chris Boseman (CISO)
* **QA Sign-off:** Taylor Nguyen (QA / Engineering Manager)
