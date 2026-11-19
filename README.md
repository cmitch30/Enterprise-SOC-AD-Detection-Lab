
# Enterprise SOC & Active Directory Detection Lab

## Project Overview

An enterprise-style cybersecurity lab using Microsoft Azure, Microsoft Defender for Endpoint, Sysmon, and Microsoft Defender Advanced Hunting.

This project focuses on developing practical SOC analyst skills through endpoint monitoring, threat hunting, authentication analysis, detection engineering, and incident response documentation.

Investigations use controlled, authorized simulations to generate and analyze real Windows endpoint telemetry.

## Lab Environment

- Microsoft Azure Cyber Range
- Windows 11 endpoint: `SOC-WIN11-01`
- Microsoft Defender for Endpoint (MDE)
- Microsoft Defender Advanced Hunting
- Windows Security Event Logs
- Sysmon v15.22
- Kusto Query Language (KQL)

The environment currently supports one virtual machine at a time.

## Completed Investigations

### IR-001: Encoded PowerShell Execution

Executed a harmless Base64-encoded PowerShell command and investigated the resulting process telemetry in Microsoft Defender.

**Skills demonstrated:**
- Endpoint telemetry analysis
- KQL threat hunting
- PowerShell command-line investigation
- Base64 payload decoding
- MITRE ATT&CK mapping
- SOC investigation documentation

[Read IR-001 Investigation](investigations/IR-001-Encoded-PowerShell.md)

### IR-002: Windows Authentication Failure Investigation

Investigated controlled network and interactive authentication failures using Windows Security Event ID 4625 and Microsoft Defender Advanced Hunting.

Developed and validated a rolling five-minute KQL detection to identify repeated failed logons.

**Key result:** Successfully detected three simulated interactive authentication failures occurring within 27 seconds.

**Skills demonstrated:**
- Windows authentication event analysis
- Security Event ID 4625 investigation
- Network vs. interactive logon analysis
- Windows Security and Defender telemetry correlation
- KQL detection engineering
- Positive and negative detection testing
- MITRE ATT&CK T1110 mapping

[Read IR-002 Investigation](investigations/IR-002-Windows-Authentication-Failures.md)

## Detection Engineering

The lab includes hands-on investigation and validation of detection logic using Microsoft Defender Advanced Hunting.

Detection scenarios completed:

| Detection Scenario | Data Source | Status |
|---|---|---|
| Encoded PowerShell execution | DeviceProcessEvents | Validated |
| Failed network authentication | DeviceLogonEvents | Validated |
| Failed interactive authentication | DeviceLogonEvents | Validated |
| Three failed logons within five minutes | DeviceLogonEvents | Positive test validated |


### Reusable Detection Queries

**Repeated Failed Windows Logons**

Developed and validated a KQL detection that identifies three or more failed authentication attempts against the same account within a rolling five-minute window.

- **Data source:** Microsoft Defender `DeviceLogonEvents`
- **MITRE ATT&CK:** T1110 — Brute Force
- **Detection threshold:** 3 failed attempts within 5 minutes
- **Validation:** 3 simulated failures detected within 27 seconds
- **Status:** Validated through Advanced Hunting (not deployed as an automated alert)

[View KQL Detection Query](detections/Repeated-Failed-Logons.kql)

Detection results were obtained through hunting queries. Automated alerting rules have not yet been deployed.

## Project Roadmap

- [x] Deploy Windows 11 Azure VM
- [x] Configure Windows security auditing
- [x] Install and configure Sysmon
- [x] Onboard endpoint to Microsoft Defender for Endpoint
- [x] Validate endpoint telemetry collection
- [x] Investigate encoded PowerShell execution
- [x] Investigate failed Windows authentication
- [x] Correlate Windows Security and Defender telemetry
- [x] Develop rolling-window KQL authentication detection
- [x] Validate positive and negative detection scenarios
- [ ] Publish reusable KQL detection queries
- [ ] Expand authentication detection scenarios
- [ ] Build Active Directory lab environment when resources permit
- [ ] Configure domain authentication logging
- [ ] Create SOC investigation dashboards

## Disclaimer

All activities were performed in an authorized cybersecurity lab environment using controlled simulations.

No real-world systems were targeted, and the documented activity does not represent a confirmed malicious compromise.

## Author

**Clark Mitchell**

B.S. Cybersecurity and Information Assurance — Western Governors University (Expected March 2027)

CompTIA Security+ | CompTIA Network+ | CompTIA A+ | ITIL

[GitHub Profile](https://github.com/cmitch30)