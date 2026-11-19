# Enterprise SOC & Active Directory Detection Lab

## Project Overview

An enterprise-style cybersecurity home lab built using Microsoft Azure, Microsoft Defender for Endpoint, Sysmon, and Microsoft Defender Advanced Hunting.

The project focuses on developing practical SOC analyst skills through endpoint monitoring, threat detection, investigation, and incident response.

## Lab Environment

- Microsoft Azure Cyber Range
- Windows 11 endpoint: SOC-WIN11-01
- Microsoft Defender for Endpoint
- Microsoft Defender Advanced Hunting
- Sysmon v15.22
- Kusto Query Language (KQL)

## Completed Investigations

### IR-001: Encoded PowerShell Execution

Conducted a controlled PowerShell execution simulation and investigated the resulting endpoint telemetry.

**Skills demonstrated:**
- Endpoint telemetry analysis
- KQL threat hunting
- PowerShell command-line investigation
- Base64 payload decoding
- MITRE ATT&CK mapping
- SOC investigation documentation

[Read the full investigation report](investigations/IR-001-Encoded-PowerShell.md)

## Project Roadmap

- [x] Deploy Windows 11 Azure VM
- [x] Configure Windows security auditing
- [x] Install and configure Sysmon
- [x] Onboard endpoint to Microsoft Defender for Endpoint
- [x] Validate endpoint telemetry collection
- [x] Investigate encoded PowerShell execution
- [x] Build Active Directory lab environment
- [x] Configure domain authentication logging
- [x] Develop additional KQL detections
- [x] Investigate simulated authentication attacks
- [x] Create SOC investigation dashboards

## Disclaimer

All testing was performed in an authorized cybersecurity training environment using controlled simulations. No production systems were targeted.
