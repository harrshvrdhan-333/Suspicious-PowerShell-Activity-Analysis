# Suspicious PowerShell Activity Analysis

## Overview

This project demonstrates a SOC L1 investigation of PowerShell activity on a Windows endpoint using Wazuh, Windows Event Viewer, PowerShell Script Block Logging, and Sysmon.

The investigation focuses on identifying and correlating suspicious PowerShell execution, Script Block Logging events, system discovery activity, and file deletion behavior.

---

## Lab Environment

| Component | Details |
|---|---|
| SIEM / EDR | Wazuh |
| Windows Endpoint | DESKTOP-2DDE5BC |
| Wazuh Agent | 002 |
| Operating System | Windows |
| Log Sources | PowerShell Operational, Sysmon |
| PowerShell Event ID | 4104 |
| Investigation Type | SOC L1 Alert Investigation |

---

## Investigation Objective

The objective was to determine whether PowerShell activity observed on the Windows endpoint was suspicious and whether Wazuh successfully detected and correlated the activity.

The investigation included:

- PowerShell Script Block Logging
- Event ID 4104 analysis
- Sysmon process creation
- Wazuh alert correlation
- MITRE ATT&CK mapping
- File deletion detection
- Timeline analysis

---

## Evidence 1 — Wazuh Alert

Wazuh generated an alert for PowerShell activity:

**Alert:** PowerShell script querying system environment variables

**Rule ID:** 91816

**MITRE ATT&CK:**
- T1082 — System Information Discovery

This indicates that PowerShell was being used to query information from the Windows environment.

---

## Evidence 2 — PowerShell Script Block Logging

Windows Event Viewer confirmed multiple **PowerShell Event ID 4104** events.

Example observed command:

```powershell
secedit /export /cfg $env:TEMP\secpol.cfg;
Get-Content $env:TEMP\secpol.cfg |
Select-String LockoutDuration;
Remove-Item $env:TEMP\secpol.cfg

Other observed queries included:

ResetLockoutCount
LockoutBadCount
LockoutDuration
MinimumPasswordLength
MinimumPasswordAge

Event ID 4104 confirms that PowerShell Script Block Logging captured the executed script content.

Evidence 3 — Sysmon Process Creation

Sysmon was also enabled on the Windows endpoint.

The Event Viewer evidence shows PowerShell process creation with:

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

This provides additional process-level visibility and allows PowerShell execution to be correlated with other security events.

Evidence 4 — Wazuh File Deletion Detection

Wazuh generated a separate alert:

Rule ID: 92021

Description:

Powershell was used to delete files or directories

The rule is associated with:

Sysmon
Windows
File Deletion
Defense Evasion

The observed PowerShell activity included:

Remove-Item

which can be used to remove temporary files created during command execution.

MITRE ATT&CK Mapping
T1059.001 — PowerShell

PowerShell was used to execute commands and scripts on the Windows endpoint.

Tactic: Execution

T1082 — System Information Discovery

Wazuh identified PowerShell activity associated with querying system/environment information.

Tactic: Discovery

Wazuh Rule: 91816

T1070.004 — File Deletion

The investigation also identified PowerShell activity involving file deletion through Remove-Item.

Tactic: Defense Evasion

Wazuh Rule: 92021

Investigation Timeline
PowerShell process execution was observed through Sysmon.
PowerShell Script Block Logging generated Event ID 4104 events.
The captured scripts queried Windows security-policy information.
Wazuh processed the Windows PowerShell events.
Wazuh generated alerts related to PowerShell/system discovery activity.
File deletion behavior involving Remove-Item was also detected.
Events were correlated using Wazuh and Windows Event Viewer.
Analyst Assessment

The observed activity is suspicious enough to investigate because PowerShell provides extensive capabilities for system discovery and command execution.

However, the presence of PowerShell or Event ID 4104 alone does not prove malicious activity.

The observed secedit commands query local security-policy settings and may also occur during legitimate administrative or security-assessment activity.

Therefore, additional context such as:

User identity
Parent process
Process command line
Execution time
Network connections
File activity
Other alerts from the same endpoint

should be reviewed before classifying the activity as confirmed malicious.

Detection & Response Recommendations
Detection
Enable PowerShell Script Block Logging.
Monitor PowerShell Event ID 4104.
Monitor Sysmon process creation events.
Correlate PowerShell activity with user and parent-process information.
Monitor suspicious use of Remove-Item.
Create Wazuh rules for encoded or obfuscated PowerShell.
Response

If the activity is confirmed malicious:

Identify the affected user and endpoint.
Review the complete PowerShell command line.
Investigate the parent process.
Check for persistence mechanisms.
Review related network connections.
Search for additional activity from the same user/host.
Isolate the endpoint if active compromise is suspected.
Preserve relevant logs for further investigation.
Key Findings
Finding	Evidence
PowerShell execution	Sysmon Process Creation
Script Block Logging	PowerShell Event ID 4104
System information discovery	Wazuh Rule 91816
File deletion activity	Wazuh Rule 92021
MITRE PowerShell	T1059.001
MITRE System Information Discovery	T1082
MITRE File Deletion	T1070.004
Screenshots
Wazuh Dashboard

PowerShell Script Block Event

PowerShell Event 4104

Wazuh PowerShell Alert

Sysmon Event

PowerShell File Deletion — MITRE ATT&CK

Conclusion

This lab demonstrates how a SOC analyst can investigate PowerShell activity by correlating multiple telemetry sources.

Windows PowerShell Event ID 4104 provided visibility into the actual script content, while Sysmon provided process-level information. Wazuh correlated these events and generated security alerts that could be mapped to MITRE ATT&CK techniques.

The investigation demonstrates the importance of combining SIEM alerts, endpoint telemetry, Windows Event Logs, and MITRE ATT&CK context rather than relying on a single alert to determine whether activity is malicious.
