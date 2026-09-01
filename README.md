# Suspicious PowerShell Activity Analysis

## Overview

This project demonstrates a SOC L1 investigation of suspicious PowerShell activity on a Windows endpoint using Wazuh, Windows Event Viewer, PowerShell Script Block Logging, and Sysmon.

The investigation focuses on identifying and correlating PowerShell execution, Script Block Logging events, system discovery activity, and file deletion behavior.

---

## Lab Environment

| Component | Details |
|---|---|
| SIEM / Security Platform | Wazuh |
| Windows Endpoint | DESKTOP-2DDE5BC |
| Wazuh Agent | 002 |
| Operating System | Windows |
| Log Sources | PowerShell Operational, Sysmon |
| PowerShell Event ID | 4104 |
| Investigation Type | SOC L1 Alert Investigation |

---

## Investigation Objective

The objective of this investigation was to determine whether PowerShell activity observed on the Windows endpoint was suspicious and whether Wazuh successfully detected and correlated the activity.

The investigation included:

- PowerShell Script Block Logging
- Windows Event ID 4104 analysis
- Sysmon process creation
- Wazuh alert correlation
- MITRE ATT&CK mapping
- File deletion detection
- Timeline analysis

---

## Evidence 1 — Wazuh PowerShell Alert

Wazuh generated an alert for PowerShell activity related to system environment information.

**Alert:** PowerShell script querying system environment variables

**Rule ID:** 91816

**MITRE ATT&CK Technique:** T1082 — System Information Discovery

This indicates that PowerShell activity was detected while querying information from the Windows environment.

### Screenshot

![Wazuh PowerShell Alert](screenshots/Evidence_01_Wazuh_PowerShell_Alert_91816.png)

---

## Evidence 2 — PowerShell Event ID 4104

Windows Event Viewer confirmed multiple PowerShell Script Block Logging events with **Event ID 4104**.

One observed PowerShell script was:

```powershell
secedit /export /cfg $env:TEMP\secpol.cfg;
Get-Content $env:TEMP\secpol.cfg |
Select-String LockoutDuration;
Remove-Item $env:TEMP\secpol.cfg

Other observed security-policy queries included:
ResetLockoutCount
LockoutBadCount
LockoutDuration
MinimumPasswordLength
MinimumPasswordAge

Event ID 4104 provides visibility into the actual PowerShell script content that was executed.

Screenshot

Evidence 3 — PowerShell Script Block Event

The Windows Event Viewer also showed PowerShell Script Block Logging events containing commands executed on the endpoint.

The events were recorded under:
Microsoft-Windows-PowerShell/Operational
with:
Event ID: 4104
This confirms that PowerShell Script Block Logging was enabled and successfully capturing script content.
Screenshot
Evidence 4 — Sysmon Process Creation

Sysmon provided additional process-level visibility into PowerShell execution.

The Event Viewer evidence showed the PowerShell process:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Sysmon process creation telemetry can be used to correlate PowerShell execution with:

Process ID
Parent process
User
Command line
Execution time

This additional context is useful during SOC investigations.

Screenshot

Evidence 5 — PowerShell File Deletion

Wazuh generated an alert related to PowerShell being used to delete files or directories.

Rule ID: 92021

Description: Powershell was used to delete files or directories

The detected activity included:

Remove-Item

The observed script removed the temporary security-policy configuration file after reading it.

This behavior is not automatically malicious, but file deletion through PowerShell can be relevant during a security investigation because attackers may use deletion to remove temporary artifacts.

Screenshot

MITRE ATT&CK Mapping
T1059.001 — PowerShell

PowerShell was used to execute commands and scripts on the Windows endpoint.

Tactic: Execution

T1082 — System Information Discovery

Wazuh identified PowerShell activity associated with querying system/environment information.

Tactic: Discovery

Wazuh Rule: 91816

T1070.004 — File Deletion

PowerShell activity included the use of Remove-Item to delete a temporary file.

Tactic: Defense Evasion

Wazuh Rule: 92021

Investigation Timeline

The investigation followed this sequence:

PowerShell process execution was observed through Sysmon.
PowerShell Script Block Logging generated Event ID 4104.
The captured scripts queried Windows security-policy information.
Wazuh processed the Windows PowerShell events.
Wazuh generated alerts related to PowerShell/system discovery activity.
File deletion behavior involving Remove-Item was also detected.
Events were correlated using Wazuh, Windows Event Viewer, and Sysmon.
Analyst Assessment

The observed PowerShell activity was considered suspicious enough to investigate because PowerShell provides extensive capabilities for system discovery and command execution.

However, the presence of PowerShell or Event ID 4104 alone does not prove malicious activity.

The observed secedit commands query local security-policy settings and may also occur during legitimate administrative or security-assessment activity.

Therefore, additional context should be reviewed before classifying the activity as confirmed malicious.

Important investigation points include:

User identity
Parent process
Process command line
Execution time
Network connections
File activity
Other alerts from the same endpoint
Persistence mechanisms

Based on the available evidence, the activity should be classified as suspicious and requiring further investigation, rather than confirmed malicious.

Detection & Response Recommendations
Detection
Enable PowerShell Script Block Logging.
Monitor PowerShell Event ID 4104.
Monitor Sysmon process creation events.
Correlate PowerShell activity with user and parent-process information.
Monitor suspicious use of Remove-Item.
Create Wazuh rules for encoded or obfuscated PowerShell.
Monitor unusual PowerShell execution from Office applications, browsers, scheduled tasks, and other unexpected parent processes.
Response

If the activity is confirmed malicious:

Identify the affected user and endpoint.
Review the complete PowerShell command line.
Investigate the parent process.
Search for persistence mechanisms.
Review related network connections.
Search for additional activity from the same user or host.
Isolate the endpoint if active compromise is suspected.
Preserve relevant logs and evidence for further investigation.
Key Findings
Finding	Evidence
PowerShell execution	Sysmon Process Creation
Script Block Logging	PowerShell Event ID 4104
System Information Discovery	Wazuh Rule 91816
File Deletion Activity	Wazuh Rule 92021
PowerShell	MITRE T1059.001
System Information Discovery	MITRE T1082
File Deletion	MITRE T1070.004
Screenshots
Wazuh PowerShell Alert

PowerShell Event ID 4104

PowerShell Script Block Event

Sysmon Process Creation

PowerShell File Deletion — MITRE ATT&CK

Conclusion

This lab demonstrates how a SOC analyst can investigate suspicious PowerShell activity by correlating multiple telemetry sources.

Windows PowerShell Event ID 4104 provided visibility into the actual script content, while Sysmon provided process-level information. Wazuh correlated these events and generated security alerts that could be mapped to MITRE ATT&CK techniques.

The investigation demonstrates the importance of combining SIEM alerts, endpoint telemetry, Windows Event Logs, and MITRE ATT&CK context rather than relying on a single alert to determine whether activity is malicious.

The final assessment is that the observed activity is suspicious and requires additional contextual investigation, but the available evidence alone is insufficient to confirm malicious activity.



