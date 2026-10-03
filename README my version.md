# dcom-remote-execution-investigation
## Overview
DCOM allows Windows applications and COM objects to communicate across systems. Administrators and Windows components can legitimately use DCOM for remote management and application functionality.

From a SOC/DFIR perspective, DCOM becomes interesting when it appears alongside:

Remote authentication
RPC/DCOM network communication
mmc.exe, svchost.exe, dllhost.exe, or other COM-related processes
Unusual parent-child process relationships
Remote source addresses
Administrative accounts
Subsequent process execution
Other lateral-movement indicators

A DCOM-related process by itself is not proof of remote execution.

The investigation therefore focuses on reconstructing the activity:

Remote Source
     ↓
Authentication
     ↓
DCOM / RPC Activity
     ↓
Process Creation
     ↓
Parent → Child Relationship
     ↓
Network / File Activity
     ↓
Follow-on Behavior

This lab investigates Windows Distributed Component Object Model (DCOM) activity from a DFIR and SOC perspective. DCOM is a legitimate Windows technology that allows COM components to communicate across processes and systems, with RPC providing the underlying communication infrastructure.

DCOM can be relevant during investigations involving remote administration, lateral movement, and remote execution. However, the presence of DCOM, RPC services, `dllhost.exe`, `svchost.exe`, or TCP port `135` does not by itself establish malicious activity.

The investigation therefore focuses on establishing a system baseline, reviewing DCOM and RPC configuration, examining relevant processes and network listeners, generating controlled local COM activity, and correlating available Windows, Sysmon, and Wazuh telemetry.

The investigation follows the principle:

> **Follow the evidence, not the assumption.**

---

## Environment

| Item | Value |
|---|---|
| Host | `DESKTOP-9MMM37V` |
| Manufacturer | Dell Inc. |
| Model | Latitude 5420 |
| Operating System | Windows 11 Pro |
| Version | `10.0.26200` |
| Build | `26200` |
| Domain | `WORKGROUP` |
| Domain Role | `0` |
| User | `desktop-9mmm37v\dell` |
| Username | `Dell` |
| Wi-Fi IP | `192.168.1.6` |
| VMware VMnet8 | `192.168.203.1` |
| VMware VMnet1 | `192.168.174.1` |
| Lab Workspace | `C:\DCOMRemoteExecutionLab\Evidence` |

---

## Lab Objectives

The objectives of this lab are to investigate Windows DCOM activity from a DFIR perspective and determine whether the available telemetry supports evidence of remote execution.

- Establish the Windows endpoint, operating system, user, and network baseline before investigation.
- Verify the current DCOM configuration and determine whether DCOM is enabled.
- Examine the status of core RPC and DCOM-related Windows services.
- Identify processes commonly associated with COM/DCOM functionality, including `dllhost.exe` and `svchost.exe`.
- Identify RPC-related network listeners, particularly TCP port `135`, and document their owning processes.
- Establish a baseline for RPC network connections before controlled activity.
- Generate controlled COM activity on the Windows endpoint without intentionally creating malicious behavior.
- Record an exact timestamp for the controlled activity to support event correlation.
- Review Sysmon Event ID `1` for process creation activity around the test window.
- Review Windows System events for DistributedCOM-related activity, including Event ID `10010`.
- Review Windows Security authentication events and determine whether they can be temporally associated with the investigation.
- Examine available Wazuh telemetry for endpoint-related changes or supporting evidence.
- Correlate timestamps, processes, users, network activity, and event details across the available telemetry sources.
- Distinguish normal Windows DCOM/RPC infrastructure from evidence that could indicate remote execution or lateral movement.
- Identify unrelated or weakly correlated events instead of forcing them into the same activity chain.
- Document telemetry gaps where the available data cannot establish remote source, authentication, DCOM communication, or process execution.
- Classify findings as confirmed, plausible, or unknown based on the evidence collected.
- Produce a final evidence-based assessment of whether DCOM remote execution was established during the investigation.

---

## Lab Scenario

A Windows endpoint is being investigated for possible **DCOM-based remote execution**. DCOM is a legitimate Windows technology used for communication between COM objects and can rely on RPC infrastructure, including TCP port `135`. Because the same components can also be involved in lateral-movement and remote-execution techniques, the presence of DCOM, `dllhost.exe`, RPC listeners, or related events cannot by itself be treated as evidence of malicious activity.

The investigation begins by establishing the normal state of the endpoint and its DCOM/RPC infrastructure. The analyst will then perform controlled COM activity and use the recorded execution timestamp as an anchor for reviewing available telemetry.

### Investigation Focus

The investigation will examine:

- Whether DCOM is enabled and whether the supporting RPC/DCOM services are running.
- Which processes and network listeners are associated with normal DCOM/RPC functionality.
- Whether controlled COM activity generates observable process or system events.
- Whether DistributedCOM events occur during or around the controlled activity.
- Whether Windows authentication events provide any useful correlation.
- Whether Wazuh or Sysmon provides endpoint telemetry supporting the activity.
- Whether the available evidence can establish a **remote source**, authentication event, RPC/DCOM communication, and subsequent process execution.

### Investigation Approach

The analyst will compare the baseline state with events observed around the controlled test window. Each event will be evaluated using its timestamp, process context, user context, network information, and available event details rather than assuming that every DCOM-related artifact belongs to the test.

Particular attention will be given to the distinction between **local COM activity and genuine remote DCOM execution**. The lab should therefore determine not only whether COM/DCOM components are active, but whether the collected evidence is sufficient to demonstrate remote execution.

The investigation must also account for telemetry limitations. Missing Security events, truncated Sysmon output, unrelated Wazuh integrity alerts, or events occurring outside the controlled test window should be documented rather than treated as proof of either malicious or benign activity.

### Expected Outcome

The final assessment should determine whether the available evidence supports:

1. Normal DCOM/RPC infrastructure only.
2. Controlled local COM activity.
3. Evidence consistent with remote DCOM execution.
4. Or insufficient telemetry to establish remote execution.

The investigation follows the principle:

> **Follow the evidence, not the assumption.**

---

## DCOM Background

DCOM extends the Component Object Model (COM) so that components can communicate across system boundaries. Windows uses DCOM and RPC for various legitimate application and administrative functions.

Relevant Windows components include:

- `RpcSs` — Remote Procedure Call (RPC)
- `DcomLaunch` — DCOM Server Process Launcher
- `RpcEptMapper` — RPC Endpoint Mapper
- TCP `135` — RPC Endpoint Mapper
- `dllhost.exe` — COM Surrogate
- `svchost.exe` — Windows service host

These components are common on Windows systems and must be interpreted in context.

A useful investigation model is:

```text
Remote Source
     |
     v
Authentication
     |
     v
RPC/DCOM Communication
     |
     v
Process Creation
     |
     v
Parent/Child Relationship
     |
     v
Command Line
     |
     v
Follow-on Activity
```

A DCOM-related process, service, or network listener alone is insufficient to establish remote execution.

---

## Lab Workspace

The investigation workspace was created at:

```text
C:\DCOMRemoteExecutionLab\Evidence
```

The directory was successfully created and verified before evidence collection.

---

## Host and User Baseline

The endpoint was identified as:

```text
DESKTOP-9MMM37V
Dell Latitude 5420
Windows 11 Pro 10.0.26200
WORKGROUP
```

The active user context was:

```text
desktop-9mmm37v\dell
```

The primary Wi-Fi address was:

```text
192.168.1.6
```

VMware virtual network interfaces were also present:

```text
VMnet8 : 192.168.203.1
VMnet1 : 192.168.174.1
```

Additional link-local interfaces were present but were not treated as primary network context.

---

## DCOM Configuration

The DCOM registry configuration was checked using:

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Ole" |
Select-Object EnableDCOM
```

Observed result:

```text
EnableDCOM
----------
Y
```

This confirms that DCOM was enabled on the endpoint.

This is a configuration finding and does not indicate that remote DCOM execution occurred.

---

## RPC and DCOM Services

The following services were checked:

```powershell
Get-Service RpcSs
Get-Service DcomLaunch
Get-Service RpcEptMapper
```

All three services were observed in the `Running` state.

These services provide normal Windows RPC/DCOM functionality and were therefore treated as baseline infrastructure.

---

## DCOM-Related Processes

The process review identified instances of:

- `dllhost.exe`
- `svchost.exe`
- `explorer.exe`

Observed executable paths included:

```text
C:\WINDOWS\system32\DllHost.exe
C:\WINDOWS\SysWOW64\DllHost.exe
C:\WINDOWS\system32\svchost.exe
C:\WINDOWS\Explorer.EXE
```

The presence of these processes was not treated as evidence of malicious DCOM execution.

Additional process context would be required, including:

- Image
- Command line
- Parent image
- Parent command line
- User
- Process ID
- Timestamp

---

## RPC Network Baseline

TCP port `135` was observed listening:

```text
LocalAddress  LocalPort  State   OwningProcess
::            135        Listen  1496
0.0.0.0       135        Listen  1496
```

The owning process was:

```text
svchost.exe
```

TCP port `445` was also observed listening:

```text
LocalAddress  LocalPort  State   OwningProcess
::            445        Listen  4
```

Port `135` is associated with the RPC Endpoint Mapper and is relevant to DCOM investigations.

However:

> TCP/135 listening does not prove that DCOM remote execution occurred.

---

## Controlled COM Activity

A benign local COM object was instantiated using:

```powershell
$ComObject = New-Object -ComObject Shell.Application
$ComObject.GetType().FullName
```

The resulting object type was:

```text
System.__ComObject
```

The object was subsequently released.

This demonstrated successful local COM object creation.

Importantly, this was a local COM test rather than a remote DCOM execution test.

Therefore, the test does not establish:

- Remote DCOM communication
- Remote authentication
- Remote process execution
- Lateral movement

---

## Controlled Test Timestamp

The controlled test timestamp was recorded as:

```text
2026-10-03 08:08:47.187 +05:30
```

This timestamp was used as the primary correlation point for subsequent telemetry.

---

## Sysmon Process Telemetry

Sysmon Event ID `1` was reviewed around the controlled test.

Process creation events were observed beginning shortly after the recorded timestamp, including activity between approximately:

```text
08:08:49
```

and:

```text
08:09:32
```

The extracted output showed the generic message:

```text
Process Create:...
```

but did not provide sufficient process-level detail to establish which process events were directly related to the COM test.

Important fields for further investigation include:

```text
Image
CommandLine
ParentImage
ParentCommandLine
User
ProcessId
```

The observed Sysmon activity was therefore treated as supporting telemetry rather than proof of DCOM remote execution.

---

## DistributedCOM Event

A DistributedCOM Event ID `10010` was identified:

```text
TimeCreated     : 03-10-2026 07:49:02
Id              : 10010
Provider        : Microsoft-Windows-DistributedCOM
Level           : Error
```

The event indicated that a DCOM server did not register within the required timeout.

The important correlation point is the timestamp.

The DCOM event occurred at:

```text
03-10-2026 07:49:02
```

The controlled test occurred at:

```text
03-10-2026 08:08:47.187 +05:30
```

The Event ID `10010` therefore occurred before the controlled test and was not attributed to the test.

A DistributedCOM timeout can represent application, service, or configuration behavior and should not automatically be interpreted as malicious activity.

---

## Wazuh FIM Telemetry

A Wazuh File Integrity Monitoring event was observed involving a registry value associated with:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\bam\State\UserSettings\
S-1-5-21-51198790-337801975-3228388354-1001\
Device\HarddiskVolume3\Windows\System32\svchost.exe
```

The event reported changes to:

- MD5
- SHA1
- SHA256

The decoder was:

```text
syscheck_registry_value_modified
```

The rule description was:

```text
Registry Value Integrity Checksum Changed
```

This event was not automatically attributed to the DCOM investigation.

A timestamp and process correlation would be required before connecting the registry integrity event to DCOM activity.

---

## Authentication Telemetry

Windows Security Event ID `4624` was reviewed.

The available events were dated:

```text
28-09-2026 07:21:13
```

through:

```text
28-09-2026 07:21:30
```

These events predated the October 3 controlled DCOM test by several days.

They were therefore not used as evidence of authentication associated with the controlled test.

For future DCOM investigations, relevant authentication fields include:

- Target username
- Logon type
- Source network address
- Authentication package
- Timestamp

---

## Evidence Assessment

| Evidence | Observation | Assessment |
|---|---|---|
| DCOM configuration | `EnableDCOM = Y` | Normal configuration |
| RPC service | Running | Normal Windows infrastructure |
| DCOM launcher | Running | Normal Windows infrastructure |
| RPC Endpoint Mapper | Running | Normal Windows infrastructure |
| `dllhost.exe` | Multiple instances present | Not inherently suspicious |
| TCP/135 | Listening | Expected RPC infrastructure |
| TCP/445 | Listening | Expected SMB infrastructure |
| Local COM object | `System.__ComObject` created | Controlled local COM activity |
| Controlled test | `2026-10-03 08:08:47.187 +05:30` | Correlation anchor |
| Sysmon EID 1 | Process events after test | Requires field-level correlation |
| DistributedCOM EID 10010 | `03-10-2026 07:49:02` | Occurred before test |
| Wazuh FIM | Registry checksum change involving `svchost.exe` | Separate telemetry |
| Remote source | Not established | Unknown |
| Remote authentication | Not established for the test | Unknown |
| Remote DCOM execution | Not established | No confirmed evidence |

---

## Investigation Limitations

The investigation had several limitations:

- The controlled test generated local COM activity rather than genuine remote DCOM activity.
- The extracted Sysmon Event ID `1` output did not expose complete process details.
- A remote DCOM source was not established.
- Authentication telemetry associated with remote DCOM activity was not established.
- The DistributedCOM Event ID `10010` occurred before the controlled test.
- The Wazuh FIM event was not sufficiently correlated with the controlled test.
- A two-endpoint remote DCOM scenario was not performed.

These limitations are documented rather than treated as evidence that the activity did not occur.

---

## Final Assessment

The investigation confirmed that DCOM was enabled and that the Windows RPC/DCOM infrastructure was active. A controlled local COM object was successfully created, and Sysmon recorded process creation activity shortly afterward.

However, the available evidence does not establish a remote DCOM connection, remote authentication, or remote process execution.

The DistributedCOM Event ID `10010` occurred before the controlled test and was therefore treated as a separate event. The Wazuh registry integrity event involving `svchost.exe` was also treated separately because a relationship to the controlled COM activity was not established.

> **Final Assessment: DCOM functionality was confirmed, but DCOM remote execution was not established from the collected evidence.**

---

