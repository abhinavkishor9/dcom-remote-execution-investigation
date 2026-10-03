# Investigation Notes

## 1. Investigation Scope

The investigation focused on Windows DCOM and the possibility of identifying evidence associated with remote execution.

The analysis covered:

- Host and user baseline
- DCOM configuration
- RPC/DCOM services
- DCOM-related processes
- RPC network listeners
- Controlled COM activity
- Windows Security events
- DistributedCOM events
- Sysmon process telemetry
- Wazuh FIM telemetry

The investigation was performed using a controlled local environment.

---

## 2. Host Baseline

The endpoint was identified as:

```text
Hostname        : DESKTOP-9MMM37V
Manufacturer    : Dell Inc.
Model           : Latitude 5420
Operating System: Microsoft Windows 11 Pro
Version         : 10.0.26200
Build           : 26200
Domain          : WORKGROUP
Domain Role     : 0
```

The last boot time reported by Windows was:

```text
28-09-2026 07:39:52
```

---

## 3. User Context

The active user was:

```text
desktop-9mmm37v\dell
```

Environment variables reported:

```text
USERNAME  : Dell
USERDOMAIN: DESKTOP-9MMM37V
```

The user and group context was saved as part of the investigation baseline.

---

## 4. Network Baseline

The endpoint contained several network interfaces.

Relevant IPv4 addresses included:

```text
Wi-Fi                         192.168.1.6
VMware Network Adapter VMnet8 192.168.203.1
VMware Network Adapter VMnet1 192.168.174.1
```

Additional interfaces had link-local addresses.

The network baseline was recorded before further investigation.

---

## 5. DCOM Configuration

The following registry location was checked:

```text
HKLM:\SOFTWARE\Microsoft\Ole
```

Command:

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

### Assessment

DCOM was enabled on the endpoint.

This is consistent with normal Windows functionality.

No malicious conclusion was drawn from the configuration alone.

---

## 6. RPC and DCOM Services

The following services were checked:

```powershell
Get-Service RpcSs
Get-Service DcomLaunch
Get-Service RpcEptMapper
```

Observed state:

```text
RpcSs         Running
DcomLaunch    Running
RpcEptMapper  Running
```

### Assessment

The core RPC/DCOM services were running.

This establishes that the Windows RPC/DCOM infrastructure was active, but does not establish that remote execution occurred.

---

## 7. DCOM-Related Processes

The process review identified multiple instances of:

```text
dllhost.exe
svchost.exe
explorer.exe
```

Relevant paths included:

```text
C:\WINDOWS\system32\DllHost.exe
C:\WINDOWS\SysWOW64\DllHost.exe
C:\WINDOWS\system32\svchost.exe
C:\WINDOWS\Explorer.EXE
```

### Assessment

These are legitimate Windows processes.

The presence of `dllhost.exe` was not treated as proof of DCOM activity or remote execution.

Further investigation would require process-level context such as:

```text
Image
CommandLine
ParentImage
ParentCommandLine
User
ProcessId
Timestamp
```

---

## 8. RPC and SMB Listening Ports

The endpoint was checked for TCP/135 and TCP/445 listeners.

Observed:

```text
TCP/135  Listen
TCP/445  Listen
```

TCP/135 was owned by process ID `1496`, which mapped to:

```text
svchost.exe
```

### Assessment

TCP/135 is expected RPC infrastructure.

TCP/445 is associated with SMB functionality.

Neither listener independently establishes remote DCOM execution.

---

## 9. RPC Connection Baseline

The pre-test RPC connection check showed TCP/135 listeners.

No established remote TCP/135 connection was demonstrated in the captured baseline.

This baseline provides a comparison point for any later RPC network activity.

---

## 10. Controlled COM Activity

A benign COM object was instantiated:

```powershell
$ComObject = New-Object -ComObject Shell.Application
$ComObject.GetType().FullName
```

The result was:

```text
System.__ComObject
```

The object was then released using:

```powershell
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObject)
```

### Assessment

The test confirmed successful local COM object creation.

It did not demonstrate remote DCOM execution.

The distinction is:

```text
Local COM activity
        !=
Remote DCOM execution
```

---

## 11. Controlled Test Timestamp

The controlled test timestamp was recorded as:

```text
2026-10-03 08:08:47.187 +05:30
```

This timestamp was used as the primary investigation anchor.

---

## 12. Sysmon Process Creation

Sysmon Event ID `1` was reviewed around the controlled test.

Process creation events were observed beginning at approximately:

```text
08:08:49
```

and continuing through approximately:

```text
08:09:32
```

The extracted event output contained generic:

```text
Process Create:...
```

messages.

### Assessment

The timing shows process creation activity shortly after the controlled test.

However, the extracted output did not provide sufficient information to determine:

- Which executable was created
- Parent process
- Command line
- User
- Process ID
- Whether the process was related to COM activity

Therefore:

> Temporal proximity was observed, but causation was not established.

---

## 13. DistributedCOM Event 10010

A DistributedCOM error was observed:

```text
TimeCreated : 03-10-2026 07:49:02
Event ID    : 10010
Provider    : Microsoft-Windows-DistributedCOM
Level       : Error
```

The event reported that a DCOM server did not register within the required timeout.

### Timestamp Analysis

The event occurred at:

```text
03-10-2026 07:49:02
```

The controlled test occurred at:

```text
03-10-2026 08:08:47.187 +05:30
```

The difference places the DCOM error before the controlled test.

### Assessment

The Event ID `10010` event was not attributed to the controlled COM activity.

It should be investigated separately if required.

---

## 14. DistributedCOM Log Enumeration

The following command was also tested:

```powershell
Get-WinEvent -ListLog *DistributedCOM* |
Select-Object LogName, IsEnabled, RecordCount
```

The command returned no separately named event log matching the wildcard.

However, the `Microsoft-Windows-DistributedCOM` provider was visible through the Windows System log.

### Assessment

The absence of a dedicated event log matching the provider name does not mean DistributedCOM telemetry is unavailable.

Provider events can be recorded within another Windows event log, such as `System`.

---

## 15. Windows Authentication Events

Event ID `4624` was reviewed:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4624
} -MaxEvents 100 |
Select-Object TimeCreated, Id, Message
```

The available events were dated around:

```text
28-09-2026 07:21:13
```

through:

```text
28-09-2026 07:21:30
```

### Assessment

These events occurred several days before the October 3 controlled test.

They were therefore not used to establish authentication associated with the controlled DCOM activity.

For future remote DCOM investigations, the following fields should be correlated:

```text
Account
Logon Type
Source Network Address
Authentication Package
Timestamp
```

---

## 16. Wazuh FIM Event

Wazuh reported a registry integrity event involving a registry value associated with:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\bam\State\UserSettings\
S-1-5-21-51198790-337801975-3228388354-1001\
Device\HarddiskVolume3\Windows\System32\svchost.exe
```

The event reported changes to:

```text
MD5
SHA1
SHA256
```

The decoder was:

```text
syscheck_registry_value_modified
```

The rule description was:

```text
Registry Value Integrity Checksum Changed
```

The event had:

```text
rule.firedtimes: 24
```

### Assessment

This confirms Wazuh FIM telemetry.

It does not establish a relationship to DCOM.

The event should remain a separate finding unless its timestamp, process context, and related activity support a correlation.

---

## 17. Evidence Correlation

The expected remote DCOM execution chain would be:

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

The collected evidence established only part of this model:

```text
DCOM Enabled
     |
     v
RPC/DCOM Services Running
     |
     v
TCP/135 Listening
     |
     v
Local COM Object Created
     |
     v
Sysmon Process Creation Observed
```

The following elements were not established:

```text
Remote Source
Remote Authentication
Remote DCOM Connection
Remote Process Execution
Suspicious Follow-on Activity
```

---

## 18. Evidence Classification

### Confirmed

- DCOM was enabled.
- RPC/DCOM services were running.
- TCP/135 was listening.
- TCP/445 was listening.
- `dllhost.exe` and `svchost.exe` were present.
- A local COM object was successfully created.
- The controlled test timestamp was recorded.
- Sysmon Event ID `1` process telemetry was present shortly afterward.
- DistributedCOM Event ID `10010` was present before the test.
- Wazuh FIM recorded a registry integrity change.

### Plausible

- Some process activity occurring shortly after the controlled COM test may represent normal activity associated with the local test or other Windows operations.

The available extracted Sysmon details are insufficient to confirm the relationship.

### Unknown

- Whether a remote DCOM client connected to the endpoint.
- Whether remote authentication occurred as part of DCOM activity.
- Whether any remote process was launched through DCOM.
- Whether the observed Sysmon process events were directly related to the COM test.

---

