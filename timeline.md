# Investigation Timeline

## Lab 95 — DCOM Remote Execution Investigation

**Host:** `DESKTOP-9MMM37V`  
**Workspace:** `C:\DCOMRemoteExecutionLab\Evidence`

---

## Timeline

| Date / Time | Source | Activity | Assessment |
|---|---|---|---|
| 28-09-2026 07:39:52 | Windows OS | Last boot time reported for the endpoint | Baseline information |
| 28-09-2026 07:21:13–07:21:30 | Windows Security | Event ID `4624` successful logon events | Predates the DCOM test by several days; not correlated |
| 03-10-2026 07:49:02 | Windows System / DistributedCOM | Event ID `10010` — DCOM server failed to register within the required timeout | Separate DCOM error; occurred before controlled test |
| 03-10-2026 08:08:47.187 +05:30 | PowerShell | Controlled COM test timestamp recorded | Primary correlation anchor |
| 03-10-2026 ~08:08:49 | Sysmon | Event ID `1` — Process Create | Occurred shortly after test; process details require further inspection |
| 03-10-2026 ~08:08:50 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:08:54 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:08:55 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:00 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:01 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:05 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:06 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:09 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:10 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:11 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:13 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:16 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:21 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:26 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:27 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:31 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |
| 03-10-2026 ~08:09:32 | Sysmon | Event ID `1` — Process Create | Requires process-field correlation |

---

## Baseline Findings

### DCOM Configuration

The endpoint reported:

```text
EnableDCOM = Y
```

This confirms that DCOM was enabled.

---

### RPC/DCOM Services

The following services were running:

```text
RpcSs
DcomLaunch
RpcEptMapper
```

These services represent normal Windows RPC/DCOM infrastructure.

---

### DCOM-Related Processes

The baseline contained:

```text
dllhost.exe
svchost.exe
explorer.exe
```

These processes were not considered suspicious solely because they were present.

---

### Network Listeners

The endpoint had:

```text
TCP/135  Listening
TCP/445  Listening
```

TCP/135 was owned by `svchost.exe`.

The presence of these listeners establishes available Windows networking infrastructure, not remote execution.

---

## Controlled COM Activity

The controlled test created a local COM object:

```powershell
$ComObject = New-Object -ComObject Shell.Application
$ComObject.GetType().FullName
```

The object returned:

```text
System.__ComObject
```

The object was subsequently released.

This demonstrated local COM activity.

It did not demonstrate remote DCOM execution.

---

## Controlled Test Anchor

The recorded timestamp was:

```text
2026-10-03 08:08:47.187 +05:30
```

This timestamp was used to compare surrounding Sysmon and Windows event activity.

---

## Sysmon Correlation

Sysmon Event ID `1` process creation events were observed shortly after the controlled test.

The first observed events began around:

```text
08:08:49
```

and continued through approximately:

```text
08:09:32
```

The extracted output did not expose complete process information.

Therefore:

```text
Process activity shortly after test = Confirmed
Direct relationship to COM test     = Not established
```

Additional analysis would require the complete Sysmon fields.

---

## DistributedCOM Event 10010

The DistributedCOM Event ID `10010` occurred at:

```text
03-10-2026 07:49:02
```

The controlled test occurred at:

```text
03-10-2026 08:08:47.187 +05:30
```

The DCOM error therefore occurred before the controlled test.

It was not included in the controlled execution chain.

---

## Authentication Timeline

The available Event ID `4624` records were from:

```text
28-09-2026 07:21:13
```

through:

```text
28-09-2026 07:21:30
```

These events occurred several days before the controlled DCOM test.

They were therefore not used as authentication evidence for the test.

---

## Wazuh Timeline Evidence

Wazuh reported a registry integrity event involving a registry value associated with:

```text
svchost.exe
```

The event reported changes to:

```text
MD5
SHA1
SHA256
```

The available evidence did not establish a temporal or causal relationship between this FIM event and the controlled COM activity.

It was therefore treated as separate telemetry.

---

## Evidence-Supported Chain

The evidence-supported sequence is:

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

The following sequence was not established:

```text
Remote Source
     |
     v
Remote Authentication
     |
     v
RPC/DCOM Remote Connection
     |
     v
Remote Process Creation
```

---

## Final Timeline Assessment

The timeline confirms that the Windows endpoint had active DCOM/RPC infrastructure and that controlled local COM activity was successfully generated.

Sysmon process creation events appeared shortly afterward, but the available extracted process information was insufficient to establish a DCOM execution chain.

The DistributedCOM Event ID `10010` occurred before the controlled test and was therefore treated as a separate event.

The Wazuh FIM registry integrity event involving `svchost.exe` was also kept separate because a relationship to the DCOM activity was not established.

### Final Assessment

> **DCOM functionality was confirmed, but DCOM remote execution was not confirmed by the collected evidence.**

The investigation follows the principle:

> **Follow the evidence, not the assumption.**
