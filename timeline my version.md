# Investigation Timeline

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

