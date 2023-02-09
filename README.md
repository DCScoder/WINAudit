# WINAudit
Windows security configuration audit.

#### Description:

The purpose of this script is to check Windows security configurations and provide recommendations based on best-practice for hardening and increasing visibility on either a Windows Server or Workstation. Once dropped onto the target system, the script will utilise a series of internal commands to query information from the host and retrieve data, which it stores in a temporary folder. Finally, the collection is archived into a ZIP file and the temporary store is deleted. The ZIP file can then be retrieved by the analyst for subsequent analysis offline. The script should be used during posture enhancement assessments or alternatively post-breach to review security configurations of compromised hosts. A log of the terminal activities is also created and retained in the archive collection.

The following categories for each item audited are provided in a report:
- Check - What configuration was checked.
- Finding - What misconfiguration was identified posing a security risk or limiting visibility.
- Information - What sufficient configuration was identified (if no finding).
- Background - Circumstances surrounding the risk or visibility finding.
- Caveat - Consider certain conditions before identifying as a finding.

#### Usage:

Step 1: Copy script to target host.

Step 2: Execute script with Administrator privileges:

```
.\WINAudit.ps1
```

If issues are encountered relating to PowerShell policies, instead of using 'Set-ExecutionPolicy' to change the policy, utilise a batch script to bypass and execute:

```
powershell.exe -ExecutionPolicy Bypass -File C:\<path_to_script>\WINAudit.ps1
```

Step 3: Download resultant (*.zip) archive file via your preferred method.

Step 4: Delete script and archive file from host:

```
Remove-Item -Path C:\<path_to_script>\WINAudit.ps1
```
```
Remove-Item -Path C:\<path_to_archive>\WINAudit_<hostname>_<date>_<time>.zip
```

#### Requirements:

- Script must be run with local Administrator privileges.
- Ensure local PowerShell policies permit execution.
- PowerShell and WMI are leveraged.
