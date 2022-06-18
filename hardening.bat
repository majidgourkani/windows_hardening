@echo off

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220932
::Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" /v "RestrictNullSessAccess" /t REG_DWORD /d 1

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220930
::Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" /v "RestrictAnonymous" /t REG_DWORD /d 1

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220937
::Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" /v "NoLMHash" /t REG_DWORD /d 1

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220938
::Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM".
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" /v "LmCompatibilityLevel" /t REG_DWORD /d 5

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220823
::Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote Assistance >> "Configure Solicited Remote Assistance" to "Disabled".
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" /v "fAllowToGetHelp" /t REG_DWORD /d 0

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220828
::Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" /v "NoAutorun" /t REG_DWORD /d 1

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220727
::Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Enable Structured Exception Handling Overwrite Protection (SEHOP)" to "Enabled".
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" /v "DisableExceptionChainValidation" /t REG_DWORD /d 0x00000000

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220857
::Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Always install with elevated privileges" to "Disabled".
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\" /v "AlwaysInstallElevated" /t REG_DWORD /d 0

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220862
::Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow Basic authentication" to "Disabled".
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" /v "AllowBasic" /t REG_DWORD /d 0

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220865
::Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Allow Basic authentication" to "Disabled".
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" /v "AllowBasic" /t REG_DWORD /d 0

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220812
::Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >> "Turn On Virtualization Based Security" to "Enabled" with "Enabled with UEFI lock" selected for "Credential Guard Configuration:".
::v1507 LTSB does not include selection options; select "Enable Credential Guard".
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\" /v "LsaCfgFlags" /t REG_DWORD /d 0x00000001

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220827
::Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Disallow Autoplay for non-volume devices" to "Enabled".
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer\" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220929
::Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled".
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1

::https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220829
::Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Turn off AutoPlay" to "Enabled:All Drives".
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 0x000000ff

::https://www.stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75147
::Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender Antivirus >> "Configure Detection for Potentially Unwanted Applications" to "Enabled" and "Block". 
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d 1

::https://www.stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75241
::Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Signature Updates -> "Define the number of days before spyware definitions are considered out of date" to "Enabled" and select "7" or less in the drop down box.
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ASSignatureDue" /t REG_DWORD /d 7

::https://www.stigviewer.com/stig/ms_windows_defender_antivirus/2020-05-12/finding/V-75243
::Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Signature Updates -> "Define the number of days before virus definitions are considered out of date" to "Enabled" and select "7" or less in the drop down box.
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "AVSignatureDue" /t REG_DWORD /d 7