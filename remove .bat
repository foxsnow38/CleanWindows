sc delete "AxInstSV"
sc delete "AJRouter"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /v "Start" /t "REG_DWORD" /d "4" /f
sc config "BDESVC" start= "disabled"
sc delete "wbengine"
sc delete "CDPUserSvc"
sc delete "DsSvc"
sc delete "DiagTrack"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t "REG_DWORD" /d "4" /f
sc delete "DcpSvc"
sc config "DPS" start= "disabled"
sc config "WdiServiceHost" start= "disabled"
sc config "WdiSystemHost" start= "disabled"
sc delete "TrkWks"
sc delete "dmwappushservice"
sc delete "MapsBroker"
sc config "EFS" start= "disabled"
sc delete "fhsvc"
sc delete "lfsvc"
sc delete "HomeGroupListener"
sc delete "HomeGroupProvider"
sc delete "MessagingService"
sc delete "wlidsvc"
sc delete "NcbService"
sc delete "CscService"
sc delete "PhoneSvc"
sc delete "wercplsupport"
sc delete "PcaSvc"
sc delete "SessionEnv"
sc delete "TermService"
sc delete "RetailDemo"
sc delete "wscsvc"
sc delete "OneSyncSvc"
sc delete "lmhosts"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t "REG_DWORD" /d "4" /f
sc delete "TabletInputService"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t "REG_DWORD" /d "4" /f
sc delete "UevAgentService"
sc delete "VSS"
sc delete "SDRSVC"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t "REG_DWORD" /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t "REG_DWORD" /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t "REG_DWORD" /d "4" /f
sc delete "wisvc"
sc delete "WerSvc"
sc delete "LicenseManager"
sc delete "WpnService"
sc delete "WinHttpAutoProxySvc"
sc delete "LanmanWorkstation"

sc delete "XblGameSave"
sc delete "XboxNetApiSvc"

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t "REG_DWORD" /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallDay" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallTime" /t "REG_DWORD" /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t "REG_DWORD" /d "1" /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t "REG_SZ" /d "Deny" /f
  
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f
  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f
  
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t "REG_SZ" /d "Deny" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t "REG_SZ" /d "Deny" /f


reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t "REG_SZ" /d "Deny" /f
bcdedit /set "disabledynamictick" "Yes"
  
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t "REG_SZ" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t "REG_DWORD" /d "0" /f
  
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t "REG_DWORD" /d "0" /f
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
net stop wuauserv
net stop bits
Windows Registry Editor Version 5.00
 
