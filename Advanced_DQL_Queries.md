# 115 Advanced Wazuh DQL Queries for Deep Threat Hunting

<img width="2355" height="948" alt="image" src="https://github.com/user-attachments/assets/9988b52b-cc87-4051-b47b-50a53402e9ca" />

## Wazuh SIEM v4.11.2 | Expert-Level Security Analytics

**For Senior SOC Analysts, Threat Hunters, Incident Responders & Red Team Detection**

> All queries use DQL syntax for Threat Hunting interface (Threat Intelligence → Threat Hunting)

---

## Table of Contents

1. [Initial Access & Reconnaissance (1-10)](#1-initial-access--reconnaissance)
2. [Execution & Process Attacks (11-20)](#2-execution--process-attacks)
3. [PowerShell & Script Attacks (21-30)](#3-powershell--script-attacks)
4. [Persistence Mechanisms (31-40)](#4-persistence-mechanisms)
5. [Privilege Escalation (41-50)](#5-privilege-escalation)
6. [Defense Evasion (51-60)](#6-defense-evasion)
7. [Credential Access & Theft (61-70)](#7-credential-access--theft)
8. [Lateral Movement (71-80)](#8-lateral-movement)
9. [Collection & Exfiltration (81-90)](#9-collection--exfiltration)
10. [Command & Control (91-100)](#10-command--control)
11. [DoS & DDoS Attack Detection (101-115)](#11-dos--ddos-attack-detection) **NEW**

---

## 1. Initial Access & Reconnaissance

### Query 1: Multi-Vector External Attack Detection
*Comprehensive detection of all external attack vectors from non-RFC1918 addresses*

```
rule.level >= 7 and (rule.groups:"attack" or rule.groups:"exploit" or rule.groups:"scan" or rule.groups:"reconnaissance" or rule.groups:"brute_force" or rule.groups:"authentication_failed") and not (data.srcip:"10.*" or data.srcip:"192.168.*" or data.srcip:"172.16.*" or data.srcip:"172.17.*" or data.srcip:"172.18.*" or data.srcip:"172.19.*" or data.srcip:"172.20.*" or data.srcip:"172.21.*" or data.srcip:"172.22.*" or data.srcip:"172.23.*" or data.srcip:"172.24.*" or data.srcip:"172.25.*" or data.srcip:"172.26.*" or data.srcip:"172.27.*" or data.srcip:"172.28.*" or data.srcip:"172.29.*" or data.srcip:"172.30.*" or data.srcip:"172.31.*" or data.srcip:"127.*")
```

### Query 2: Advanced Port Scan Detection with Wazuh Rules
*Detects aggressive scanning using specific Wazuh rule IDs*

```
rule.level >= 6 and (rule.id:"5706" or rule.id:"5707" or rule.id:"5708" or rule.id:"5709" or rule.id:"5710" or rule.id:"5711" or rule.id:"5712" or rule.id:"5713" or rule.id:"5714" or rule.id:"5715" or rule.id:"5716" or rule.id:"5717" or rule.id:"5718" or rule.id:"5719" or rule.id:"5720" or rule.id:"40101" or rule.id:"40102" or rule.id:"40103" or rule.id:"40104" or rule.id:"40105")
```

### Query 3: Web Application Attack Detection (OWASP Top 10)
*Comprehensive web attack detection covering SQL injection, XSS, CSRF, RCE, LFI, RFI*

```
rule.level >= 7 and (rule.groups:"web" or rule.groups:"attack" or rule.groups:"accesslog") and (rule.id:"31101" or rule.id:"31102" or rule.id:"31103" or rule.id:"31104" or rule.id:"31105" or rule.id:"31106" or rule.id:"31107" or rule.id:"31108" or rule.id:"31109" or rule.id:"31110" or rule.id:"31111" or rule.id:"31112" or rule.id:"31113" or rule.id:"31114" or rule.id:"31115" or rule.id:"31116" or rule.id:"31117" or rule.id:"31118" or rule.id:"31119" or rule.id:"31120" or rule.id:"31121" or rule.id:"31122" or rule.id:"31123" or rule.id:"31124" or rule.id:"31125" or rule.id:"31151" or rule.id:"31152" or rule.id:"31153" or rule.id:"31154" or rule.id:"31161" or rule.id:"31162" or rule.id:"31163" or rule.id:"31164" or rule.id:"31165" or rule.id:"31166" or rule.id:"31167" or rule.id:"31168" or rule.id:"31169" or rule.id:"31170" or rule.id:"31171" or rule.id:"31172" or rule.id:"31173" or rule.id:"31174" or rule.id:"31175" or rule.id:"31501" or rule.id:"31502" or rule.id:"31503" or rule.id:"31504" or rule.id:"31505" or rule.id:"31506" or rule.id:"31507" or rule.id:"31508" or rule.id:"31509" or rule.id:"31510" or rule.id:"31511" or rule.id:"31512" or rule.id:"31513" or rule.id:"31514" or rule.id:"31515" or rule.id:"31516" or rule.id:"31517" or rule.id:"31518" or rule.id:"31519" or rule.id:"31520")
```

### Query 4: SQL Injection Attack Patterns
*Deep detection of SQL injection attempts with payload patterns*

```
rule.level >= 7 and (rule.groups:"sql_injection" or rule.groups:"attack" or rule.groups:"web") and (rule.description:"*SQL*injection*" or rule.description:"*UNION*SELECT*" or rule.description:"*OR 1=1*" or rule.description:"*DROP TABLE*" or rule.description:"*INSERT INTO*" or rule.description:"*DELETE FROM*" or rule.description:"*UPDATE*SET*" or rule.description:"*EXEC*" or rule.description:"*xp_cmdshell*" or rule.description:"*information_schema*" or rule.description:"*sysobjects*" or rule.description:"*syscolumns*")
```

### Query 5: Cross-Site Scripting (XSS) Detection
*Comprehensive XSS attack detection including reflected, stored, and DOM-based*

```
rule.level >= 7 and (rule.groups:"xss" or rule.groups:"attack" or rule.groups:"web") and (rule.description:"*<script*" or rule.description:"*javascript:*" or rule.description:"*onerror=*" or rule.description:"*onload=*" or rule.description:"*onclick=*" or rule.description:"*onmouseover=*" or rule.description:"*eval(*" or rule.description:"*document.cookie*" or rule.description:"*alert(*" or rule.description:"*String.fromCharCode*" or rule.description:"*&#x*" or rule.description:"*%3Cscript*")
```

### Query 6: Directory Traversal & Path Manipulation
*Detects path traversal attempts to access sensitive files*

```
rule.level >= 7 and (rule.groups:"attack" or rule.groups:"web") and (rule.description:"*../*" or rule.description:"*..\\*" or rule.description:"*%2e%2e*" or rule.description:"*%252e*" or rule.description:"*/etc/passwd*" or rule.description:"*/etc/shadow*" or rule.description:"*/windows/system32*" or rule.description:"*boot.ini*" or rule.description:"*win.ini*" or rule.description:"*php://filter*" or rule.description:"*file://*" or rule.description:"*expect://*")
```

### Query 7: Remote Code Execution (RCE) Attempts
*Detects command injection and RCE attempts*

```
rule.level >= 10 and (rule.groups:"attack" or rule.groups:"exploit" or rule.groups:"web") and (rule.description:"*;id*" or rule.description:"*|id*" or rule.description:"*`id`*" or rule.description:"*$(id)*" or rule.description:"*;cat*" or rule.description:"*|cat*" or rule.description:"*;ls*" or rule.description:"*|ls*" or rule.description:"*;whoami*" or rule.description:"*|whoami*" or rule.description:"*;wget*" or rule.description:"*;curl*" or rule.description:"*;nc*" or rule.description:"*;bash*" or rule.description:"*;sh*" or rule.description:"*cmd.exe*" or rule.description:"*powershell*")
```

### Query 8: Server-Side Request Forgery (SSRF) Detection
*Detects SSRF attempts targeting internal services*

```
rule.level >= 7 and (rule.groups:"attack" or rule.groups:"web") and (rule.description:"*127.0.0.1*" or rule.description:"*localhost*" or rule.description:"*169.254.169.254*" or rule.description:"*metadata*" or rule.description:"*internal*" or rule.description:"*file://*" or rule.description:"*dict://*" or rule.description:"*gopher://*" or rule.description:"*http://10.*" or rule.description:"*http://192.168.*" or rule.description:"*http://172.*")
```

### Query 9: SSH Brute Force with High Fidelity
*Detects SSH brute force attacks with multiple Wazuh signatures*

```
rule.level >= 10 and rule.groups:"sshd" and (rule.id:"5710" or rule.id:"5711" or rule.id:"5712" or rule.id:"5720" or rule.id:"5721" or rule.id:"5722" or rule.id:"5723" or rule.id:"5724" or rule.id:"5725" or rule.id:"5726" or rule.id:"5727" or rule.id:"5728" or rule.id:"5729" or rule.id:"5730" or rule.id:"5755" or rule.id:"5756" or rule.id:"5757" or rule.id:"5758" or rule.id:"5759" or rule.id:"5760" or rule.id:"5761" or rule.id:"5762" or rule.id:"5763")
```

### Query 10: Vulnerability Exploitation Indicators
*Detects exploitation of known vulnerabilities (CVE patterns)*

```
rule.level >= 10 and (rule.groups:"exploit" or rule.groups:"vulnerability" or rule.groups:"attack") and (rule.description:"*CVE-*" or rule.description:"*exploit*" or rule.description:"*vulnerability*" or rule.description:"*overflow*" or rule.description:"*buffer*" or rule.description:"*heap*spray*" or rule.description:"*use-after-free*" or rule.description:"*remote*code*" or rule.description:"*arbitrary*code*" or rule.description:"*privilege*escalation*")
```

---

## 2. Execution & Process Attacks

### Query 11: Suspicious Process Execution (Windows Comprehensive)
*Detects execution of commonly abused Windows binaries*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.originalFileName:"cmd.exe" or data.win.eventdata.originalFileName:"powershell.exe" or data.win.eventdata.originalFileName:"pwsh.exe" or data.win.eventdata.originalFileName:"wscript.exe" or data.win.eventdata.originalFileName:"cscript.exe" or data.win.eventdata.originalFileName:"mshta.exe" or data.win.eventdata.originalFileName:"regsvr32.exe" or data.win.eventdata.originalFileName:"rundll32.exe" or data.win.eventdata.originalFileName:"certutil.exe" or data.win.eventdata.originalFileName:"bitsadmin.exe" or data.win.eventdata.originalFileName:"msiexec.exe" or data.win.eventdata.originalFileName:"wmic.exe" or data.win.eventdata.originalFileName:"cmstp.exe" or data.win.eventdata.originalFileName:"msbuild.exe" or data.win.eventdata.originalFileName:"installutil.exe" or data.win.eventdata.originalFileName:"regasm.exe" or data.win.eventdata.originalFileName:"regsvcs.exe" or data.win.eventdata.originalFileName:"odbcconf.exe" or data.win.eventdata.originalFileName:"ieexec.exe" or data.win.eventdata.originalFileName:"msconfig.exe")
```

### Query 12: Office Application Spawning Suspicious Processes
*Detects Office applications launching potentially malicious child processes*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.parentImage:"*\\WINWORD.EXE" or data.win.eventdata.parentImage:"*\\EXCEL.EXE" or data.win.eventdata.parentImage:"*\\POWERPNT.EXE" or data.win.eventdata.parentImage:"*\\OUTLOOK.EXE" or data.win.eventdata.parentImage:"*\\MSACCESS.EXE" or data.win.eventdata.parentImage:"*\\MSPUB.EXE" or data.win.eventdata.parentImage:"*\\ONENOTE.EXE") and (data.win.eventdata.image:"*\\cmd.exe" or data.win.eventdata.image:"*\\powershell.exe" or data.win.eventdata.image:"*\\wscript.exe" or data.win.eventdata.image:"*\\cscript.exe" or data.win.eventdata.image:"*\\mshta.exe" or data.win.eventdata.image:"*\\certutil.exe" or data.win.eventdata.image:"*\\bitsadmin.exe" or data.win.eventdata.image:"*\\regsvr32.exe" or data.win.eventdata.image:"*\\rundll32.exe")
```

### Query 13: Living-Off-The-Land Binaries (LOLBins) Abuse
*Detects abuse of legitimate Windows binaries for malicious purposes*

```
rule.level >= 8 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*certutil*-decode*" or data.win.eventdata.commandLine:"*certutil*-urlcache*" or data.win.eventdata.commandLine:"*bitsadmin*/transfer*" or data.win.eventdata.commandLine:"*regsvr32*/s*/u*/i:http*" or data.win.eventdata.commandLine:"*rundll32*javascript:*" or data.win.eventdata.commandLine:"*mshta*http*" or data.win.eventdata.commandLine:"*mshta*javascript:*" or data.win.eventdata.commandLine:"*wmic*process*call*create*" or data.win.eventdata.commandLine:"*forfiles*/p*c:*cmd*" or data.win.eventdata.commandLine:"*msiexec*/q*/i*http*" or data.win.eventdata.commandLine:"*odbcconf*/a*{REGSVR*")
```

### Query 14: DLL Injection & Process Injection
*Detects process injection techniques via DLL loading*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60007" or rule.id:"60010") and (data.win.eventdata.imageLoaded:"*\\Temp\\*" or data.win.eventdata.imageLoaded:"*\\AppData\\*" or data.win.eventdata.imageLoaded:"*\\ProgramData\\*" or data.win.eventdata.signed:"false")
```

### Query 15: Suspicious Script Execution (VBS, JS, BAT, PS1)
*Detects execution of scripts from suspicious locations*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\wscript.exe" or data.win.eventdata.image:"*\\cscript.exe") and (data.win.eventdata.commandLine:"*\\Temp\\*.vbs" or data.win.eventdata.commandLine:"*\\Temp\\*.js" or data.win.eventdata.commandLine:"*\\AppData\\*.vbs" or data.win.eventdata.commandLine:"*\\AppData\\*.js" or data.win.eventdata.commandLine:"*\\Downloads\\*.vbs" or data.win.eventdata.commandLine:"*\\Downloads\\*.js" or data.win.eventdata.commandLine:"*\\ProgramData\\*.vbs" or data.win.eventdata.commandLine:"*\\ProgramData\\*.js")
```

### Query 16: Process Hollowing Detection
*Detects process hollowing using parent-child process anomalies*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60001" and (data.win.eventdata.parentImage:"*\\svchost.exe" or data.win.eventdata.parentImage:"*\\explorer.exe" or data.win.eventdata.parentImage:"*\\services.exe") and (data.win.eventdata.image:"*\\Temp\\*" or data.win.eventdata.image:"*\\AppData\\*" or data.win.eventdata.commandLine:"*suspend*")
```

### Query 17: Unsigned Process Execution from Non-Standard Paths
*Detects unsigned binaries running from suspicious directories*

```
rule.level >= 7 and rule.groups:"sysmon" and rule.id:"60001" and data.win.eventdata.signed:"false" and (data.win.eventdata.image:"*\\Temp\\*" or data.win.eventdata.image:"*\\AppData\\Roaming\\*" or data.win.eventdata.image:"*\\Users\\Public\\*" or data.win.eventdata.image:"*\\ProgramData\\*" or data.win.eventdata.image:"*C:\\Users\\*\\Downloads\\*")
```

### Query 18: WMI Process Creation
*Detects processes created via WMI (common in lateral movement)*

```
rule.level >= 8 and rule.groups:"sysmon" and rule.id:"60001" and data.win.eventdata.parentImage:"*\\WmiPrvSE.exe"
```

### Query 19: Remote Thread Creation
*Detects CreateRemoteThread API usage (injection technique)*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60008" and not (data.win.eventdata.sourceImage:"*\\System32\\*" or data.win.eventdata.sourceImage:"*\\SysWOW64\\*")
```

### Query 20: Fileless Malware Indicators
*Detects indicators of fileless/memory-only malware execution*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*IEX*" or data.win.eventdata.commandLine:"*Invoke-Expression*" or data.win.eventdata.commandLine:"*DownloadString*" or data.win.eventdata.commandLine:"*DownloadData*" or data.win.eventdata.commandLine:"*FromBase64String*" or data.win.eventdata.commandLine:"*-EncodedCommand*" or data.win.eventdata.commandLine:"*-enc*" or data.win.eventdata.commandLine:"*ReflectivePEInjection*" or data.win.eventdata.commandLine:"*Invoke-Shellcode*")
```

---

## 3. PowerShell & Script Attacks

### Query 21: PowerShell Download Cradles
*Detects PowerShell downloading files from the internet*

```
rule.level >= 10 and rule.groups:"powershell" and (data.win.eventdata.scriptBlockText:"*Net.WebClient*" or data.win.eventdata.scriptBlockText:"*DownloadString*" or data.win.eventdata.scriptBlockText:"*DownloadFile*" or data.win.eventdata.scriptBlockText:"*Invoke-WebRequest*" or data.win.eventdata.scriptBlockText:"*iwr*" or data.win.eventdata.scriptBlockText:"*wget*" or data.win.eventdata.scriptBlockText:"*curl*" or data.win.eventdata.scriptBlockText:"*BitsTransfer*" or data.win.eventdata.scriptBlockText:"*Start-BitsTransfer*")
```

### Query 22: PowerShell Encoded Commands
*Detects obfuscated/encoded PowerShell execution*

```
rule.level >= 10 and rule.groups:"powershell" and (data.win.eventdata.commandLine:"*-EncodedCommand*" or data.win.eventdata.commandLine:"*-enc*" or data.win.eventdata.commandLine:"*-e *" or data.win.eventdata.scriptBlockText:"*FromBase64String*" or data.win.eventdata.scriptBlockText:"*ToBase64String*")
```

### Query 23: PowerShell Execution Policy Bypass
*Detects attempts to bypass PowerShell execution policy*

```
rule.level >= 8 and rule.groups:"powershell" and (data.win.eventdata.commandLine:"*-ExecutionPolicy Bypass*" or data.win.eventdata.commandLine:"*-ep bypass*" or data.win.eventdata.commandLine:"*-ExecutionPolicy Unrestricted*" or data.win.eventdata.commandLine:"*Set-ExecutionPolicy*")
```

### Query 24: PowerShell Empire/Metasploit Indicators
*Detects common frameworks like Empire, Metasploit, Covenant*

```
rule.level >= 12 and rule.groups:"powershell" and (data.win.eventdata.scriptBlockText:"*Invoke-Mimikatz*" or data.win.eventdata.scriptBlockText:"*Invoke-Empire*" or data.win.eventdata.scriptBlockText:"*Invoke-Shellcode*" or data.win.eventdata.scriptBlockText:"*Invoke-Kerberoast*" or data.win.eventdata.scriptBlockText:"*Invoke-PowerShellTcp*" or data.win.eventdata.scriptBlockText:"*Invoke-DllInjection*" or data.win.eventdata.scriptBlockText:"*Invoke-ReflectivePEInjection*" or data.win.eventdata.scriptBlockText:"*PowerSploit*" or data.win.eventdata.scriptBlockText:"*Covenant*" or data.win.eventdata.scriptBlockText:"*SharpSploit*")
```

### Query 25: PowerShell Remoting Activity
*Detects PowerShell remoting (WinRM) usage*

```
rule.level >= 7 and rule.groups:"powershell" and (data.win.eventdata.commandLine:"*Enter-PSSession*" or data.win.eventdata.commandLine:"*Invoke-Command*" or data.win.eventdata.commandLine:"*New-PSSession*" or data.win.eventdata.commandLine:"*-ComputerName*" or data.win.eventdata.scriptBlockText:"*Enter-PSSession*" or data.win.eventdata.scriptBlockText:"*Invoke-Command*")
```

### Query 26: AMSI Bypass Attempts
*Detects Antimalware Scan Interface (AMSI) bypass techniques*

```
rule.level >= 12 and rule.groups:"powershell" and (data.win.eventdata.scriptBlockText:"*AmsiScanBuffer*" or data.win.eventdata.scriptBlockText:"*amsiInitFailed*" or data.win.eventdata.scriptBlockText:"*AmsiUtils*" or data.win.eventdata.scriptBlockText:"*Patch*AMSI*" or data.win.eventdata.scriptBlockText:"*Bypass*AMSI*" or data.win.eventdata.commandLine:"*Reflection.Assembly*" or data.win.eventdata.scriptBlockText:"*System.Management.Automation.AmsiUtils*")
```

### Query 27: PowerShell Credential Access
*Detects PowerShell credential theft techniques*

```
rule.level >= 12 and rule.groups:"powershell" and (data.win.eventdata.scriptBlockText:"*Get-Credential*" or data.win.eventdata.scriptBlockText:"*ConvertTo-SecureString*" or data.win.eventdata.scriptBlockText:"*System.Net.CredentialCache*" or data.win.eventdata.scriptBlockText:"*PasswordVault*" or data.win.eventdata.scriptBlockText:"*Get-StoredCredential*" or data.win.eventdata.scriptBlockText:"*Invoke-Mimikatz*" or data.win.eventdata.scriptBlockText:"*sekurlsa::*")
```

### Query 28: PowerShell Persistence Mechanisms
*Detects PowerShell-based persistence creation*

```
rule.level >= 10 and rule.groups:"powershell" and (data.win.eventdata.scriptBlockText:"*New-ScheduledTask*" or data.win.eventdata.scriptBlockText:"*Register-ScheduledTask*" or data.win.eventdata.scriptBlockText:"*HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" or data.win.eventdata.scriptBlockText:"*HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" or data.win.eventdata.scriptBlockText:"*New-Service*" or data.win.eventdata.scriptBlockText:"*WMI*__EventFilter*" or data.win.eventdata.scriptBlockText:"*__EventConsumer*")
```

### Query 29: Suspicious PowerShell Module Loading
*Detects loading of offensive security PowerShell modules*

```
rule.level >= 10 and rule.groups:"powershell" and (data.win.eventdata.scriptBlockText:"*Import-Module*PowerSploit*" or data.win.eventdata.scriptBlockText:"*Import-Module*Nishang*" or data.win.eventdata.scriptBlockText:"*Import-Module*Empire*" or data.win.eventdata.scriptBlockText:"*Import-Module*PowerUp*" or data.win.eventdata.scriptBlockText:"*Import-Module*Inveigh*")
```

### Query 30: PowerShell Anti-Forensics
*Detects log clearing and anti-forensics activities*

```
rule.level >= 12 and rule.groups:"powershell" and (data.win.eventdata.scriptBlockText:"*Clear-EventLog*" or data.win.eventdata.scriptBlockText:"*Remove-EventLog*" or data.win.eventdata.scriptBlockText:"*wevtutil*cl*" or data.win.eventdata.scriptBlockText:"*Remove-Item*-Path*PSReadline*" or data.win.eventdata.scriptBlockText:"*Set-MpPreference*-DisableRealtimeMonitoring*")
```

---

## 4. Persistence Mechanisms

### Query 31: Registry Run Keys Modification
*Detects creation/modification of Windows Run registry keys*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60013" and (data.win.eventdata.targetObject:"*\\Microsoft\\Windows\\CurrentVersion\\Run*" or data.win.eventdata.targetObject:"*\\Microsoft\\Windows\\CurrentVersion\\RunOnce*" or data.win.eventdata.targetObject:"*\\Microsoft\\Windows\\CurrentVersion\\RunServices*" or data.win.eventdata.targetObject:"*\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce*" or data.win.eventdata.targetObject:"*\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders*" or data.win.eventdata.targetObject:"*\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders*")
```

### Query 32: Scheduled Task Creation
*Detects creation of scheduled tasks for persistence*

```
rule.level >= 8 and (rule.groups:"sysmon" or rule.groups:"windows") and (data.win.eventdata.image:"*\\schtasks.exe" or rule.id:"60106" or rule.id:"60107") and (data.win.eventdata.commandLine:"*/create*" or data.win.eventdata.commandLine:"*/change*" or data.win.system.eventID:"4698")
```

### Query 33: Service Creation/Modification
*Detects new service creation or modification*

```
rule.level >= 8 and rule.groups:"windows" and (rule.id:"60102" or rule.id:"60103" or data.win.system.eventID:"4697" or data.win.system.eventID:"7045") and not (data.win.eventdata.serviceName:"Windows*" or data.win.eventdata.serviceName:"Microsoft*")
```

### Query 34: WMI Event Subscription (Persistence)
*Detects WMI event subscriptions used for persistence*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60019" or rule.id:"60020" or rule.id:"60021") and (data.win.eventdata.eventNamespace:"*__EventFilter*" or data.win.eventdata.eventNamespace:"*__EventConsumer*" or data.win.eventdata.eventNamespace:"*__FilterToConsumerBinding*")
```

### Query 35: Startup Folder Modifications
*Detects files added to Windows Startup folders*

```
rule.level >= 8 and rule.groups:"sysmon" and rule.id:"60011" and (data.win.eventdata.targetFilename:"*\\Start Menu\\Programs\\Startup\\*" or data.win.eventdata.targetFilename:"*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*")
```

### Query 36: Winlogon Helper DLL Registry Modification
*Detects modifications to Winlogon Helper DLL registry keys*

```
rule.level >= 12 and rule.groups:"sysmon" and rule.id:"60013" and (data.win.eventdata.targetObject:"*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell*" or data.win.eventdata.targetObject:"*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit*" or data.win.eventdata.targetObject:"*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify*")
```

### Query 37: AppInit DLLs Registry Modification
*Detects AppInit_DLLs persistence technique*

```
rule.level >= 12 and rule.groups:"sysmon" and rule.id:"60013" and (data.win.eventdata.targetObject:"*\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs*" or data.win.eventdata.targetObject:"*\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs*")
```

### Query 38: Office Application Startup Persistence
*Detects persistence via Office application startup locations*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60011" or rule.id:"60013") and (data.win.eventdata.targetFilename:"*\\Microsoft\\Word\\STARTUP\\*" or data.win.eventdata.targetFilename:"*\\Microsoft\\Excel\\XLSTART\\*" or data.win.eventdata.targetObject:"*\\Software\\Microsoft\\Office\\*\\Word\\Security\\AccessVBOM*" or data.win.eventdata.targetObject:"*\\Software\\Microsoft\\Office\\*\\Excel\\Security\\AccessVBOM*")
```

### Query 39: Browser Extension Installation
*Detects installation of browser extensions (potential persistence)*

```
rule.level >= 7 and rule.groups:"sysmon" and rule.id:"60011" and (data.win.eventdata.targetFilename:"*\\Google\\Chrome\\User Data\\Default\\Extensions\\*" or data.win.eventdata.targetFilename:"*\\Mozilla\\Firefox\\Profiles\\*\\extensions\\*" or data.win.eventdata.targetFilename:"*\\Microsoft\\Edge\\User Data\\Default\\Extensions\\*")
```

### Query 40: Screensaver Persistence
*Detects screensaver manipulation for persistence*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60013" and (data.win.eventdata.targetObject:"*\\Control Panel\\Desktop\\SCRNSAVE.EXE*" or data.win.eventdata.targetObject:"*\\Control Panel\\Desktop\\ScreenSaveActive*")
```

---

## 5. Privilege Escalation

### Query 41: UAC Bypass Attempts
*Detects User Account Control bypass techniques*

```
rule.level >= 12 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*eventvwr.exe*" or data.win.eventdata.commandLine:"*fodhelper.exe*" or data.win.eventdata.commandLine:"*computerdefaults.exe*" or data.win.eventdata.commandLine:"*sdclt.exe*" or data.win.eventdata.targetObject:"*\\mscfile\\shell\\open\\command*" or data.win.eventdata.targetObject:"*\\ms-settings\\shell\\open\\command*" or data.win.eventdata.targetObject:"*\\exefile\\shell\\runas\\command\\isolatedCommand*")
```

### Query 42: Token Manipulation Detection
*Detects token impersonation and privilege escalation*

```
rule.level >= 12 and rule.groups:"windows" and (data.win.system.eventID:"4672" or data.win.system.eventID:"4673" or data.win.system.eventID:"4674") and data.win.eventdata.privilegeList:"*SeDebugPrivilege*"
```

### Query 43: Service DLL Hijacking
*Detects DLL search order hijacking in services*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60007" and (data.win.eventdata.imageLoaded:"*\\Temp\\*" or data.win.eventdata.imageLoaded:"*\\AppData\\*") and data.win.eventdata.signed:"false"
```

### Query 44: Credential Dumping via Task Manager
*Detects LSASS process access for credential dumping*

```
rule.level >= 12 and rule.groups:"sysmon" and rule.id:"60010" and data.win.eventdata.targetImage:"*\\lsass.exe" and not data.win.eventdata.sourceImage:"*\\System32\\*"
```

### Query 45: Exploitation Framework Execution
*Detects known privilege escalation tools and frameworks*

```
rule.level >= 12 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\mimikatz.exe" or data.win.eventdata.image:"*\\procdump*" or data.win.eventdata.commandLine:"*Invoke-Mimikatz*" or data.win.eventdata.commandLine:"*Get-GPPPassword*" or data.win.eventdata.commandLine:"*Invoke-PowerUp*" or data.win.eventdata.commandLine:"*PowerUp.ps1*" or data.win.eventdata.commandLine:"*SharpUp*")
```

### Query 46: Kernel Driver Loading
*Detects suspicious kernel driver loading*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60006" and (data.win.eventdata.imageLoaded:"*\\Temp\\*" or data.win.eventdata.imageLoaded:"*\\Users\\*" or data.win.eventdata.signed:"false")
```

### Query 47: SAM Database Access
*Detects attempts to access SAM registry hive*

```
rule.level >= 12 and rule.groups:"sysmon" and (rule.id:"60012" or rule.id:"60013") and data.win.eventdata.targetObject:"*\\SAM\\SAM\\Domains\\Account\\Users\\*"
```

### Query 48: PrintSpooler Exploitation (PrintNightmare)
*Detects PrintNightmare and related Print Spooler exploits*

```
rule.level >= 12 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\spoolsv.exe" or data.win.eventdata.parentImage:"*\\spoolsv.exe") and (data.win.eventdata.image:"*\\cmd.exe" or data.win.eventdata.image:"*\\powershell.exe" or data.win.eventdata.commandLine:"*AddPrinterDriverEx*")
```

### Query 49: Sudo/SUID Binary Abuse (Linux)
*Detects privilege escalation via SUID binaries or sudo abuse on Linux*

```
rule.level >= 10 and (rule.groups:"sudo" or rule.groups:"linux") and (rule.description:"*sudo*" or rule.description:"*SUID*" or data.command:"*sudo*" or data.command:"*pkexec*")
```

### Query 50: Accessibility Feature Abuse (Sticky Keys)
*Detects sticky keys and other accessibility feature backdoors*

```
rule.level >= 12 and rule.groups:"sysmon" and rule.id:"60013" and (data.win.eventdata.targetObject:"*\\Image File Execution Options\\sethc.exe*" or data.win.eventdata.targetObject:"*\\Image File Execution Options\\utilman.exe*" or data.win.eventdata.targetObject:"*\\Image File Execution Options\\osk.exe*" or data.win.eventdata.targetObject:"*\\Image File Execution Options\\Magnify.exe*")
```

---

## 6. Defense Evasion

### Query 51: Windows Defender Tampering
*Detects attempts to disable or tamper with Windows Defender*

```
rule.level >= 12 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*Set-MpPreference*-DisableRealtimeMonitoring*" or data.win.eventdata.commandLine:"*Set-MpPreference*-DisableBehaviorMonitoring*" or data.win.eventdata.commandLine:"*Set-MpPreference*-DisableIOAVProtection*" or data.win.eventdata.commandLine:"*Add-MpPreference*-ExclusionPath*" or data.win.eventdata.targetObject:"*\\Windows Defender\\DisableAntiSpyware*" or data.win.eventdata.targetObject:"*\\Windows Defender\\DisableAntiVirus*")
```

### Query 52: Event Log Clearing
*Detects clearing of Windows event logs*

```
rule.level >= 12 and rule.groups:"windows" and (data.win.system.eventID:"1102" or data.win.system.eventID:"104" or data.win.eventdata.commandLine:"*wevtutil*cl*" or data.win.eventdata.commandLine:"*Clear-EventLog*")
```

### Query 53: Timestomping Detection
*Detects file timestamp modification*

```
rule.level >= 8 and rule.groups:"sysmon" and rule.id:"60002" and data.win.eventdata.previousCreationUtcTime:* and not data.win.eventdata.image:"*\\MsiExec.exe"
```

### Query 54: Process Masquerading
*Detects processes with names similar to legitimate Windows processes*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60001" and (data.win.eventdata.image:"*\\svchost.exe" or data.win.eventdata.image:"*\\lsass.exe" or data.win.eventdata.image:"*\\csrss.exe" or data.win.eventdata.image:"*\\smss.exe") and not (data.win.eventdata.image:"C:\\Windows\\System32\\*" or data.win.eventdata.image:"C:\\Windows\\SysWOW64\\*")
```

### Query 55: Indicator Removal - File Deletion
*Detects deletion of files from suspicious locations*

```
rule.level >= 8 and rule.groups:"sysmon" and rule.id:"60023" and (data.win.eventdata.targetFilename:"*\\Temp\\*" or data.win.eventdata.targetFilename:"*\\AppData\\*" or data.win.eventdata.targetFilename:"*.log" or data.win.eventdata.targetFilename:"*.evtx")
```

### Query 56: DLL Side-Loading
*Detects DLL side-loading techniques*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60007" and data.win.eventdata.signed:"false" and not (data.win.eventdata.imageLoaded:"C:\\Windows\\System32\\*" or data.win.eventdata.imageLoaded:"C:\\Windows\\SysWOW64\\*" or data.win.eventdata.imageLoaded:"C:\\Program Files\\*")
```

### Query 57: Code Signing Abuse
*Detects execution of signed binaries from suspicious locations*

```
rule.level >= 8 and rule.groups:"sysmon" and rule.id:"60001" and data.win.eventdata.signed:"true" and (data.win.eventdata.image:"*\\Temp\\*" or data.win.eventdata.image:"*\\AppData\\*" or data.win.eventdata.image:"*\\Users\\Public\\*")
```

### Query 58: Rootkit Behavior
*Detects rootkit-like behaviors and hidden processes*

```
rule.level >= 12 and (rule.groups:"rootkit" or rule.groups:"malware") and (rule.id:"510" or rule.id:"511" or rule.id:"512" or rule.id:"513" or rule.id:"514" or rule.id:"515" or rule.id:"516" or rule.id:"517" or rule.id:"518" or rule.id:"519")
```

### Query 59: Obfuscated Files or Information
*Detects heavily obfuscated commands and files*

```
rule.level >= 10 and (rule.groups:"sysmon" or rule.groups:"powershell") and (data.win.eventdata.commandLine:"*^^^*" or data.win.eventdata.commandLine:"*+++*" or data.win.eventdata.scriptBlockText:"*^^^*" or data.win.eventdata.scriptBlockText:"*+++*")
```

### Query 60: Impair Defenses - Firewall Modification
*Detects changes to Windows Firewall configuration*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*netsh*firewall*" or data.win.eventdata.commandLine:"*netsh*advfirewall*" or data.win.eventdata.commandLine:"*Set-NetFirewallProfile*" or data.win.eventdata.commandLine:"*Disable-NetFirewall*")
```

---

## 7. Credential Access & Theft

### Query 61: LSASS Memory Dumping
*Detects attempts to dump LSASS process memory*

```
rule.level >= 12 and rule.groups:"sysmon" and rule.id:"60010" and data.win.eventdata.targetImage:"*\\lsass.exe" and (data.win.eventdata.grantedAccess:"0x1010" or data.win.eventdata.grantedAccess:"0x1410" or data.win.eventdata.grantedAccess:"0x1fffff")
```

### Query 62: Credential Dumping Tools Execution
*Detects execution of known credential dumping tools*

```
rule.level >= 12 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\mimikatz*" or data.win.eventdata.image:"*\\procdump*" or data.win.eventdata.image:"*\\pwdump*" or data.win.eventdata.commandLine:"*sekurlsa::*" or data.win.eventdata.commandLine:"*lsadump::*" or data.win.eventdata.originalFileName:"mimikatz.exe" or data.win.eventdata.originalFileName:"procdump.exe")
```

### Query 63: DCSync Attack Detection
*Detects DCSync attack against Active Directory*

```
rule.level >= 12 and rule.groups:"windows" and data.win.system.eventID:"4662" and (data.win.eventdata.properties:"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" or data.win.eventdata.properties:"*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*") and not data.win.eventdata.subjectUserName:"*$"
```

### Query 64: Kerberoasting Detection
*Detects Kerberoasting attacks (SPN ticket requests)*

```
rule.level >= 10 and rule.groups:"windows" and data.win.system.eventID:"4769" and data.win.eventdata.ticketEncryptionType:"0x17" and not (data.win.eventdata.serviceName:"krbtgt" or data.win.eventdata.serviceName:"*$")
```

### Query 65: AS-REP Roasting Detection
*Detects AS-REP roasting attempts*

```
rule.level >= 10 and rule.groups:"windows" and data.win.system.eventID:"4768" and data.win.eventdata.preAuthType:"0"
```

### Query 66: SAM Registry Hive Access
*Detects access to SAM registry hive for credential theft*

```
rule.level >= 12 and rule.groups:"sysmon" and rule.id:"60012" and (data.win.eventdata.targetObject:"*\\SAM\\SAM\\Domains\\Account\\Users\\*" or data.win.eventdata.targetObject:"*\\SECURITY\\Policy\\Secrets\\*")
```

### Query 67: NTDS.dit Access
*Detects attempts to access Active Directory database file*

```
rule.level >= 12 and rule.groups:"sysmon" and (rule.id:"60011" or rule.id:"60015") and data.win.eventdata.targetFilename:"*\\NTDS.dit"
```

### Query 68: Credential Manager Access
*Detects access to Windows Credential Manager*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*vaultcmd*" or data.win.eventdata.commandLine:"*VaultPasswordV*" or data.win.eventdata.targetFilename:"*\\Microsoft\\Vault\\*" or data.win.eventdata.targetFilename:"*\\Microsoft\\Credentials\\*")
```

### Query 69: Browser Credential Theft
*Detects access to browser credential stores*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60011" or rule.id:"60015") and (data.win.eventdata.targetFilename:"*\\Google\\Chrome\\User Data\\Default\\Login Data*" or data.win.eventdata.targetFilename:"*\\Mozilla\\Firefox\\Profiles\\*\\logins.json*" or data.win.eventdata.targetFilename:"*\\Microsoft\\Edge\\User Data\\Default\\Login Data*")
```

### Query 70: Network Sniffing & Packet Capture
*Detects network sniffing tools and packet capture*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\wireshark*" or data.win.eventdata.image:"*\\tshark*" or data.win.eventdata.image:"*\\tcpdump*" or data.win.eventdata.commandLine:"*Invoke-Inveigh*" or data.win.eventdata.commandLine:"*net.sockets*" or data.win.eventdata.driverLoaded:"*\\WinDivert*" or data.win.eventdata.driverLoaded:"*\\npf.sys*")
```

---

## 8. Lateral Movement

### Query 71: PSExec Usage Detection
*Detects PSExec and similar remote execution tools*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\psexec.exe" or data.win.eventdata.image:"*\\PSEXESVC.exe" or data.win.eventdata.originalFileName:"psexec.c" or data.win.eventdata.serviceName:"PSEXESVC" or data.win.eventdata.commandLine:"*\\admin$\\*")
```

### Query 72: Remote Desktop Protocol (RDP) Lateral Movement
*Detects suspicious RDP connections*

```
rule.level >= 8 and rule.groups:"windows" and (data.win.system.eventID:"4624" or data.win.system.eventID:"4778") and data.win.eventdata.logonType:"10" and not data.srcip:"10.*"
```

### Query 73: Windows Admin Shares Access
*Detects access to administrative network shares (C$, ADMIN$)*

```
rule.level >= 8 and rule.groups:"windows" and data.win.system.eventID:"5140" and (data.win.eventdata.shareName:"\\\\*\\ADMIN$" or data.win.eventdata.shareName:"\\\\*\\C$" or data.win.eventdata.shareName:"\\\\*\\IPC$")
```

### Query 74: WMI Remote Execution
*Detects WMI used for remote command execution*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\wmic.exe" or data.win.eventdata.image:"*\\mofcomp.exe") and data.win.eventdata.commandLine:"*/node:*"
```

### Query 75: Remote Service Creation
*Detects remote service creation (e.g., sc.exe)*

```
rule.level >= 10 and rule.groups:"sysmon" and data.win.eventdata.image:"*\\sc.exe" and (data.win.eventdata.commandLine:"*\\\\*" or data.win.eventdata.commandLine:"*create*")
```

### Query 76: SMB/Windows File Sharing
*Detects lateral movement via SMB*

```
rule.level >= 7 and rule.groups:"windows" and (data.win.system.eventID:"5140" or data.win.system.eventID:"5145") and not data.srcip:"10.*"
```

### Query 77: Pass-the-Hash Attack Detection
*Detects Pass-the-Hash authentication attempts*

```
rule.level >= 12 and rule.groups:"windows" and data.win.system.eventID:"4624" and data.win.eventdata.logonType:"3" and data.win.eventdata.logonProcessName:"NtLmSsp" and data.win.eventdata.keyLength:"0"
```

### Query 78: Remote Scheduled Task Creation
*Detects scheduled tasks created on remote systems*

```
rule.level >= 10 and rule.groups:"sysmon" and data.win.eventdata.image:"*\\schtasks.exe" and data.win.eventdata.commandLine:"*/s*" and data.win.eventdata.commandLine:"*/create*"
```

### Query 79: Distributed Component Object Model (DCOM)
*Detects DCOM-based lateral movement*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\mmc.exe" or data.win.eventdata.image:"*\\excel.exe" or data.win.eventdata.image:"*\\outlook.exe") and data.win.eventdata.commandLine:"*-Embedding*"
```

### Query 80: SSH Lateral Movement (Linux)
*Detects SSH connections from internal hosts*

```
rule.level >= 7 and rule.groups:"sshd" and rule.description:"*Accepted*" and data.srcip:"10.*"
```

---

## 9. Collection & Exfiltration

### Query 81: Screen Capture Tools
*Detects execution of screenshot and screen recording tools*

```
rule.level >= 8 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\SnippingTool.exe" or data.win.eventdata.image:"*\\screencapture*" or data.win.eventdata.commandLine:"*screenshot*" or data.win.eventdata.commandLine:"*Get-Screenshot*")
```

### Query 82: Clipboard Data Collection
*Detects clipboard access and monitoring*

```
rule.level >= 8 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*Get-Clipboard*" or data.win.eventdata.commandLine:"*Set-Clipboard*" or data.win.eventdata.scriptBlockText:"*Windows.Clipboard*")
```

### Query 83: Audio/Video Recording
*Detects microphone and camera access*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*audio*" or data.win.eventdata.commandLine:"*microphone*" or data.win.eventdata.commandLine:"*webcam*" or data.win.eventdata.commandLine:"*camera*")
```

### Query 84: Email Collection
*Detects email data collection and PST file access*

```
rule.level >= 8 and rule.groups:"sysmon" and (data.win.eventdata.targetFilename:"*.pst" or data.win.eventdata.targetFilename:"*.ost" or data.win.eventdata.commandLine:"*Export-Mailbox*" or data.win.eventdata.commandLine:"*Get-Mailbox*")
```

### Query 85: Archive Collection (RAR, ZIP, 7z)
*Detects creation of archives (common pre-exfiltration activity)*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\rar.exe" or data.win.eventdata.image:"*\\7z.exe" or data.win.eventdata.image:"*\\winrar.exe" or data.win.eventdata.commandLine:"*Compress-Archive*" or data.win.eventdata.targetFilename:"*.zip" or data.win.eventdata.targetFilename:"*.rar" or data.win.eventdata.targetFilename:"*.7z")
```

### Query 86: Data Staging in Unusual Locations
*Detects data staged in preparation for exfiltration*

```
rule.level >= 8 and rule.groups:"sysmon" and rule.id:"60011" and (data.win.eventdata.targetFilename:"*\\Users\\Public\\*" or data.win.eventdata.targetFilename:"*\\ProgramData\\*" or data.win.eventdata.targetFilename:"*\\Temp\\*") and (data.win.eventdata.targetFilename:"*.zip" or data.win.eventdata.targetFilename:"*.rar" or data.win.eventdata.targetFilename:"*.7z" or data.win.eventdata.targetFilename:"*.tar")
```

### Query 87: Large File Transfers
*Detects large file transfers (potential exfiltration)*

```
rule.level >= 7 and (rule.groups:"web" or rule.groups:"firewall" or rule.groups:"proxy") and data.bytes_sent > 10000000
```

### Query 88: Cloud Storage Upload Detection
*Detects uploads to cloud storage services*

```
rule.level >= 7 and (rule.groups:"proxy" or rule.groups:"web" or rule.groups:"firewall") and (data.url:"*dropbox.com*" or data.url:"*drive.google.com*" or data.url:"*onedrive.com*" or data.url:"*box.com*" or data.url:"*mega.nz*" or data.url:"*wetransfer.com*")
```

### Query 89: DNS Exfiltration Detection
*Detects DNS tunneling and exfiltration*

```
rule.level >= 10 and rule.groups:"dns" and (data.query_length > 50 or rule.description:"*tunnel*" or rule.description:"*exfiltration*")
```

### Query 90: FTP/SFTP File Transfers
*Detects FTP and SFTP file transfer activity*

```
rule.level >= 7 and (rule.groups:"network" or rule.groups:"firewall") and (data.dstport:"21" or data.dstport:"22" or data.dstport:"990") and data.protocol:"TCP"
```

---

## 10. Command & Control

### Query 91: Suspicious Outbound Network Connections
*Detects outbound connections to uncommon ports*

```
rule.level >= 7 and rule.groups:"firewall" and not (data.dstport:"80" or data.dstport:"443" or data.dstport:"53" or data.dstport:"22" or data.dstport:"21" or data.dstport:"25" or data.dstport:"110" or data.dstport:"143" or data.dstport:"3389" or data.dstport:"445")
```

### Query 92: Long-Running Network Connections (Beaconing)
*Detects persistent network connections indicative of C2 beaconing*

```
rule.level >= 10 and (rule.groups:"network" or rule.groups:"firewall") and data.connection_duration > 3600
```

### Query 93: Non-Standard User-Agent Strings
*Detects suspicious HTTP User-Agent strings*

```
rule.level >= 7 and (rule.groups:"web" or rule.groups:"proxy") and (data.user_agent:"*python*" or data.user_agent:"*powershell*" or data.user_agent:"*curl*" or data.user_agent:"*wget*" or data.user_agent:"*scanner*" or data.user_agent:"*bot*")
```

### Query 94: Encoded/Obfuscated C2 Communication
*Detects encoded network communication*

```
rule.level >= 10 and (rule.groups:"network" or rule.groups:"proxy" or rule.groups:"web") and (rule.description:"*encoded*" or rule.description:"*base64*" or rule.description:"*obfuscated*" or rule.description:"*encrypted*" or data.url:"*base64*" or data.url:"*==" or data.url:"*%3D%3D*")
```

### Query 95: Domain Generation Algorithm (DGA) Detection
*Detects DGA-generated domain patterns*

```
rule.level >= 10 and (rule.groups:"dns" or rule.groups:"network") and (rule.description:"*DGA*" or rule.description:"*random*domain*" or rule.description:"*algorithmic*" or rule.description:"*generated*domain*" or rule.description:"*suspicious*domain*" or rule.description:"*malware*domain*")
```

### Query 96: Web Shell Communication
*Detects web shell C2 patterns*

```
rule.level >= 10 and (rule.groups:"web" or rule.groups:"accesslog") and (rule.description:"*webshell*" or rule.description:"*web shell*" or rule.description:"*backdoor*" or data.url:"*cmd=*" or data.url:"*exec=*" or data.url:"*command=*" or data.url:"*shell=*" or data.url:"*c99*" or data.url:"*r57*" or data.url:"*b374k*" or data.url:"*weevely*" or data.url:"*php?*=*system*" or data.url:"*php?*=*passthru*" or data.url:"*php?*=*exec*")
```

### Query 97: Proxy/Tunnel Detection
*Detects proxy and tunneling tools*

```
rule.level >= 7 and (rule.groups:"sysmon" or rule.groups:"network") and (data.win.eventdata.image:"*\\plink.exe" or data.win.eventdata.image:"*\\ngrok*" or data.win.eventdata.image:"*\\chisel*" or data.win.eventdata.image:"*\\proxychains*" or data.win.eventdata.commandLine:"*ssh*-D*" or data.win.eventdata.commandLine:"*ssh*-R*" or data.win.eventdata.commandLine:"*ssh*-L*" or data.win.eventdata.commandLine:"*socat*" or data.win.eventdata.commandLine:"*netsh*portproxy*" or data.win.eventdata.commandLine:"*proxifier*" or data.command:"*ssh*-D*" or data.command:"*ssh*tunnel*" or data.command:"*proxychains*")
```

### Query 98: TOR Network Usage
*Detects TOR network communication*

```
rule.level >= 10 and (rule.groups:"network" or rule.groups:"firewall" or rule.groups:"sysmon") and (data.dstport:"9001" or data.dstport:"9030" or data.dstport:"9050" or data.dstport:"9051" or data.dstport:"9150" or data.dstport:"9151" or data.win.eventdata.image:"*\\tor.exe" or data.win.eventdata.image:"*\\Tor Browser\\*" or rule.description:"*TOR*" or rule.description:"*onion*" or rule.description:"*darknet*")
```

### Query 99: Multi-Protocol C2 Detection
*Detects C2 using multiple protocols*

```
rule.level >= 10 and (rule.groups:"network" or rule.groups:"firewall" or rule.groups:"sysmon") and (rule.description:"*ICMP*tunnel*" or rule.description:"*DNS*tunnel*" or rule.description:"*HTTP*tunnel*" or rule.description:"*HTTPS*tunnel*" or rule.description:"*multi*protocol*" or rule.description:"*covert*channel*" or data.win.eventdata.commandLine:"*icmpsh*" or data.win.eventdata.commandLine:"*dnscat*" or data.win.eventdata.commandLine:"*dns2tcp*" or data.win.eventdata.commandLine:"*iodine*")
```

### Query 100: Comprehensive C2 Behavior Analysis
*Master query for all C2 indicators*

```
rule.level >= 10 and ((rule.groups:"network" or rule.groups:"firewall" or rule.groups:"sysmon" or rule.groups:"proxy") and (rule.description:"*C2*" or rule.description:"*C&C*" or rule.description:"*command*control*" or rule.description:"*beacon*" or rule.description:"*callback*" or rule.description:"*implant*" or rule.description:"*RAT*" or rule.description:"*backdoor*" or rule.description:"*trojan*" or rule.description:"*malware*" or rule.description:"*botnet*")) or (data.dstport:"4444" or data.dstport:"5555" or data.dstport:"6666" or data.dstport:"7777" or data.dstport:"8888" or data.dstport:"9999" or data.dstport:"1234" or data.dstport:"31337" or data.dstport:"12345" or data.dstport:"54321")
```

---

## 11. DoS & DDoS Attack Detection

### Query 101: SYN Flood Detection
*Detects TCP SYN flood attacks based on high volume of SYN packets*
*MITRE Technique: T1498 - Network Denial of Service*

```
rule.level >= 10 and (rule.groups:"firewall" or rule.groups:"ids" or rule.groups:"network") and (rule.description:"*SYN*flood*" or rule.description:"*TCP*flood*" or rule.id:"86600") and data.protocol:"TCP"
```

### Query 102: HTTP/HTTPS Flood Detection
*Detects application-layer DDoS via excessive HTTP requests*
*MITRE Technique: T1499.004 - Application or System Exploitation*

```
rule.level >= 10 and (rule.groups:"web" or rule.groups:"accesslog" or rule.groups:"apache" or rule.groups:"nginx") and (rule.id:"31316" or rule.id:"31317" or rule.description:"*flood*" or rule.description:"*high*request*rate*" or rule.description:"*excessive*connections*")
```

### Query 103: ICMP Flood (Ping Flood) Detection
*Detects ICMP-based denial of service attacks*
*MITRE Technique: T1498.001 - Direct Network Flood*

```
rule.level >= 10 and (rule.groups:"firewall" or rule.groups:"ids" or rule.groups:"network") and (rule.description:"*ICMP*flood*" or rule.description:"*ping*flood*" or rule.description:"*ping*death*") and data.protocol:"ICMP"
```

### Query 104: UDP Flood Detection
*Detects UDP-based flood attacks*
*MITRE Technique: T1498.001 - Direct Network Flood*

```
rule.level >= 10 and (rule.groups:"firewall" or rule.groups:"ids" or rule.groups:"network") and (rule.description:"*UDP*flood*" or rule.description:"*UDP*amplification*") and data.protocol:"UDP"
```

### Query 105: DNS Amplification Attack
*Detects DNS amplification DDoS attacks*
*MITRE Technique: T1498.002 - Reflection Amplification*

```
rule.level >= 10 and (rule.groups:"dns" or rule.groups:"network" or rule.groups:"firewall") and (rule.description:"*DNS*amplification*" or rule.description:"*DNS*reflection*" or data.query_type:"ANY") and data.response_size > 512
```

### Query 106: NTP Amplification Attack
*Detects NTP amplification DDoS attacks*
*MITRE Technique: T1498.002 - Reflection Amplification*

```
rule.level >= 10 and (rule.groups:"network" or rule.groups:"firewall") and data.dstport:"123" and (rule.description:"*NTP*amplification*" or rule.description:"*monlist*")
```

### Query 107: Slowloris Attack Detection
*Detects Slowloris slow HTTP DoS attacks*
*MITRE Technique: T1499.003 - Application Exhaustion Flood*

```
rule.level >= 10 and (rule.groups:"web" or rule.groups:"apache" or rule.groups:"nginx") and (rule.description:"*slowloris*" or rule.description:"*slow*http*" or rule.description:"*slow*request*" or rule.description:"*keep-alive*abuse*")
```

### Query 108: Suricata DoS/DDoS Alerts
*Comprehensive detection using Suricata IDS for DoS/DDoS patterns*
*MITRE Technique: T1498 - Network Denial of Service*

```
rule.level >= 10 and rule.groups:"suricata" and (rule.description:"*DOS*" or rule.description:"*DDOS*" or rule.description:"*DoS*" or rule.description:"*DDoS*" or rule.description:"*denial*service*" or rule.description:"*flood*attack*" or rule.id:"86600")
```

### Query 109: GoldenEye DoS Attack
*Detects GoldenEye HTTP DoS tool*
*MITRE Technique: T1499.004 - Application or System Exploitation*

```
rule.level >= 12 and rule.groups:"suricata" and (rule.id:"100200" or rule.description:"*GoldenEye*DoS*" or rule.description:"*ET DOS Inbound GoldenEye*")
```

### Query 110: Connection Rate Anomaly Detection
*Detects abnormally high connection rates from single sources*
*MITRE Technique: T1498 - Network Denial of Service*

```
rule.level >= 10 and (rule.groups:"firewall" or rule.groups:"network" or rule.groups:"sshd") and (rule.id:"5710" or rule.id:"5711" or rule.id:"5712") and rule.description:"*multiple*connection*"
```

### Query 111: Resource Exhaustion (CPU/Memory/Disk)
*Detects system resource exhaustion attacks*
*MITRE Technique: T1499 - Endpoint Denial of Service*

```
rule.level >= 10 and (rule.groups:"sysmon" or rule.groups:"windows" or rule.groups:"linux") and (rule.description:"*high*cpu*" or rule.description:"*memory*exhaustion*" or rule.description:"*disk*full*" or rule.description:"*resource*limit*")
```

### Query 112: Distributed Scanning Activity
*Detects coordinated port scanning (DDoS reconnaissance)*
*MITRE Technique: T1046 - Network Service Discovery*

```
rule.level >= 8 and (rule.groups:"firewall" or rule.groups:"ids") and (rule.id:"5706" or rule.id:"5710") and rule.description:"*scan*" and data.alert_count > 100
```

### Query 113: Application-Layer Attack (Wordpress XML-RPC)
*Detects XML-RPC amplification attacks on WordPress*
*MITRE Technique: T1499.004 - Application or System Exploitation*

```
rule.level >= 10 and (rule.groups:"web" or rule.groups:"wordpress") and (data.url:"*xmlrpc.php*" or rule.description:"*XML-RPC*") and data.method:"POST"
```

### Query 114: Memcached Amplification Attack
*Detects Memcached DDoS amplification attacks*
*MITRE Technique: T1498.002 - Reflection Amplification*

```
rule.level >= 10 and (rule.groups:"network" or rule.groups:"firewall") and data.dstport:"11211" and (rule.description:"*memcached*amplification*" or data.command:"stats*")
```

### Query 115: Multi-Vector DDoS Detection (Comprehensive)
*Master query combining multiple DDoS attack indicators*
*MITRE Technique: T1498 - Network Denial of Service*

```
rule.level >= 10 and ((rule.groups:"dos" or rule.groups:"ddos" or rule.groups:"suricata" or rule.groups:"firewall") and (rule.description:"*DOS*" or rule.description:"*DDOS*" or rule.description:"*flood*" or rule.description:"*amplification*" or rule.description:"*denial*service*")) or (rule.id:"86600" or rule.id:"100200" or rule.id:"31316" or rule.id:"5710" or rule.id:"5711" or rule.id:"5712")
```

---

## Quick Reference

### Severity Levels
| Level | Description |
|-------|-------------|
| 0-3 | Informational |
| 4-6 | Low |
| 7-9 | Medium |
| 10-11 | High |
| 12-15 | Critical |

### Common Wazuh Rule Groups
```
attack, exploit, authentication_failed, invalid_login
brute_force, dos, ddos, sql_injection, xss, web
malware, rootkit, trojan, backdoor, virus
scan, reconnaissance, privilege_escalation
lateral_movement, credential_access, exfiltration
syscheck, fim, sysmon, windows, sshd, sudo
powershell, audit, network, firewall, proxy
suricata, ids, apache, nginx, wordpress
```

### Key Wazuh Rule IDs
| Range | Category |
|-------|----------|
| 5xxx | SSH/PAM/Connection |
| 31xxx | Web Attacks |
| 60xxx | Windows/Sysmon |
| 510-519 | Rootkit |
| 550-559 | FIM |
| 86600 | Suricata Alerts |
| 100200+ | Custom DoS/DDoS Rules |

### DoS/DDoS Specific Rule IDs
| Rule ID | Description |
|---------|-------------|
| 5710 | Multiple connection attempts |
| 5711 | Multiple authentication failures |
| 5712 | Multiple connection attempts (high) |
| 31316 | Web server high error rate |
| 31317 | Web server excessive requests |
| 86600 | Suricata alert (DoS/DDoS patterns) |
| 100200 | GoldenEye DoS attack |

---

## Usage Notes

1. **Time Range**: Always set appropriate time range in the Threat Hunting interface
2. **Performance**: Complex queries with wildcards may take longer to execute
3. **Customization**: Modify queries to match your environment's specific agent names, IP ranges, and rule configurations
4. **False Positives**: Some queries may generate false positives - tune based on your baseline
5. **Correlation**: Use multiple queries together to build attack timelines
6. **Suricata Integration**: DoS/DDoS detection is significantly enhanced with Suricata IDS integration

---

## MITRE ATT&CK Coverage

| Tactic | Queries | MITRE IDs |
|--------|---------|-----------|
| Initial Access | 1-10 | T1190, T1133, T1078 |
| Execution | 11-30 | T1059, T1203, T1204 |
| Persistence | 31-40 | T1547, T1053, T1543 |
| Privilege Escalation | 41-50 | T1068, T1134, T1548 |
| Defense Evasion | 51-60 | T1562, T1070, T1055 |
| Credential Access | 61-70 | T1003, T1558, T1110 |
| Lateral Movement | 71-80 | T1021, T1570, T1563 |
| Collection/Exfiltration | 81-90 | T1119, T1560, T1048 |
| Command & Control | 91-100 | T1071, T1572, T1090 |
| **DoS/DDoS** | **101-115** | **T1498, T1499** |

---

## DoS/DDoS Detection Strategy

### Detection Layers

1. **Network Layer (L3/L4)**
   - Queries 101, 103, 104, 106, 110, 114
   - Focus: SYN floods, ICMP floods, UDP floods, amplification attacks

2. **Application Layer (L7)**
   - Queries 102, 107, 109, 113
   - Focus: HTTP floods, Slowloris, XML-RPC abuse, application exploits

3. **IDS Integration**
   - Queries 108, 109
   - Focus: Suricata-detected patterns, signature-based detection

4. **Behavioral Analysis**
   - Queries 110, 111, 112, 115
   - Focus: Rate anomalies, resource exhaustion, distributed patterns

### Recommended Approach

1. **Deploy Suricata**: Integrate Suricata IDS with Wazuh for comprehensive network-level DoS/DDoS detection
2. **Enable Web Server Logs**: Configure Apache/Nginx log monitoring for application-layer attacks
3. **Set Thresholds**: Adjust rule levels and frequency thresholds based on your network baseline
4. **Active Response**: Configure Wazuh active response with `firewall-drop` script for automatic blocking
5. **Correlation**: Use queries 115 (comprehensive) alongside specific attack-type queries for validation

---

**Document Version**: 2.0  
**Wazuh Version**: 4.11.2  
**Last Updated**: January 2025  
**New in v2.0**: Added 15 comprehensive DoS/DDoS detection queries (101-115) with MITRE ATT&CK coverage
