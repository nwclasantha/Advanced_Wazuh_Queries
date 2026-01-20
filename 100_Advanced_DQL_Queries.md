# 100 Advanced Wazuh DQL Queries for Deep Threat Hunting

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

### Query 13: Browser Spawning Suspicious Processes
*Detects browsers launching potentially malicious child processes*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.parentImage:"*\\chrome.exe" or data.win.eventdata.parentImage:"*\\firefox.exe" or data.win.eventdata.parentImage:"*\\iexplore.exe" or data.win.eventdata.parentImage:"*\\msedge.exe" or data.win.eventdata.parentImage:"*\\opera.exe" or data.win.eventdata.parentImage:"*\\brave.exe") and (data.win.eventdata.image:"*\\cmd.exe" or data.win.eventdata.image:"*\\powershell.exe" or data.win.eventdata.image:"*\\wscript.exe" or data.win.eventdata.image:"*\\cscript.exe" or data.win.eventdata.image:"*\\mshta.exe")
```

### Query 14: Suspicious Process from Temp/Download Directories
*Detects process execution from suspicious locations*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\Temp\\*" or data.win.eventdata.image:"*\\tmp\\*" or data.win.eventdata.image:"*\\Downloads\\*" or data.win.eventdata.image:"*\\AppData\\Local\\Temp\\*" or data.win.eventdata.image:"*\\AppData\\Roaming\\*" or data.win.eventdata.image:"*\\ProgramData\\*" or data.win.eventdata.image:"*\\Users\\Public\\*" or data.win.eventdata.image:"*\\Windows\\Temp\\*" or data.win.eventdata.image:"*\\$Recycle.Bin\\*")
```

### Query 15: Linux Reverse Shell Detection
*Detects common reverse shell patterns on Linux*

```
rule.level >= 12 and (rule.groups:"audit" or rule.groups:"sysmon" or rule.groups:"command") and (data.command:"*bash -i*" or data.command:"*/dev/tcp/*" or data.command:"*/dev/udp/*" or data.command:"*nc -e*" or data.command:"*nc -c*" or data.command:"*netcat -e*" or data.command:"*ncat -e*" or data.command:"*python*socket*" or data.command:"*python*pty.spawn*" or data.command:"*perl*socket*" or data.command:"*php -r*socket*" or data.command:"*ruby*TCPSocket*" or data.command:"*socat*exec*" or data.command:"*mkfifo*" or data.command:"*mknod*")
```

### Query 16: Windows Reverse Shell Detection
*Detects reverse shell creation on Windows*

```
rule.level >= 12 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*TCPClient*" or data.win.eventdata.commandLine:"*Net.Sockets*" or data.win.eventdata.commandLine:"*System.Net.Sockets*" or data.win.eventdata.commandLine:"*invoke-expression*" or data.win.eventdata.commandLine:"*downloadstring*" or data.win.eventdata.commandLine:"*nishang*" or data.win.eventdata.commandLine:"*powercat*" or data.win.eventdata.commandLine:"*Invoke-PowerShellTcp*" or data.win.eventdata.commandLine:"*-e cmd.exe*" or data.win.eventdata.commandLine:"*nc.exe*-e*")
```

### Query 17: Process Hollowing Indicators
*Detects process hollowing technique indicators*

```
rule.level >= 12 and rule.groups:"sysmon" and (rule.id:"60008" or rule.description:"*hollow*" or rule.description:"*inject*" or rule.description:"*NtUnmapViewOfSection*" or rule.description:"*WriteProcessMemory*" or rule.description:"*SetThreadContext*" or rule.description:"*ResumeThread*" or rule.description:"*VirtualAllocEx*")
```

### Query 18: DLL Search Order Hijacking
*Detects DLL hijacking attempts*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60007" or rule.description:"*DLL*hijack*" or rule.description:"*side-load*" or rule.description:"*sideload*") and (data.win.eventdata.imageLoaded:"*\\Temp\\*" or data.win.eventdata.imageLoaded:"*\\Downloads\\*" or data.win.eventdata.imageLoaded:"*\\AppData\\*" or data.win.eventdata.imageLoaded:"*\\ProgramData\\*" or data.win.eventdata.imageLoaded:"*\\Users\\Public\\*")
```

### Query 19: Suspicious Child Process of System Processes
*Detects anomalous child processes from Windows system binaries*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.parentImage:"*\\services.exe" or data.win.eventdata.parentImage:"*\\svchost.exe" or data.win.eventdata.parentImage:"*\\lsass.exe" or data.win.eventdata.parentImage:"*\\smss.exe" or data.win.eventdata.parentImage:"*\\csrss.exe" or data.win.eventdata.parentImage:"*\\wininit.exe" or data.win.eventdata.parentImage:"*\\winlogon.exe") and (data.win.eventdata.image:"*\\cmd.exe" or data.win.eventdata.image:"*\\powershell.exe" or data.win.eventdata.image:"*\\wscript.exe" or data.win.eventdata.image:"*\\cscript.exe" or data.win.eventdata.image:"*\\mshta.exe" or data.win.eventdata.image:"*\\certutil.exe")
```

### Query 20: Suspicious Command Line Patterns
*Detects suspicious command line argument patterns*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*-nop*" or data.win.eventdata.commandLine:"*-noni*" or data.win.eventdata.commandLine:"*-w hidden*" or data.win.eventdata.commandLine:"*-window hidden*" or data.win.eventdata.commandLine:"*-ep bypass*" or data.win.eventdata.commandLine:"*-exec bypass*" or data.win.eventdata.commandLine:"*-executionpolicy bypass*" or data.win.eventdata.commandLine:"*-enc*" or data.win.eventdata.commandLine:"*-encoded*" or data.win.eventdata.commandLine:"*-e JAB*" or data.win.eventdata.commandLine:"*-e SQBF*" or data.win.eventdata.commandLine:"*-e SQB*" or data.win.eventdata.commandLine:"*-e aQB*" or data.win.eventdata.commandLine:"*-e cwB*" or data.win.eventdata.commandLine:"*-e dwB*")
```

---

## 3. PowerShell & Script Attacks

### Query 21: PowerShell Download Cradles
*Detects various PowerShell download techniques*

```
rule.level >= 10 and (rule.groups:"powershell" or rule.groups:"sysmon") and (data.win.eventdata.commandLine:"*DownloadString*" or data.win.eventdata.commandLine:"*DownloadFile*" or data.win.eventdata.commandLine:"*DownloadData*" or data.win.eventdata.commandLine:"*Invoke-WebRequest*" or data.win.eventdata.commandLine:"*iwr *" or data.win.eventdata.commandLine:"*wget *" or data.win.eventdata.commandLine:"*curl *" or data.win.eventdata.commandLine:"*Net.WebClient*" or data.win.eventdata.commandLine:"*Start-BitsTransfer*" or data.win.eventdata.commandLine:"*bitsadmin*" or data.win.eventdata.commandLine:"*certutil*-urlcache*" or data.win.eventdata.commandLine:"*Invoke-RestMethod*" or data.win.eventdata.commandLine:"*irm *")
```

### Query 22: PowerShell Encoded Command Execution
*Detects Base64 encoded PowerShell commands*

```
rule.level >= 10 and (rule.groups:"powershell" or rule.groups:"sysmon") and (data.win.eventdata.commandLine:"*-enc *" or data.win.eventdata.commandLine:"*-EncodedCommand*" or data.win.eventdata.commandLine:"*-ec *" or data.win.eventdata.commandLine:"*FromBase64String*" or data.win.eventdata.commandLine:"*[Convert]::FromBase64*" or data.win.eventdata.commandLine:"*[System.Convert]::FromBase64*" or data.win.eventdata.commandLine:"*[Text.Encoding]::*" or data.win.eventdata.commandLine:"*[IO.MemoryStream]*" or data.win.eventdata.commandLine:"*DeflateStream*" or data.win.eventdata.commandLine:"*GzipStream*")
```

### Query 23: PowerShell AMSI Bypass Attempts
*Detects attempts to bypass Antimalware Scan Interface*

```
rule.level >= 12 and (rule.groups:"powershell" or rule.groups:"sysmon") and (data.win.eventdata.commandLine:"*AmsiUtils*" or data.win.eventdata.commandLine:"*amsiInitFailed*" or data.win.eventdata.commandLine:"*AmsiScanBuffer*" or data.win.eventdata.commandLine:"*amsi.dll*" or data.win.eventdata.commandLine:"*Reflection.Assembly*" or data.win.eventdata.commandLine:"*System.Management.Automation.AmsiUtils*" or data.win.eventdata.commandLine:"*AmsiContext*" or data.win.eventdata.commandLine:"*Disable-Amsi*")
```

### Query 24: PowerShell Constrained Language Mode Bypass
*Detects attempts to bypass PowerShell Constrained Language Mode*

```
rule.level >= 12 and (rule.groups:"powershell" or rule.groups:"sysmon") and (data.win.eventdata.commandLine:"*FullLanguage*" or data.win.eventdata.commandLine:"*LanguageMode*" or data.win.eventdata.commandLine:"*PSLockdownPolicy*" or data.win.eventdata.commandLine:"*__PSLockdownPolicy*" or data.win.eventdata.commandLine:"*SystemPolicy*" or data.win.eventdata.commandLine:"*ExecutionContext*" or data.win.eventdata.commandLine:"*SessionStateInternal*")
```

### Query 25: PowerShell Credential Harvesting
*Detects credential theft via PowerShell*

```
rule.level >= 12 and (rule.groups:"powershell" or rule.groups:"sysmon") and (data.win.eventdata.commandLine:"*Get-Credential*" or data.win.eventdata.commandLine:"*PromptForCredential*" or data.win.eventdata.commandLine:"*SecureString*" or data.win.eventdata.commandLine:"*ConvertFrom-SecureString*" or data.win.eventdata.commandLine:"*NetworkCredential*" or data.win.eventdata.commandLine:"*Mimikatz*" or data.win.eventdata.commandLine:"*sekurlsa*" or data.win.eventdata.commandLine:"*logonpasswords*" or data.win.eventdata.commandLine:"*Invoke-Mimikatz*" or data.win.eventdata.commandLine:"*DumpCreds*")
```

### Query 26: PowerShell Reconnaissance Commands
*Detects PowerShell-based reconnaissance*

```
rule.level >= 7 and (rule.groups:"powershell" or rule.groups:"sysmon") and (data.win.eventdata.commandLine:"*Get-ADUser*" or data.win.eventdata.commandLine:"*Get-ADComputer*" or data.win.eventdata.commandLine:"*Get-ADGroup*" or data.win.eventdata.commandLine:"*Get-ADDomain*" or data.win.eventdata.commandLine:"*Get-NetUser*" or data.win.eventdata.commandLine:"*Get-NetComputer*" or data.win.eventdata.commandLine:"*Get-NetGroup*" or data.win.eventdata.commandLine:"*Get-NetDomain*" or data.win.eventdata.commandLine:"*Get-DomainUser*" or data.win.eventdata.commandLine:"*Get-DomainComputer*" or data.win.eventdata.commandLine:"*Get-DomainController*" or data.win.eventdata.commandLine:"*Find-LocalAdminAccess*" or data.win.eventdata.commandLine:"*Invoke-UserHunter*" or data.win.eventdata.commandLine:"*Invoke-ShareFinder*")
```

### Query 27: PowerShell Empire/Covenant Indicators
*Detects common C2 framework PowerShell patterns*

```
rule.level >= 12 and (rule.groups:"powershell" or rule.groups:"sysmon") and (data.win.eventdata.commandLine:"*Empire*" or data.win.eventdata.commandLine:"*Invoke-Empire*" or data.win.eventdata.commandLine:"*Covenant*" or data.win.eventdata.commandLine:"*Grunt*" or data.win.eventdata.commandLine:"*Invoke-Obfuscation*" or data.win.eventdata.commandLine:"*Invoke-CradleCrafter*" or data.win.eventdata.commandLine:"*Out-EncodedCommand*" or data.win.eventdata.commandLine:"*PoshC2*" or data.win.eventdata.commandLine:"*Merlin*")
```

### Query 28: VBScript/JScript Malicious Patterns
*Detects suspicious VBS/JS script execution*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\wscript.exe" or data.win.eventdata.image:"*\\cscript.exe") and (data.win.eventdata.commandLine:"*WScript.Shell*" or data.win.eventdata.commandLine:"*Shell.Application*" or data.win.eventdata.commandLine:"*Scripting.FileSystemObject*" or data.win.eventdata.commandLine:"*MSXML2.XMLHTTP*" or data.win.eventdata.commandLine:"*WinHttp.WinHttpRequest*" or data.win.eventdata.commandLine:"*Adodb.Stream*" or data.win.eventdata.commandLine:"*CreateObject*" or data.win.eventdata.commandLine:"*.Run*" or data.win.eventdata.commandLine:"*.Exec*")
```

### Query 29: MSHTA Abuse Detection
*Detects MSHTA being used for malicious purposes*

```
rule.level >= 10 and rule.groups:"sysmon" and data.win.eventdata.image:"*\\mshta.exe" and (data.win.eventdata.commandLine:"*javascript:*" or data.win.eventdata.commandLine:"*vbscript:*" or data.win.eventdata.commandLine:"*http://*" or data.win.eventdata.commandLine:"*https://*" or data.win.eventdata.commandLine:"*file://*" or data.win.eventdata.commandLine:"*about:*" or data.win.eventdata.commandLine:"*ActiveXObject*" or data.win.eventdata.commandLine:"*GetObject*")
```

### Query 30: Script Interpreter Spawning Network Tools
*Detects scripts launching network utilities*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.parentImage:"*\\wscript.exe" or data.win.eventdata.parentImage:"*\\cscript.exe" or data.win.eventdata.parentImage:"*\\mshta.exe" or data.win.eventdata.parentImage:"*\\powershell.exe" or data.win.eventdata.parentImage:"*\\pwsh.exe") and (data.win.eventdata.image:"*\\net.exe" or data.win.eventdata.image:"*\\net1.exe" or data.win.eventdata.image:"*\\netstat.exe" or data.win.eventdata.image:"*\\nslookup.exe" or data.win.eventdata.image:"*\\ping.exe" or data.win.eventdata.image:"*\\tracert.exe" or data.win.eventdata.image:"*\\arp.exe" or data.win.eventdata.image:"*\\route.exe" or data.win.eventdata.image:"*\\ipconfig.exe" or data.win.eventdata.image:"*\\systeminfo.exe" or data.win.eventdata.image:"*\\whoami.exe" or data.win.eventdata.image:"*\\hostname.exe")
```

---

## 4. Persistence Mechanisms

### Query 31: Registry Run Key Persistence (Comprehensive)
*Detects all registry-based autostart locations*

```
rule.level >= 7 and rule.groups:"sysmon" and (rule.id:"60004" or rule.id:"60012" or rule.id:"60013" or rule.id:"60014") and (data.win.eventdata.targetObject:"*\\CurrentVersion\\Run*" or data.win.eventdata.targetObject:"*\\CurrentVersion\\RunOnce*" or data.win.eventdata.targetObject:"*\\CurrentVersion\\RunServices*" or data.win.eventdata.targetObject:"*\\CurrentVersion\\RunServicesOnce*" or data.win.eventdata.targetObject:"*\\CurrentVersion\\Policies\\Explorer\\Run*" or data.win.eventdata.targetObject:"*\\CurrentVersion\\Windows\\Run*" or data.win.eventdata.targetObject:"*\\Wow6432Node\\*\\Run*" or data.win.eventdata.targetObject:"*\\Explorer\\User Shell Folders*" or data.win.eventdata.targetObject:"*\\Explorer\\Shell Folders*" or data.win.eventdata.targetObject:"*\\CurrentVersion\\Windows\\Load*" or data.win.eventdata.targetObject:"*\\Winlogon\\Shell*" or data.win.eventdata.targetObject:"*\\Winlogon\\Userinit*" or data.win.eventdata.targetObject:"*\\Winlogon\\Notify*")
```

### Query 32: Scheduled Task Creation (Windows)
*Comprehensive scheduled task persistence detection*

```
rule.level >= 7 and (rule.groups:"sysmon" or rule.groups:"windows") and (rule.id:"60103" or rule.id:"60106" or rule.id:"60107" or rule.id:"4698" or rule.id:"4699" or rule.id:"4700" or rule.id:"4701" or rule.id:"4702") or (data.win.eventdata.commandLine:"*schtasks*" and (data.win.eventdata.commandLine:"*/create*" or data.win.eventdata.commandLine:"*/change*" or data.win.eventdata.commandLine:"*/run*"))
```

### Query 33: Windows Service Installation/Modification
*Detects new or modified Windows services*

```
rule.level >= 7 and (rule.groups:"sysmon" or rule.groups:"windows") and (rule.id:"60006" or rule.id:"7045" or rule.id:"7040" or rule.id:"60009" or rule.id:"60010" or rule.id:"60011") or (data.win.eventdata.commandLine:"*sc *create*" or data.win.eventdata.commandLine:"*sc *config*" or data.win.eventdata.commandLine:"*New-Service*" or data.win.eventdata.commandLine:"*Install-Service*")
```

### Query 34: WMI Persistence Detection
*Detects WMI event subscription persistence*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60019" or rule.id:"60020" or rule.id:"60021") or (data.win.eventdata.commandLine:"*EventConsumer*" or data.win.eventdata.commandLine:"*EventFilter*" or data.win.eventdata.commandLine:"*FilterToConsumerBinding*" or data.win.eventdata.commandLine:"*__EventFilter*" or data.win.eventdata.commandLine:"*CommandLineEventConsumer*" or data.win.eventdata.commandLine:"*ActiveScriptEventConsumer*" or data.win.eventdata.commandLine:"*Register-WmiEvent*" or data.win.eventdata.commandLine:"*Set-WmiInstance*")
```

### Query 35: Linux Cron Persistence (Comprehensive)
*Detects all cron-based persistence attempts*

```
rule.level >= 7 and rule.groups:"syscheck" and (syscheck.path:"/etc/crontab" or syscheck.path:"/etc/cron.d/*" or syscheck.path:"/etc/cron.daily/*" or syscheck.path:"/etc/cron.hourly/*" or syscheck.path:"/etc/cron.weekly/*" or syscheck.path:"/etc/cron.monthly/*" or syscheck.path:"/var/spool/cron/*" or syscheck.path:"/var/spool/cron/crontabs/*" or syscheck.path:"*/anacron*" or syscheck.path:"/etc/anacrontab")
```

### Query 36: Linux Systemd Service Persistence
*Detects systemd-based persistence*

```
rule.level >= 7 and rule.groups:"syscheck" and (syscheck.path:"/etc/systemd/system/*" or syscheck.path:"/lib/systemd/system/*" or syscheck.path:"/usr/lib/systemd/system/*" or syscheck.path:"/run/systemd/system/*" or syscheck.path:"~/.config/systemd/user/*" or syscheck.path:"/etc/systemd/user/*")
```

### Query 37: Linux Init Scripts & RC Files
*Detects traditional init-based persistence*

```
rule.level >= 7 and rule.groups:"syscheck" and (syscheck.path:"/etc/init.d/*" or syscheck.path:"/etc/rc.d/*" or syscheck.path:"/etc/rc.local" or syscheck.path:"/etc/rc*.d/*" or syscheck.path:"/etc/init/*" or syscheck.path:"/etc/inittab")
```

### Query 38: Shell Profile Persistence (Linux)
*Detects persistence via shell profiles*

```
rule.level >= 7 and rule.groups:"syscheck" and (syscheck.path:"*/.bashrc" or syscheck.path:"*/.bash_profile" or syscheck.path:"*/.bash_login" or syscheck.path:"*/.profile" or syscheck.path:"/etc/profile" or syscheck.path:"/etc/profile.d/*" or syscheck.path:"/etc/bash.bashrc" or syscheck.path:"*/.zshrc" or syscheck.path:"*/.zprofile" or syscheck.path:"*/.zshenv" or syscheck.path:"/etc/zsh/*")
```

### Query 39: COM Object Hijacking
*Detects COM object hijacking for persistence*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60004" or rule.id:"60014") and (data.win.eventdata.targetObject:"*\\InprocServer32*" or data.win.eventdata.targetObject:"*\\LocalServer32*" or data.win.eventdata.targetObject:"*\\TreatAs*" or data.win.eventdata.targetObject:"*\\ProgID*" or data.win.eventdata.targetObject:"*\\CLSID\\*\\(Default)*")
```

### Query 40: Image File Execution Options (IFEO) Hijacking
*Detects debugger persistence via IFEO*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60004" or rule.id:"60014") and data.win.eventdata.targetObject:"*\\Image File Execution Options\\*" and (data.win.eventdata.targetObject:"*\\Debugger*" or data.win.eventdata.targetObject:"*\\GlobalFlag*" or data.win.eventdata.targetObject:"*\\VerifierDlls*")
```

---

## 5. Privilege Escalation

### Query 41: Sudo Exploitation & Abuse (Linux)
*Comprehensive sudo abuse detection*

```
rule.level >= 7 and rule.groups:"sudo" and (rule.id:"5401" or rule.id:"5402" or rule.id:"5403" or rule.id:"5404" or rule.id:"5405" or rule.id:"5406" or rule.id:"5407" or rule.id:"5408" or rule.id:"5409" or rule.id:"5410") or (rule.description:"*sudo*" and (rule.description:"*fail*" or rule.description:"*incorrect*" or rule.description:"*not allowed*" or rule.description:"*3 incorrect*"))
```

### Query 42: SUID/SGID Binary Manipulation
*Detects SUID/SGID changes that could indicate privilege escalation*

```
rule.level >= 10 and rule.groups:"syscheck" and (syscheck.perm_after:"*s*" or rule.description:"*SUID*" or rule.description:"*SGID*" or rule.description:"*setuid*" or rule.description:"*setgid*" or rule.description:"*4755*" or rule.description:"*4711*" or rule.description:"*6755*" or rule.description:"*2755*")
```

### Query 43: Windows Token Manipulation
*Detects token theft and impersonation*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60008" or rule.description:"*token*" or rule.description:"*impersonat*" or rule.description:"*CreateToken*" or rule.description:"*DuplicateToken*" or rule.description:"*ImpersonateLoggedOnUser*" or rule.description:"*SetThreadToken*" or rule.description:"*AdjustTokenPrivileges*")
```

### Query 44: UAC Bypass Techniques
*Detects User Account Control bypass attempts*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*fodhelper*" or data.win.eventdata.commandLine:"*eventvwr*" or data.win.eventdata.commandLine:"*sdclt*" or data.win.eventdata.commandLine:"*computerdefaults*" or data.win.eventdata.commandLine:"*slui*" or data.win.eventdata.commandLine:"*cmstp*" or data.win.eventdata.commandLine:"*wsreset*" or data.win.eventdata.commandLine:"*DiskCleanup*" or data.win.eventdata.commandLine:"*Bypass-UAC*" or data.win.eventdata.commandLine:"*UACMe*")
```

### Query 45: Windows Named Pipe Impersonation
*Detects named pipe token impersonation attacks*

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60017" or rule.id:"60018") or (data.win.eventdata.pipeName:"*\\pipe\\*" and (rule.description:"*impersonat*" or rule.description:"*privilege*" or rule.description:"*token*"))
```

### Query 46: Kernel Driver Loading
*Detects potentially malicious kernel driver loading*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60006" and (data.win.eventdata.imageLoaded:"*.sys" or data.win.eventdata.signed:"false" or data.win.eventdata.signatureStatus:"Unavailable")
```

### Query 47: Linux Kernel Module Loading
*Detects suspicious kernel module operations*

```
rule.level >= 10 and (rule.groups:"audit" or rule.groups:"sysmon" or rule.groups:"command") and (data.command:"*insmod*" or data.command:"*modprobe*" or data.command:"*rmmod*" or data.command:"*lsmod*" or rule.description:"*kernel*module*" or rule.description:"*kmod*")
```

### Query 48: Windows Privilege Escalation via Services
*Detects service-based privilege escalation*

```
rule.level >= 10 and rule.groups:"sysmon" and data.win.eventdata.image:"*\\services.exe" and (data.win.eventdata.commandLine:"*config*" or data.win.eventdata.commandLine:"*binpath*" or data.win.eventdata.commandLine:"*start*")
```

### Query 49: AlwaysInstallElevated Exploitation
*Detects MSI-based privilege escalation*

```
rule.level >= 10 and rule.groups:"sysmon" and data.win.eventdata.image:"*\\msiexec.exe" and (data.win.eventdata.commandLine:"*/i *" or data.win.eventdata.commandLine:"*/package*" or data.win.eventdata.commandLine:"*/quiet*" or data.win.eventdata.commandLine:"*/qn*")
```

### Query 50: DLL Hijacking for Privilege Escalation
*Detects DLL hijacking in privileged directories*

```
rule.level >= 10 and rule.groups:"sysmon" and rule.id:"60007" and (data.win.eventdata.imageLoaded:"*\\System32\\*" or data.win.eventdata.imageLoaded:"*\\SysWOW64\\*" or data.win.eventdata.imageLoaded:"*\\Windows\\*") and (data.win.eventdata.signed:"false" or data.win.eventdata.signatureStatus:"Unavailable")
```

---

## 6. Defense Evasion

### Query 51: Windows Event Log Clearing
*Detects security log clearing attempts*

```
rule.level >= 12 and (rule.id:"1102" or rule.id:"104" or rule.id:"60116" or rule.description:"*log*clear*" or rule.description:"*audit*log*") or (data.win.eventdata.commandLine:"*wevtutil*cl*" or data.win.eventdata.commandLine:"*Clear-EventLog*" or data.win.eventdata.commandLine:"*Remove-EventLog*" or data.win.eventdata.commandLine:"*Limit-EventLog*size*0*")
```

### Query 52: Linux Log Tampering
*Detects manipulation of Linux log files*

```
rule.level >= 10 and ((rule.groups:"syscheck" and (syscheck.path:"/var/log/*" or syscheck.path:"*/syslog*" or syscheck.path:"*/auth.log*" or syscheck.path:"*/secure*" or syscheck.path:"*/messages*" or syscheck.path:"*/audit/*")) or (data.command:"*rm*/var/log*" or data.command:"*truncate*log*" or data.command:"*shred*log*" or data.command:"*>/var/log*" or data.command:"*echo*>*log*"))
```

### Query 53: Timestomping Detection
*Detects file timestamp manipulation*

```
rule.level >= 7 and ((rule.groups:"sysmon" and rule.id:"60002") or (rule.groups:"syscheck" and rule.description:"*timestamp*") or (data.command:"*touch*-t*" or data.command:"*touch*-d*" or data.command:"*touch*--date*" or data.command:"*SetFileTime*" or data.command:"*timestomp*"))
```

### Query 54: Process Injection Techniques
*Comprehensive process injection detection*

```
rule.level >= 12 and rule.groups:"sysmon" and (rule.id:"60008" or rule.id:"60010") and (rule.description:"*inject*" or rule.description:"*hollow*" or rule.description:"*CreateRemoteThread*" or rule.description:"*QueueUserAPC*" or rule.description:"*SetWindowsHookEx*" or rule.description:"*NtMapViewOfSection*" or rule.description:"*WriteProcessMemory*" or rule.description:"*VirtualAllocEx*")
```

### Query 55: Antivirus/EDR Tampering
*Detects attempts to disable security tools*

```
rule.level >= 12 and (rule.description:"*defender*disable*" or rule.description:"*antivirus*stop*" or rule.description:"*tamper*protection*" or data.win.eventdata.commandLine:"*Set-MpPreference*-Disable*" or data.win.eventdata.commandLine:"*sc*stop*WinDefend*" or data.win.eventdata.commandLine:"*net*stop*" or data.win.eventdata.commandLine:"*Uninstall-WindowsFeature*" or data.win.eventdata.commandLine:"*Remove-WindowsFeature*" or data.win.eventdata.commandLine:"*WMIC*AntiVirusProduct*")
```

### Query 56: File Hiding Techniques
*Detects file hiding and attribute manipulation*

```
rule.level >= 7 and ((rule.groups:"sysmon" or rule.groups:"syscheck") and (data.win.eventdata.commandLine:"*attrib*+h*" or data.win.eventdata.commandLine:"*attrib*+s*" or data.win.eventdata.commandLine:"*attrib*+r*" or rule.description:"*hidden*attribute*" or rule.description:"*system*attribute*")) or (data.command:"*chattr*+i*" or data.command:"*.hidden*")
```

### Query 57: Masquerading Detection
*Detects processes masquerading as legitimate binaries*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.originalFileName:* and not data.win.eventdata.image:"*\\Windows\\*" and not data.win.eventdata.image:"*\\Program Files*") and (data.win.eventdata.originalFileName:"svchost.exe" or data.win.eventdata.originalFileName:"lsass.exe" or data.win.eventdata.originalFileName:"services.exe" or data.win.eventdata.originalFileName:"csrss.exe" or data.win.eventdata.originalFileName:"smss.exe" or data.win.eventdata.originalFileName:"wininit.exe" or data.win.eventdata.originalFileName:"winlogon.exe" or data.win.eventdata.originalFileName:"explorer.exe" or data.win.eventdata.originalFileName:"rundll32.exe")
```

### Query 58: Indicator Removal from Tools
*Detects removal of forensic artifacts*

```
rule.level >= 10 and (data.win.eventdata.commandLine:"*SDelete*" or data.win.eventdata.commandLine:"*cipher*/w*" or data.win.eventdata.commandLine:"*Eraser*" or data.win.eventdata.commandLine:"*BleachBit*" or data.win.eventdata.commandLine:"*CCleaner*" or data.command:"*shred*" or data.command:"*wipe*" or data.command:"*srm*" or data.command:"*secure-delete*")
```

### Query 59: Rootkit Indicators
*Detects rootkit-like behavior*

```
rule.level >= 12 and (rule.groups:"rootkit" or rule.groups:"rootcheck") and (rule.id:"510" or rule.id:"511" or rule.id:"512" or rule.id:"513" or rule.id:"514" or rule.id:"515" or rule.id:"516" or rule.id:"517" or rule.id:"518" or rule.id:"519" or rule.description:"*rootkit*" or rule.description:"*hidden*process*" or rule.description:"*hidden*file*" or rule.description:"*kernel*hook*")
```

### Query 60: Binary Padding/Packing Detection
*Detects packed or padded executables*

```
rule.level >= 7 and rule.groups:"sysmon" and (rule.description:"*packed*" or rule.description:"*UPX*" or rule.description:"*entropy*" or rule.description:"*obfuscat*" or rule.description:"*crypter*" or rule.description:"*packer*")
```

---

## 7. Credential Access & Theft

### Query 61: LSASS Memory Access (Comprehensive)
*Detects all LSASS memory access attempts*

```
rule.level >= 12 and rule.groups:"sysmon" and (rule.id:"60010" or data.win.eventdata.targetImage:"*\\lsass.exe") and not (data.win.eventdata.sourceImage:"*\\MsMpEng.exe" or data.win.eventdata.sourceImage:"*\\csrss.exe" or data.win.eventdata.sourceImage:"*\\wininit.exe" or data.win.eventdata.sourceImage:"*\\svchost.exe")
```

### Query 62: SAM/SYSTEM/SECURITY Hive Access
*Detects access to credential storage hives*

```
rule.level >= 12 and rule.groups:"sysmon" and (data.win.eventdata.targetFilename:"*\\SAM" or data.win.eventdata.targetFilename:"*\\SYSTEM" or data.win.eventdata.targetFilename:"*\\SECURITY" or data.win.eventdata.targetFilename:"*\\NTDS.dit" or data.win.eventdata.commandLine:"*reg*save*SAM*" or data.win.eventdata.commandLine:"*reg*save*SYSTEM*" or data.win.eventdata.commandLine:"*reg*save*SECURITY*" or data.win.eventdata.commandLine:"*ntdsutil*" or data.win.eventdata.commandLine:"*vssadmin*shadow*")
```

### Query 63: Credential Manager Access
*Detects Windows Credential Manager access*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.targetFilename:"*\\Credentials\\*" or data.win.eventdata.targetFilename:"*\\Vault\\*" or data.win.eventdata.commandLine:"*vaultcmd*" or data.win.eventdata.commandLine:"*cmdkey*" or data.win.eventdata.commandLine:"*CredentialManager*" or rule.description:"*credential*manager*")
```

### Query 64: Browser Credential Theft
*Detects access to browser credential stores*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.targetFilename:"*\\Login Data*" or data.win.eventdata.targetFilename:"*\\logins.json*" or data.win.eventdata.targetFilename:"*\\signons.sqlite*" or data.win.eventdata.targetFilename:"*\\cookies.sqlite*" or data.win.eventdata.targetFilename:"*\\Chrome\\User Data\\*" or data.win.eventdata.targetFilename:"*\\Firefox\\Profiles\\*" or data.win.eventdata.targetFilename:"*\\Microsoft\\Edge\\*")
```

### Query 65: Kerberoasting Attack Detection
*Detects service ticket requests with RC4 encryption*

```
rule.level >= 10 and rule.groups:"windows" and (rule.id:"4769") and (data.win.eventdata.ticketEncryptionType:"0x17" or data.win.eventdata.ticketEncryptionType:"0x18")
```

### Query 66: AS-REP Roasting Detection
*Detects AS-REP roasting attacks*

```
rule.level >= 10 and rule.groups:"windows" and rule.id:"4768" and data.win.eventdata.preAuthType:"0"
```

### Query 67: DCSync Attack Detection
*Detects DCSync replication attacks*

```
rule.level >= 12 and rule.groups:"windows" and (rule.id:"4662") and (data.win.eventdata.properties:"*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" or data.win.eventdata.properties:"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" or data.win.eventdata.properties:"*89e95b76-444d-4c62-991a-0facbeda640c*")
```

### Query 68: Linux Shadow File Access
*Detects access to /etc/shadow and related files*

```
rule.level >= 10 and (rule.groups:"syscheck" or rule.groups:"audit") and (syscheck.path:"/etc/shadow" or syscheck.path:"/etc/shadow-" or syscheck.path:"/etc/gshadow" or syscheck.path:"/etc/passwd" or data.command:"*cat*/etc/shadow*" or data.command:"*cat*/etc/passwd*" or data.command:"*unshadow*" or data.command:"*john*")
```

### Query 69: SSH Key Theft Detection
*Detects access to SSH private keys*

```
rule.level >= 10 and (rule.groups:"syscheck" or rule.groups:"audit") and (syscheck.path:"*/.ssh/id_rsa" or syscheck.path:"*/.ssh/id_dsa" or syscheck.path:"*/.ssh/id_ecdsa" or syscheck.path:"*/.ssh/id_ed25519" or syscheck.path:"*/.ssh/authorized_keys" or syscheck.path:"*/.ssh/known_hosts" or data.command:"*cat*id_rsa*" or data.command:"*cat*authorized_keys*")
```

### Query 70: Password Spraying Detection
*Detects password spray attacks (many users, few passwords)*

```
rule.level >= 10 and (rule.groups:"authentication_failed" or rule.groups:"invalid_login") and (rule.id:"5710" or rule.id:"5711" or rule.id:"5712" or rule.id:"60122" or rule.id:"60204" or rule.id:"4625" or rule.id:"4771")
```

---

## 8. Lateral Movement

### Query 71: RDP Lateral Movement (Internal)
*Detects RDP connections from internal sources*

```
rule.level >= 7 and rule.groups:"windows" and (rule.id:"4624" or rule.id:"4625") and data.win.eventdata.logonType:"10" and (data.win.eventdata.ipAddress:"10.*" or data.win.eventdata.ipAddress:"192.168.*" or data.win.eventdata.ipAddress:"172.16.*" or data.win.eventdata.ipAddress:"172.17.*" or data.win.eventdata.ipAddress:"172.18.*" or data.win.eventdata.ipAddress:"172.19.*" or data.win.eventdata.ipAddress:"172.20.*" or data.win.eventdata.ipAddress:"172.21.*" or data.win.eventdata.ipAddress:"172.22.*" or data.win.eventdata.ipAddress:"172.23.*" or data.win.eventdata.ipAddress:"172.24.*" or data.win.eventdata.ipAddress:"172.25.*" or data.win.eventdata.ipAddress:"172.26.*" or data.win.eventdata.ipAddress:"172.27.*" or data.win.eventdata.ipAddress:"172.28.*" or data.win.eventdata.ipAddress:"172.29.*" or data.win.eventdata.ipAddress:"172.30.*" or data.win.eventdata.ipAddress:"172.31.*")
```

### Query 72: SSH Lateral Movement (Internal)
*Detects SSH connections between internal hosts*

```
rule.level >= 5 and rule.groups:"sshd" and rule.groups:"authentication_success" and (data.srcip:"10.*" or data.srcip:"192.168.*" or data.srcip:"172.16.*" or data.srcip:"172.17.*" or data.srcip:"172.18.*" or data.srcip:"172.19.*" or data.srcip:"172.20.*" or data.srcip:"172.21.*" or data.srcip:"172.22.*" or data.srcip:"172.23.*" or data.srcip:"172.24.*" or data.srcip:"172.25.*" or data.srcip:"172.26.*" or data.srcip:"172.27.*" or data.srcip:"172.28.*" or data.srcip:"172.29.*" or data.srcip:"172.30.*" or data.srcip:"172.31.*")
```

### Query 73: Pass-the-Hash Detection
*Detects NTLM authentication with Pass-the-Hash indicators*

```
rule.level >= 12 and rule.groups:"windows" and rule.id:"4624" and (data.win.eventdata.logonType:"9" or data.win.eventdata.logonType:"3") and data.win.eventdata.logonProcessName:"seclogo"
```

### Query 74: Pass-the-Ticket Detection
*Detects Kerberos ticket reuse attacks*

```
rule.level >= 12 and rule.groups:"windows" and (rule.id:"4768" or rule.id:"4769" or rule.id:"4770") and (data.win.eventdata.ticketOptions:"*0x40810000*" or data.win.eventdata.ticketOptions:"*0x40800000*" or data.win.eventdata.ticketOptions:"*0x60810010*")
```

### Query 75: WMI Remote Execution
*Detects WMI-based lateral movement*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\wmiprvse.exe" or data.win.eventdata.parentImage:"*\\wmiprvse.exe" or data.win.eventdata.commandLine:"*wmic*/node:*" or data.win.eventdata.commandLine:"*Invoke-WmiMethod*" or data.win.eventdata.commandLine:"*Get-WmiObject*" or data.win.eventdata.commandLine:"*Set-WmiInstance*")
```

### Query 76: WinRM/PSRemoting Lateral Movement
*Detects PowerShell Remoting usage*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\wsmprovhost.exe" or data.win.eventdata.parentImage:"*\\wsmprovhost.exe" or data.win.eventdata.commandLine:"*Enter-PSSession*" or data.win.eventdata.commandLine:"*Invoke-Command*-ComputerName*" or data.win.eventdata.commandLine:"*New-PSSession*" or data.win.eventdata.commandLine:"*winrs*")
```

### Query 77: SMB Admin Share Access
*Detects access to administrative shares*

```
rule.level >= 7 and rule.groups:"windows" and (rule.id:"5140" or rule.id:"5145") and (data.win.eventdata.shareName:"\\\\*\\ADMIN$" or data.win.eventdata.shareName:"\\\\*\\C$" or data.win.eventdata.shareName:"\\\\*\\IPC$" or data.win.eventdata.shareName:"\\\\*\\D$" or data.win.eventdata.shareName:"\\\\*\\E$")
```

### Query 78: PsExec Execution Detection
*Detects PsExec and similar remote execution tools*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.image:"*\\psexec*" or data.win.eventdata.parentImage:"*\\psexec*" or data.win.eventdata.image:"*\\PSEXESVC.exe" or data.win.eventdata.commandLine:"*psexec*" or data.win.eventdata.commandLine:"*paexec*" or data.win.eventdata.commandLine:"*remcom*" or data.win.eventdata.commandLine:"*csexec*")
```

### Query 79: DCOM Lateral Movement
*Detects DCOM-based remote execution*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.parentImage:"*\\mmc.exe" or data.win.eventdata.parentImage:"*\\excel.exe" or data.win.eventdata.parentImage:"*\\outlook.exe") and (data.win.eventdata.image:"*\\cmd.exe" or data.win.eventdata.image:"*\\powershell.exe" or data.win.eventdata.image:"*\\mshta.exe") and data.win.eventdata.commandLine:"*-Embedding*"
```

### Query 80: Remote Service Creation
*Detects remote service installation for lateral movement*

```
rule.level >= 10 and rule.groups:"windows" and (rule.id:"7045" or rule.id:"7040") and (data.win.eventdata.imagePath:"*\\\\*" or data.win.eventdata.imagePath:"*cmd*" or data.win.eventdata.imagePath:"*powershell*")
```

---

## 9. Collection & Exfiltration

### Query 81: Data Staging (Archive Creation)
*Detects creation of data archives for exfiltration*

```
rule.level >= 7 and (rule.groups:"sysmon" or rule.groups:"syscheck") and (data.win.eventdata.targetFilename:"*.zip" or data.win.eventdata.targetFilename:"*.rar" or data.win.eventdata.targetFilename:"*.7z" or data.win.eventdata.targetFilename:"*.tar" or data.win.eventdata.targetFilename:"*.gz" or data.win.eventdata.targetFilename:"*.cab" or data.win.eventdata.commandLine:"*Compress-Archive*" or data.win.eventdata.commandLine:"*zip*" or data.win.eventdata.commandLine:"*rar*" or data.win.eventdata.commandLine:"*7z*" or data.command:"*tar*czf*" or data.command:"*zip*-r*" or data.command:"*gzip*")
```

### Query 82: Screenshot/Screen Capture Detection
*Detects screen capture activities*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*screenshot*" or data.win.eventdata.commandLine:"*screen*capture*" or data.win.eventdata.commandLine:"*printscreen*" or data.win.eventdata.commandLine:"*Get-Screenshot*" or data.win.eventdata.commandLine:"*[System.Windows.Forms.Screen]*" or data.win.eventdata.commandLine:"*CopyFromScreen*" or data.win.eventdata.commandLine:"*BitBlt*")
```

### Query 83: Keylogger Indicators
*Detects potential keylogging activities*

```
rule.level >= 10 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*GetAsyncKeyState*" or data.win.eventdata.commandLine:"*SetWindowsHookEx*" or data.win.eventdata.commandLine:"*keylog*" or data.win.eventdata.commandLine:"*keystroke*" or data.win.eventdata.commandLine:"*keyboard*hook*" or rule.description:"*keylog*" or rule.description:"*keystroke*")
```

### Query 84: Clipboard Data Access
*Detects clipboard monitoring and theft*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.commandLine:"*Get-Clipboard*" or data.win.eventdata.commandLine:"*[Windows.Forms.Clipboard]*" or data.win.eventdata.commandLine:"*GetClipboardData*" or data.win.eventdata.commandLine:"*OpenClipboard*" or data.win.eventdata.commandLine:"*clip.exe*")
```

### Query 85: Email Collection Detection
*Detects access to email data stores*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.targetFilename:"*.pst" or data.win.eventdata.targetFilename:"*.ost" or data.win.eventdata.targetFilename:"*.msg" or data.win.eventdata.targetFilename:"*.eml" or data.win.eventdata.commandLine:"*New-MailboxExportRequest*" or data.win.eventdata.commandLine:"*Export-Mailbox*" or data.win.eventdata.targetFilename:"*\\Microsoft\\Outlook\\*")
```

### Query 86: DNS Tunneling Detection
*Detects potential DNS exfiltration*

```
rule.level >= 10 and (rule.groups:"dns" or rule.groups:"named" or rule.groups:"network") and (rule.description:"*tunnel*" or rule.description:"*unusually*long*" or rule.description:"*base64*" or rule.description:"*encoded*" or rule.description:"*high*frequency*" or rule.description:"*suspicious*subdomain*")
```

### Query 87: HTTP/HTTPS Data Exfiltration
*Detects potential data exfiltration over HTTP(S)*

```
rule.level >= 7 and (rule.groups:"web" or rule.groups:"network") and (rule.description:"*large*upload*" or rule.description:"*POST*data*" or rule.description:"*exfil*" or rule.description:"*transfer*" or data.url:"*pastebin*" or data.url:"*paste.ee*" or data.url:"*hastebin*" or data.url:"*ghostbin*" or data.url:"*dpaste*" or data.url:"*transfer.sh*" or data.url:"*file.io*" or data.url:"*0x0.st*")
```

### Query 88: Cloud Storage Exfiltration
*Detects uploads to cloud storage services*

```
rule.level >= 7 and (rule.groups:"sysmon" or rule.groups:"network") and (data.url:"*dropbox.com*" or data.url:"*drive.google.com*" or data.url:"*onedrive.live.com*" or data.url:"*icloud.com*" or data.url:"*box.com*" or data.url:"*mega.nz*" or data.url:"*mediafire.com*" or data.url:"*wetransfer.com*" or data.url:"*sendspace.com*" or data.url:"*4shared.com*")
```

### Query 89: FTP/SFTP Data Transfer
*Detects FTP-based data transfers*

```
rule.level >= 7 and (rule.groups:"network" or rule.groups:"sysmon" or rule.groups:"audit") and (data.dstport:"21" or data.dstport:"22" or data.dstport:"990" or data.win.eventdata.commandLine:"*ftp*" or data.win.eventdata.commandLine:"*sftp*" or data.win.eventdata.commandLine:"*scp*" or data.win.eventdata.commandLine:"*winscp*" or data.win.eventdata.commandLine:"*filezilla*" or data.command:"*ftp*" or data.command:"*sftp*" or data.command:"*scp*")
```

### Query 90: USB/Removable Media Exfiltration
*Detects data transfer to removable media*

```
rule.level >= 7 and (rule.groups:"sysmon" or rule.groups:"windows") and (rule.id:"60023" or rule.description:"*removable*" or rule.description:"*USB*" or rule.description:"*external*drive*" or data.win.eventdata.targetFilename:"*:\\*" and not data.win.eventdata.targetFilename:"C:\\*")
```

---

## 10. Command & Control

### Query 91: Beaconing Detection (Regular Intervals)
*Detects C2 beaconing patterns*

```
rule.level >= 7 and (rule.groups:"network" or rule.groups:"firewall" or rule.groups:"proxy") and (rule.description:"*beacon*" or rule.description:"*periodic*" or rule.description:"*interval*" or rule.description:"*heartbeat*" or rule.description:"*callback*") and not (data.dstip:"10.*" or data.dstip:"192.168.*" or data.dstip:"172.16.*" or data.dstip:"172.17.*" or data.dstip:"172.18.*" or data.dstip:"172.19.*" or data.dstip:"172.20.*" or data.dstip:"172.21.*" or data.dstip:"172.22.*" or data.dstip:"172.23.*" or data.dstip:"172.24.*" or data.dstip:"172.25.*" or data.dstip:"172.26.*" or data.dstip:"172.27.*" or data.dstip:"172.28.*" or data.dstip:"172.29.*" or data.dstip:"172.30.*" or data.dstip:"172.31.*")
```

### Query 92: Known C2 Framework Indicators
*Detects known C2 framework patterns*

```
rule.level >= 12 and (rule.description:"*Cobalt Strike*" or rule.description:"*Metasploit*" or rule.description:"*Empire*" or rule.description:"*Covenant*" or rule.description:"*Merlin*" or rule.description:"*PoshC2*" or rule.description:"*Sliver*" or rule.description:"*Brute Ratel*" or rule.description:"*Havoc*" or rule.description:"*Mythic*" or data.win.eventdata.commandLine:"*beacon*" or data.win.eventdata.commandLine:"*meterpreter*" or data.win.eventdata.commandLine:"*payload*")
```

### Query 93: Non-Standard Port Usage for C2
*Detects communication on unusual ports*

```
rule.level >= 7 and (rule.groups:"network" or rule.groups:"firewall") and (data.dstport:"4444" or data.dstport:"5555" or data.dstport:"6666" or data.dstport:"7777" or data.dstport:"8888" or data.dstport:"9999" or data.dstport:"1234" or data.dstport:"31337" or data.dstport:"12345" or data.dstport:"54321" or data.dstport:"1337" or data.dstport:"6667" or data.dstport:"6697" or data.dstport:"8080" or data.dstport:"8443" or data.dstport:"9090" or data.dstport:"9443")
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
```

### Key Wazuh Rule IDs
| Range | Category |
|-------|----------|
| 5xxx | SSH/PAM |
| 31xxx | Web Attacks |
| 60xxx | Windows/Sysmon |
| 510-519 | Rootkit |
| 550-559 | FIM |

---

## Usage Notes

1. **Time Range**: Always set appropriate time range in the Threat Hunting interface
2. **Performance**: Complex queries with wildcards may take longer to execute
3. **Customization**: Modify queries to match your environment's specific agent names, IP ranges, and rule configurations
4. **False Positives**: Some queries may generate false positives - tune based on your baseline
5. **Correlation**: Use multiple queries together to build attack timelines

---

## MITRE ATT&CK Coverage

| Tactic | Queries |
|--------|---------|
| Initial Access | 1-10 |
| Execution | 11-30 |
| Persistence | 31-40 |
| Privilege Escalation | 41-50 |
| Defense Evasion | 51-60 |
| Credential Access | 61-70 |
| Lateral Movement | 71-80 |
| Collection/Exfiltration | 81-90 |
| Command & Control | 91-100 |

---

**Document Version**: 1.0  
**Wazuh Version**: 4.11.2  
**Last Updated**: January 2025
