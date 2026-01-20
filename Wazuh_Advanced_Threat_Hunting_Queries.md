# WAZUH SIEM - Advanced Threat Hunting & Investigation Queries

<img width="2052" height="1125" alt="image" src="https://github.com/user-attachments/assets/c95dccaa-90f8-4f9e-9071-e0427c90e6d1" />

## Version 4.11.2 | 100+ Advanced DQL & Elasticsearch DSL Queries

**For SOC Analysts, Threat Hunters & Incident Responders**

This comprehensive guide provides production-ready queries for deep-level security investigations, threat hunting, and incident response using Wazuh SIEM.

---

## Table of Contents

- [Query Interfaces](#query-interfaces)
- [Section 1: Initial Access & Reconnaissance](#section-1-initial-access--reconnaissance)
- [Section 2: Execution & Command Execution](#section-2-execution--command-execution)
- [Section 3: Persistence Mechanisms](#section-3-persistence-mechanisms)
- [Section 4: Privilege Escalation](#section-4-privilege-escalation)
- [Section 5: Defense Evasion](#section-5-defense-evasion)
- [Section 6: Credential Access](#section-6-credential-access)
- [Section 7: Lateral Movement](#section-7-lateral-movement)
- [Section 8: Collection & Exfiltration](#section-8-collection--exfiltration)
- [Section 9: Command & Control](#section-9-command--control)
- [Section 10: Advanced Analytics & Correlation](#section-10-advanced-analytics--correlation)
- [Section 11: Incident Response Queries](#section-11-incident-response-queries)
- [Quick Reference - Wazuh Rule IDs](#quick-reference---wazuh-rule-ids)
- [DQL vs DSL Syntax Reference](#dql-vs-dsl-syntax-reference)

---

## Query Interfaces

Wazuh 4.11.2 has **three main query interfaces**, each using different syntax:

| Interface | Location | Query Syntax | Use Case |
|-----------|----------|--------------|----------|
| **Threat Hunting / Discover** | Threat Intelligence → Threat Hunting | DQL (Lucene-based) | Security event investigation |
| **WQL Search Bars** | Agents, Rules, MITRE tabs | WQL (Wazuh Query Language) | Filtering dashboard data |
| **Dev Tools** | Indexer Management → Dev Tools | Elasticsearch DSL (JSON) | Advanced/API queries |

### How to Use DQL Queries
1. Navigate to **Threat Intelligence → Threat Hunting**
2. Ensure **DQL** is enabled (toggle ON)
3. Paste the query in the search bar
4. Set your time range and click **Refresh**

### How to Use DSL Queries
1. Navigate to **Indexer Management → Dev Tools**
2. Paste the JSON query
3. Click the **Play** button (▶) to execute

---

## Section 1: Initial Access & Reconnaissance

Detect attackers attempting to gain initial foothold in your environment.

### 1.1 External Scanning & Enumeration Detection

**MITRE ATT&CK: T1595 - Active Scanning, T1046 - Network Service Discovery**

#### DQL: Aggressive Port Scanning from Single Source
*Detects single IP hitting multiple ports across multiple hosts - classic Nmap behavior*

```
rule.level >= 5 and (rule.groups:"scan" or rule.groups:"reconnaissance" or rule.groups:"firewall" or rule.id:"5706" or rule.id:"5707" or rule.id:"5710" or rule.id:"5711") and data.srcip:*
```

#### DSL: Top Scanners with Port Distribution
*Identifies attackers and their scanning patterns - which ports they target most*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "range": { "rule.level": { "gte": 5 } } }
      ],
      "should": [
        { "match": { "rule.groups": "scan" } },
        { "match": { "rule.groups": "reconnaissance" } },
        { "match": { "rule.groups": "firewall" } },
        { "terms": { "rule.id": ["5706", "5707", "5710", "5711", "5712"] } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "scanner_ips": {
      "terms": { "field": "data.srcip", "size": 20 },
      "aggs": {
        "ports_targeted": {
          "terms": { "field": "data.dstport", "size": 50 }
        },
        "hosts_targeted": {
          "cardinality": { "field": "agent.name" }
        },
        "scan_timeline": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "10m" }
        }
      }
    }
  }
}
```

#### DSL: Horizontal Scan Detection (Same Port, Multiple Hosts)
*Detects attacker scanning same service across network - looking for vulnerable services*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-6h" } } },
        { "exists": { "field": "data.srcip" } },
        { "exists": { "field": "data.dstport" } }
      ],
      "should": [
        { "match": { "rule.groups": "firewall" } },
        { "match": { "rule.groups": "scan" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_source_and_port": {
      "composite": {
        "size": 100,
        "sources": [
          { "srcip": { "terms": { "field": "data.srcip" } } },
          { "port": { "terms": { "field": "data.dstport" } } }
        ]
      },
      "aggs": {
        "unique_targets": { "cardinality": { "field": "data.dstip" } },
        "target_list": { "terms": { "field": "data.dstip", "size": 20 } }
      }
    }
  }
}
```

### 1.2 Exploitation & Initial Compromise

**MITRE ATT&CK: T1190 - Exploit Public-Facing Application**

#### DQL: Web Application Exploitation Attempts
*Comprehensive detection of web-based attacks including SQLi, XSS, RCE, LFI/RFI*

```
rule.level >= 7 and (rule.groups:"attack" or rule.groups:"web" or rule.groups:"exploit") and (rule.id:"31101" or rule.id:"31102" or rule.id:"31103" or rule.id:"31104" or rule.id:"31105" or rule.id:"31106" or rule.id:"31107" or rule.id:"31108" or rule.id:"31109" or rule.id:"31110" or rule.id:"31151" or rule.id:"31152" or rule.id:"31153" or rule.id:"31154" or rule.id:"31161" or rule.id:"31162" or rule.id:"31163" or rule.id:"31164" or rule.id:"31165" or rule.id:"31166" or rule.id:"31167" or rule.id:"31168" or rule.id:"31171" or rule.id:"31172" or rule.id:"31173" or rule.id:"31174" or rule.id:"31501" or rule.id:"31502" or rule.id:"31503" or rule.id:"31504" or rule.id:"31505" or rule.id:"31506" or rule.id:"31507" or rule.id:"31508" or rule.id:"31509" or rule.id:"31510" or rule.id:"31511" or rule.id:"31512" or rule.id:"31513" or rule.id:"31514" or rule.id:"31515" or rule.id:"31516" or rule.id:"31517" or rule.id:"31518" or rule.id:"31519" or rule.id:"31520")
```

#### DSL: Attack Pattern Analysis with Payload Extraction
*Deep analysis of exploitation attempts with attacker profiling*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "range": { "rule.level": { "gte": 7 } } }
      ],
      "should": [
        { "match": { "rule.groups": "sql_injection" } },
        { "match": { "rule.groups": "xss" } },
        { "match": { "rule.groups": "attack" } },
        { "match": { "rule.groups": "web_attack" } },
        { "wildcard": { "rule.description": "*injection*" } },
        { "wildcard": { "rule.description": "*traversal*" } },
        { "wildcard": { "rule.description": "*command*execution*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "attack_sources": {
      "terms": { "field": "data.srcip", "size": 30 },
      "aggs": {
        "attack_types": {
          "terms": { "field": "rule.description.keyword", "size": 20 }
        },
        "targeted_endpoints": {
          "terms": { "field": "data.url.keyword", "size": 20 }
        },
        "attack_timeline": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "30m" }
        },
        "success_indicators": {
          "filter": { "range": { "rule.level": { "gte": 10 } } }
        }
      }
    },
    "by_attack_type": {
      "terms": { "field": "rule.groups", "size": 20 }
    },
    "severity_distribution": {
      "histogram": { "field": "rule.level", "interval": 1 }
    }
  }
}
```

#### DQL: SSH/RDP Exploitation & Brute Force
*Detects remote access service attacks*

```
rule.level >= 7 and ((rule.groups:"sshd" and (rule.groups:"authentication_failed" or rule.groups:"invalid_login")) or (rule.groups:"windows" and rule.id:"60122") or rule.id:"5710" or rule.id:"5711" or rule.id:"5712" or rule.id:"5720" or rule.id:"5721" or rule.id:"5722" or rule.id:"5723" or rule.id:"5724" or rule.id:"5725" or rule.id:"5760" or rule.id:"5761" or rule.id:"5762" or rule.id:"5763")
```

### 1.3 Phishing & Social Engineering Indicators

#### DQL: Suspicious Document/Macro Execution
*Detects Office documents spawning suspicious processes*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.parentImage:"*WINWORD.EXE" or data.win.eventdata.parentImage:"*EXCEL.EXE" or data.win.eventdata.parentImage:"*POWERPNT.EXE" or data.win.eventdata.parentImage:"*OUTLOOK.EXE") and (data.win.eventdata.image:"*cmd.exe" or data.win.eventdata.image:"*powershell.exe" or data.win.eventdata.image:"*wscript.exe" or data.win.eventdata.image:"*cscript.exe" or data.win.eventdata.image:"*mshta.exe")
```

#### DSL: Document-Based Attack Analysis
*Tracks suspicious child processes from Office applications*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "match": { "rule.groups": "sysmon" } }
      ],
      "should": [
        { "wildcard": { "data.win.eventdata.parentImage": "*WINWORD*" } },
        { "wildcard": { "data.win.eventdata.parentImage": "*EXCEL*" } },
        { "wildcard": { "data.win.eventdata.parentImage": "*POWERPNT*" } },
        { "wildcard": { "data.win.eventdata.parentImage": "*OUTLOOK*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_parent": {
      "terms": { "field": "data.win.eventdata.parentImage", "size": 10 },
      "aggs": {
        "child_processes": {
          "terms": { "field": "data.win.eventdata.image", "size": 20 }
        },
        "command_lines": {
          "terms": { "field": "data.win.eventdata.commandLine.keyword", "size": 20 }
        },
        "affected_users": {
          "terms": { "field": "data.win.eventdata.user", "size": 20 }
        }
      }
    }
  }
}
```

---

## Section 2: Execution & Command Execution

Detect malicious code execution and suspicious command-line activity.

### 2.1 Suspicious Process Execution

**MITRE ATT&CK: T1059 - Command and Scripting Interpreter**

#### DQL: Suspicious Process Creation (Windows)
*Detects execution of commonly abused binaries and suspicious patterns*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.originalFileName:"cmd.exe" or data.win.eventdata.originalFileName:"powershell.exe" or data.win.eventdata.originalFileName:"wscript.exe" or data.win.eventdata.originalFileName:"cscript.exe" or data.win.eventdata.originalFileName:"mshta.exe" or data.win.eventdata.originalFileName:"regsvr32.exe" or data.win.eventdata.originalFileName:"rundll32.exe" or data.win.eventdata.originalFileName:"certutil.exe" or data.win.eventdata.originalFileName:"bitsadmin.exe")
```

#### DQL: Suspicious Linux Process Execution
*Detects suspicious command execution on Linux systems*

```
rule.level >= 7 and (rule.groups:"sysmon" or rule.groups:"audit") and (data.command:"*wget*" or data.command:"*curl*" or data.command:"*nc *" or data.command:"*netcat*" or data.command:"*python*-c*" or data.command:"*perl*-e*" or data.command:"*ruby*-e*" or data.command:"*php*-r*" or data.command:"*bash*-i*" or data.command:"*/dev/tcp/*" or data.command:"*/dev/udp/*")
```

#### DSL: Process Execution Chain Analysis
*Tracks parent-child process relationships to identify attack chains*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "match": { "rule.groups": "sysmon" } },
        { "exists": { "field": "data.win.eventdata.parentImage" } }
      ]
    }
  },
  "aggs": {
    "process_chains": {
      "terms": { "field": "data.win.eventdata.parentImage", "size": 30 },
      "aggs": {
        "child_processes": {
          "terms": { "field": "data.win.eventdata.image", "size": 20 },
          "aggs": {
            "command_lines": {
              "terms": { "field": "data.win.eventdata.commandLine.keyword", "size": 10 }
            },
            "users": {
              "terms": { "field": "data.win.eventdata.user", "size": 5 }
            }
          }
        },
        "suspicious_children": {
          "filter": {
            "bool": {
              "should": [
                { "wildcard": { "data.win.eventdata.image": "*powershell*" } },
                { "wildcard": { "data.win.eventdata.image": "*cmd.exe*" } },
                { "wildcard": { "data.win.eventdata.image": "*wscript*" } },
                { "wildcard": { "data.win.eventdata.image": "*certutil*" } },
                { "wildcard": { "data.win.eventdata.image": "*mshta*" } }
              ]
            }
          }
        }
      }
    }
  }
}
```

### 2.2 PowerShell Attack Detection

**MITRE ATT&CK: T1059.001 - PowerShell**

#### DQL: Malicious PowerShell Indicators
*Detects encoded commands, download cradles, and evasion techniques*

```
rule.level >= 7 and (rule.groups:"powershell" or rule.groups:"sysmon") and (rule.description:"*encoded*" or rule.description:"*base64*" or rule.description:"*downloadstring*" or rule.description:"*invoke-expression*" or rule.description:"*iex*" or rule.description:"*bypass*" or rule.description:"*hidden*" or rule.description:"*noprofile*" or rule.description:"*executionpolicy*")
```

#### DSL: PowerShell Command Analysis with Encoding Detection
*Deep analysis of PowerShell usage patterns and suspicious commands*

```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } }
      ],
      "should": [
        { "match": { "rule.groups": "powershell" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*powershell*" } }
      ],
      "minimum_should_match": 1,
      "filter": [
        {
          "bool": {
            "should": [
              { "wildcard": { "data.win.eventdata.commandLine": "*-enc*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*-encoded*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*frombase64*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*downloadstring*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*invoke-webrequest*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*iwr*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*invoke-expression*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*iex*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*bypass*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*hidden*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*-nop*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*-w hidden*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*new-object*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*webclient*" } },
              { "wildcard": { "data.win.eventdata.commandLine": "*reflection.assembly*" } }
            ]
          }
        }
      ]
    }
  },
  "sort": [{ "@timestamp": { "order": "desc" } }],
  "_source": ["@timestamp", "agent.name", "data.win.eventdata.commandLine", "data.win.eventdata.user", "data.win.eventdata.parentImage", "rule.description"]
}
```

#### DSL: PowerShell Script Block Logging Analysis
*Analyzes PowerShell script content for malicious patterns*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "match": { "rule.groups": "powershell" } }
      ]
    }
  },
  "aggs": {
    "by_host": {
      "terms": { "field": "agent.name", "size": 30 },
      "aggs": {
        "suspicious_commands": {
          "filters": {
            "filters": {
              "encoded_commands": { "wildcard": { "data.win.eventdata.commandLine": "*-enc*" } },
              "download_cradles": { "wildcard": { "data.win.eventdata.commandLine": "*downloadstring*" } },
              "web_requests": { "wildcard": { "data.win.eventdata.commandLine": "*invoke-webrequest*" } },
              "hidden_execution": { "wildcard": { "data.win.eventdata.commandLine": "*-w hidden*" } },
              "bypass_execution": { "wildcard": { "data.win.eventdata.commandLine": "*bypass*" } }
            }
          }
        },
        "users": {
          "terms": { "field": "data.win.eventdata.user", "size": 10 }
        },
        "timeline": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" }
        }
      }
    }
  }
}
```

### 2.3 Living Off The Land (LOLBins)

**MITRE ATT&CK: T1218 - System Binary Proxy Execution**

#### DQL: LOLBin Execution Detection
*Detects abuse of legitimate Windows binaries for malicious purposes*

```
rule.level >= 5 and rule.groups:"sysmon" and (data.win.eventdata.originalFileName:"certutil.exe" or data.win.eventdata.originalFileName:"bitsadmin.exe" or data.win.eventdata.originalFileName:"mshta.exe" or data.win.eventdata.originalFileName:"regsvr32.exe" or data.win.eventdata.originalFileName:"rundll32.exe" or data.win.eventdata.originalFileName:"msiexec.exe" or data.win.eventdata.originalFileName:"installutil.exe" or data.win.eventdata.originalFileName:"regasm.exe" or data.win.eventdata.originalFileName:"regsvcs.exe" or data.win.eventdata.originalFileName:"msconfig.exe" or data.win.eventdata.originalFileName:"msbuild.exe" or data.win.eventdata.originalFileName:"cmstp.exe" or data.win.eventdata.originalFileName:"wmic.exe" or data.win.eventdata.originalFileName:"forfiles.exe" or data.win.eventdata.originalFileName:"pcalua.exe")
```

#### DSL: LOLBin Usage Analysis with Command Context
*Comprehensive LOLBin monitoring with command-line analysis*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "match": { "rule.groups": "sysmon" } }
      ],
      "should": [
        { "wildcard": { "data.win.eventdata.image": "*\\\\certutil.exe" } },
        { "wildcard": { "data.win.eventdata.image": "*\\\\bitsadmin.exe" } },
        { "wildcard": { "data.win.eventdata.image": "*\\\\mshta.exe" } },
        { "wildcard": { "data.win.eventdata.image": "*\\\\regsvr32.exe" } },
        { "wildcard": { "data.win.eventdata.image": "*\\\\rundll32.exe" } },
        { "wildcard": { "data.win.eventdata.image": "*\\\\msiexec.exe" } },
        { "wildcard": { "data.win.eventdata.image": "*\\\\wmic.exe" } },
        { "wildcard": { "data.win.eventdata.image": "*\\\\msbuild.exe" } },
        { "wildcard": { "data.win.eventdata.image": "*\\\\cmstp.exe" } },
        { "wildcard": { "data.win.eventdata.image": "*\\\\forfiles.exe" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_lolbin": {
      "terms": { "field": "data.win.eventdata.image", "size": 20 },
      "aggs": {
        "command_lines": {
          "terms": { "field": "data.win.eventdata.commandLine.keyword", "size": 30 }
        },
        "parent_processes": {
          "terms": { "field": "data.win.eventdata.parentImage", "size": 10 }
        },
        "users": {
          "terms": { "field": "data.win.eventdata.user", "size": 10 }
        },
        "hosts": {
          "terms": { "field": "agent.name", "size": 20 }
        },
        "suspicious_downloads": {
          "filter": {
            "bool": {
              "should": [
                { "wildcard": { "data.win.eventdata.commandLine": "*http*" } },
                { "wildcard": { "data.win.eventdata.commandLine": "*ftp*" } },
                { "wildcard": { "data.win.eventdata.commandLine": "*urlcache*" } },
                { "wildcard": { "data.win.eventdata.commandLine": "*decode*" } }
              ]
            }
          }
        }
      }
    }
  }
}
```

### 2.4 Script-Based Attacks

#### DQL: WScript/CScript Execution
*Detects Windows Script Host abuse*

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.image:"*wscript.exe" or data.win.eventdata.image:"*cscript.exe") and (data.win.eventdata.commandLine:"*.vbs*" or data.win.eventdata.commandLine:"*.js*" or data.win.eventdata.commandLine:"*.jse*" or data.win.eventdata.commandLine:"*.vbe*" or data.win.eventdata.commandLine:"*.wsf*")
```

#### DQL: Bash/Shell Script Execution (Linux)
*Detects suspicious shell script execution*

```
rule.level >= 7 and (rule.groups:"audit" or rule.groups:"sysmon") and (data.command:"*bash*-c*" or data.command:"*sh*-c*" or data.command:"*base64*-d*" or data.command:"*eval*" or data.command:"*exec*")
```

---

## Section 3: Persistence Mechanisms

Detect attackers establishing persistent access to compromised systems.

### 3.1 Scheduled Tasks & Cron Jobs

**MITRE ATT&CK: T1053 - Scheduled Task/Job**

#### DQL: Suspicious Scheduled Task Creation
*Detects creation of scheduled tasks that may indicate persistence*

```
rule.level >= 7 and ((rule.groups:"sysmon" and rule.id:"60103") or (rule.groups:"windows" and (rule.id:"60106" or rule.id:"60107")) or rule.description:"*scheduled*task*" or rule.description:"*schtasks*")
```

#### DSL: Scheduled Task Analysis with Suspicious Indicators

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } }
      ],
      "should": [
        { "wildcard": { "rule.description": "*scheduled*task*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*schtasks*" } },
        { "match": { "rule.id": "60103" } },
        { "match": { "rule.id": "60106" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_host": {
      "terms": { "field": "agent.name", "size": 30 },
      "aggs": {
        "task_details": {
          "terms": { "field": "data.win.eventdata.taskName.keyword", "size": 20 }
        },
        "suspicious_tasks": {
          "filter": {
            "bool": {
              "should": [
                { "wildcard": { "data.win.eventdata.commandLine": "*powershell*" } },
                { "wildcard": { "data.win.eventdata.commandLine": "*cmd*" } },
                { "wildcard": { "data.win.eventdata.commandLine": "*http*" } },
                { "wildcard": { "data.win.eventdata.commandLine": "*temp*" } },
                { "wildcard": { "data.win.eventdata.commandLine": "*appdata*" } }
              ]
            }
          }
        }
      }
    }
  }
}
```

#### DQL: Linux Cron Job Modifications
*Detects changes to cron configuration*

```
rule.level >= 7 and rule.groups:"syscheck" and (syscheck.path:"*/cron*" or syscheck.path:"*/crontab*" or syscheck.path:"/etc/cron.d/*" or syscheck.path:"/etc/cron.daily/*" or syscheck.path:"/etc/cron.hourly/*" or syscheck.path:"/var/spool/cron/*")
```

#### DSL: Cron Job Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } },
        { "match": { "rule.groups": "syscheck" } }
      ],
      "should": [
        { "wildcard": { "syscheck.path": "*cron*" } },
        { "wildcard": { "syscheck.path": "*crontab*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "sort": [{ "@timestamp": { "order": "desc" } }],
  "_source": ["@timestamp", "agent.name", "syscheck.path", "syscheck.event", "syscheck.diff", "rule.description"]
}
```

### 3.2 Registry-Based Persistence (Windows)

**MITRE ATT&CK: T1547.001 - Registry Run Keys / Startup Folder**

#### DQL: Registry Run Key Modifications
*Detects modifications to common persistence registry locations*

```
rule.level >= 7 and rule.groups:"sysmon" and (rule.id:"60004" or rule.id:"60014") and (data.win.eventdata.targetObject:"*\\\\Run\\\\*" or data.win.eventdata.targetObject:"*\\\\RunOnce\\\\*" or data.win.eventdata.targetObject:"*\\\\RunServices\\\\*" or data.win.eventdata.targetObject:"*\\\\Policies\\\\Explorer\\\\Run*" or data.win.eventdata.targetObject:"*\\\\CurrentVersion\\\\Windows\\\\Load*" or data.win.eventdata.targetObject:"*\\\\CurrentVersion\\\\Winlogon*")
```

#### DSL: Registry Persistence Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } },
        { "match": { "rule.groups": "sysmon" } }
      ],
      "should": [
        { "wildcard": { "data.win.eventdata.targetObject": "*\\\\Run\\\\*" } },
        { "wildcard": { "data.win.eventdata.targetObject": "*\\\\RunOnce\\\\*" } },
        { "wildcard": { "data.win.eventdata.targetObject": "*\\\\Services\\\\*" } },
        { "wildcard": { "data.win.eventdata.targetObject": "*\\\\Winlogon\\\\*" } },
        { "wildcard": { "data.win.eventdata.targetObject": "*\\\\Explorer\\\\Shell*" } },
        { "wildcard": { "data.win.eventdata.targetObject": "*\\\\Image File Execution*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_registry_path": {
      "terms": { "field": "data.win.eventdata.targetObject.keyword", "size": 50 },
      "aggs": {
        "values_set": {
          "terms": { "field": "data.win.eventdata.details.keyword", "size": 20 }
        },
        "modifying_processes": {
          "terms": { "field": "data.win.eventdata.image", "size": 10 }
        },
        "affected_hosts": {
          "terms": { "field": "agent.name", "size": 20 }
        }
      }
    }
  }
}
```

### 3.3 Service Persistence

**MITRE ATT&CK: T1543.003 - Windows Service**

#### DQL: Suspicious Service Installation
*Detects new services that may indicate persistence*

```
rule.level >= 7 and ((rule.groups:"windows" and (rule.id:"60009" or rule.id:"60010" or rule.id:"60011")) or (rule.groups:"sysmon" and rule.id:"60006") or rule.description:"*service*installed*" or rule.description:"*service*created*")
```

#### DSL: Service Analysis with Anomaly Detection

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } }
      ],
      "should": [
        { "wildcard": { "rule.description": "*service*install*" } },
        { "wildcard": { "rule.description": "*service*creat*" } },
        { "terms": { "rule.id": ["60009", "60010", "60011", "7045"] } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_host": {
      "terms": { "field": "agent.name", "size": 30 },
      "aggs": {
        "services": {
          "terms": { "field": "data.win.system.serviceName.keyword", "size": 30 }
        },
        "service_paths": {
          "terms": { "field": "data.win.eventdata.imagePath.keyword", "size": 30 }
        },
        "suspicious_paths": {
          "filter": {
            "bool": {
              "should": [
                { "wildcard": { "data.win.eventdata.imagePath": "*temp*" } },
                { "wildcard": { "data.win.eventdata.imagePath": "*appdata*" } },
                { "wildcard": { "data.win.eventdata.imagePath": "*public*" } },
                { "wildcard": { "data.win.eventdata.imagePath": "*programdata*" } },
                { "wildcard": { "data.win.eventdata.imagePath": "*.ps1*" } },
                { "wildcard": { "data.win.eventdata.imagePath": "*powershell*" } }
              ]
            }
          }
        }
      }
    }
  }
}
```

### 3.4 Startup Items & Autorun

#### DQL: Startup Folder Modifications
*Detects files added to startup folders*

```
rule.level >= 7 and rule.groups:"syscheck" and (syscheck.path:"*\\\\Start Menu\\\\Programs\\\\Startup\\\\*" or syscheck.path:"*\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\*")
```

#### DQL: Linux Init Script Modifications
*Detects changes to system startup scripts*

```
rule.level >= 7 and rule.groups:"syscheck" and (syscheck.path:"/etc/init.d/*" or syscheck.path:"/etc/rc*.d/*" or syscheck.path:"/etc/systemd/system/*" or syscheck.path:"/lib/systemd/system/*" or syscheck.path:"~/.bashrc" or syscheck.path:"~/.bash_profile" or syscheck.path:"/etc/profile" or syscheck.path:"/etc/profile.d/*")
```

---

## Section 4: Privilege Escalation

Detect attempts to gain elevated privileges on compromised systems.

### 4.1 Sudo & Su Abuse (Linux)

**MITRE ATT&CK: T1548.003 - Sudo and Sudo Caching**

#### DQL: Sudo Abuse and Privilege Escalation
*Detects suspicious sudo usage patterns*

```
rule.level >= 7 and rule.groups:"sudo" and (rule.id:"5401" or rule.id:"5402" or rule.id:"5403" or rule.id:"5404" or rule.id:"5405" or rule.id:"5406" or rule.id:"5407" or rule.id:"5408" or rule.description:"*sudo*" or rule.description:"*root*")
```

#### DSL: Sudo Activity Analysis with Anomaly Detection

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "match": { "rule.groups": "sudo" } }
      ]
    }
  },
  "aggs": {
    "by_user": {
      "terms": { "field": "data.srcuser", "size": 30 },
      "aggs": {
        "commands_run": {
          "terms": { "field": "data.command.keyword", "size": 50 }
        },
        "target_users": {
          "terms": { "field": "data.dstuser", "size": 10 }
        },
        "source_hosts": {
          "terms": { "field": "agent.name", "size": 20 }
        },
        "hourly_distribution": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" }
        },
        "failed_attempts": {
          "filter": { "match": { "rule.groups": "authentication_failed" } }
        },
        "suspicious_commands": {
          "filter": {
            "bool": {
              "should": [
                { "wildcard": { "data.command": "*chmod*777*" } },
                { "wildcard": { "data.command": "*passwd*" } },
                { "wildcard": { "data.command": "*shadow*" } },
                { "wildcard": { "data.command": "*sudoers*" } },
                { "wildcard": { "data.command": "*visudo*" } },
                { "wildcard": { "data.command": "*/bin/bash*" } },
                { "wildcard": { "data.command": "*/bin/sh*" } }
              ]
            }
          }
        }
      }
    }
  }
}
```

### 4.2 Token Manipulation (Windows)

**MITRE ATT&CK: T1134 - Access Token Manipulation**

#### DQL: Token Manipulation Detection

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60008" or rule.description:"*token*" or rule.description:"*impersonat*" or rule.description:"*privilege*escalat*")
```

#### DSL: Token Manipulation Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "match": { "rule.groups": "sysmon" } }
      ],
      "should": [
        { "wildcard": { "rule.description": "*token*" } },
        { "wildcard": { "rule.description": "*impersonat*" } },
        { "match": { "rule.id": "60008" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_process": {
      "terms": { "field": "data.win.eventdata.sourceImage", "size": 20 },
      "aggs": {
        "target_processes": {
          "terms": { "field": "data.win.eventdata.targetImage", "size": 20 }
        },
        "affected_hosts": {
          "terms": { "field": "agent.name", "size": 20 }
        }
      }
    }
  }
}
```

### 4.3 SUID/SGID Exploitation (Linux)

**MITRE ATT&CK: T1548.001 - Setuid and Setgid**

#### DQL: SUID Binary Monitoring
*Detects new SUID/SGID binaries and modifications*

```
rule.level >= 10 and rule.groups:"syscheck" and (rule.description:"*SUID*" or rule.description:"*SGID*" or rule.description:"*setuid*" or rule.description:"*setgid*" or syscheck.perm_after:"*s*")
```

#### DSL: SUID/SGID File Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } },
        { "match": { "rule.groups": "syscheck" } }
      ],
      "should": [
        { "wildcard": { "rule.description": "*SUID*" } },
        { "wildcard": { "rule.description": "*SGID*" } },
        { "wildcard": { "syscheck.perm_after": "*s*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "sort": [{ "@timestamp": { "order": "desc" } }],
  "_source": ["@timestamp", "agent.name", "syscheck.path", "syscheck.perm_before", "syscheck.perm_after", "syscheck.uname_after", "syscheck.gname_after", "rule.description"]
}
```

### 4.4 Kernel Exploits & Capabilities

#### DQL: Kernel Module Loading
*Detects suspicious kernel module activity*

```
rule.level >= 10 and (rule.groups:"audit" or rule.groups:"sysmon") and (rule.description:"*kernel*module*" or rule.description:"*insmod*" or rule.description:"*modprobe*" or data.command:"*insmod*" or data.command:"*modprobe*")
```

#### DQL: Linux Capabilities Abuse

```
rule.level >= 7 and (rule.groups:"audit" or rule.groups:"syscheck") and (rule.description:"*capability*" or rule.description:"*setcap*" or data.command:"*setcap*")
```

---

## Section 5: Defense Evasion

Detect attackers attempting to avoid detection and security controls.

### 5.1 Log Tampering & Evidence Destruction

**MITRE ATT&CK: T1070 - Indicator Removal on Host**

#### DQL: Log Clearing Detection
*Detects attempts to clear security logs*

```
rule.level >= 10 and ((rule.groups:"windows" and (rule.id:"60116" or rule.id:"1102")) or rule.description:"*log*clear*" or rule.description:"*event*log*" or rule.description:"*audit*log*delete*")
```

#### DSL: Log Tampering Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } }
      ],
      "should": [
        { "wildcard": { "rule.description": "*log*clear*" } },
        { "wildcard": { "rule.description": "*log*delet*" } },
        { "wildcard": { "rule.description": "*audit*" } },
        { "match": { "rule.id": "1102" } },
        { "match": { "rule.id": "60116" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*wevtutil*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*Clear-EventLog*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_host": {
      "terms": { "field": "agent.name", "size": 30 },
      "aggs": {
        "clearing_events": {
          "terms": { "field": "rule.description.keyword", "size": 20 }
        },
        "users_responsible": {
          "terms": { "field": "data.win.eventdata.subjectUserName", "size": 10 }
        },
        "timeline": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "1d" }
        }
      }
    }
  }
}
```

#### DQL: Linux Log Tampering

```
rule.level >= 10 and ((rule.groups:"syscheck" and (syscheck.path:"/var/log/*" or syscheck.path:"*/syslog*" or syscheck.path:"*/auth.log*" or syscheck.path:"*/secure*")) or (data.command:"*rm*/var/log*" or data.command:"*truncate*" or data.command:"*shred*"))
```

### 5.2 Security Tool Disabling

**MITRE ATT&CK: T1562 - Impair Defenses**

#### DQL: Security Software Tampering
*Detects attempts to disable security tools*

```
rule.level >= 10 and (rule.description:"*antivirus*" or rule.description:"*defender*" or rule.description:"*firewall*disable*" or rule.description:"*security*service*stop*" or (rule.groups:"sysmon" and (data.win.eventdata.targetFilename:"*defender*" or data.win.eventdata.targetFilename:"*antivirus*")))
```

#### DSL: Security Tool Status Monitoring

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } }
      ],
      "should": [
        { "wildcard": { "rule.description": "*defender*" } },
        { "wildcard": { "rule.description": "*antivirus*" } },
        { "wildcard": { "rule.description": "*firewall*" } },
        { "wildcard": { "rule.description": "*security*center*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*stop*MpsSvc*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*disable*realtime*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*Set-MpPreference*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_action": {
      "terms": { "field": "rule.description.keyword", "size": 30 }
    },
    "by_host": {
      "terms": { "field": "agent.name", "size": 30 }
    },
    "timeline": {
      "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" }
    }
  }
}
```

### 5.3 Timestomping Detection

**MITRE ATT&CK: T1070.006 - Timestomp**

#### DQL: File Timestamp Manipulation

```
rule.level >= 7 and rule.groups:"syscheck" and (rule.description:"*timestamp*" or (syscheck.mtime_after:* and syscheck.mtime_before:*))
```

#### DQL: Touch Command Usage (Linux)

```
rule.level >= 5 and (rule.groups:"audit" or rule.groups:"sysmon") and (data.command:"*touch*-t*" or data.command:"*touch*-d*" or data.command:"*touch*--date*")
```

### 5.4 Process Injection

**MITRE ATT&CK: T1055 - Process Injection**

#### DQL: Process Injection Detection

```
rule.level >= 10 and rule.groups:"sysmon" and (rule.id:"60008" or rule.description:"*inject*" or rule.description:"*hollowing*" or rule.description:"*CreateRemoteThread*")
```

#### DSL: Process Injection Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "match": { "rule.groups": "sysmon" } }
      ],
      "should": [
        { "match": { "rule.id": "60008" } },
        { "wildcard": { "rule.description": "*inject*" } },
        { "wildcard": { "rule.description": "*CreateRemoteThread*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_source_process": {
      "terms": { "field": "data.win.eventdata.sourceImage", "size": 20 },
      "aggs": {
        "target_processes": {
          "terms": { "field": "data.win.eventdata.targetImage", "size": 20 }
        },
        "affected_hosts": {
          "terms": { "field": "agent.name", "size": 20 }
        }
      }
    }
  }
}
```

---

## Section 6: Credential Access

Detect credential theft and authentication attacks.

### 6.1 Credential Dumping

**MITRE ATT&CK: T1003 - OS Credential Dumping**

#### DQL: LSASS Memory Access
*Detects processes accessing LSASS - common credential dumping technique*

```
rule.level >= 12 and rule.groups:"sysmon" and (rule.id:"60010" or data.win.eventdata.targetImage:"*lsass.exe" or rule.description:"*lsass*" or rule.description:"*credential*dump*" or rule.description:"*mimikatz*")
```

#### DSL: Credential Access Pattern Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } }
      ],
      "should": [
        { "wildcard": { "data.win.eventdata.targetImage": "*lsass*" } },
        { "wildcard": { "rule.description": "*credential*" } },
        { "wildcard": { "rule.description": "*password*dump*" } },
        { "wildcard": { "rule.description": "*mimikatz*" } },
        { "wildcard": { "rule.description": "*secretsdump*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*sekurlsa*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*lsadump*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_source_process": {
      "terms": { "field": "data.win.eventdata.sourceImage", "size": 20 },
      "aggs": {
        "target_processes": {
          "terms": { "field": "data.win.eventdata.targetImage", "size": 10 }
        },
        "affected_hosts": {
          "terms": { "field": "agent.name", "size": 20 }
        }
      }
    },
    "by_host": {
      "terms": { "field": "agent.name", "size": 30 }
    }
  }
}
```

#### DQL: SAM Database Access

```
rule.level >= 12 and rule.groups:"sysmon" and (data.win.eventdata.targetFilename:"*\\\\SAM" or data.win.eventdata.targetFilename:"*\\\\SYSTEM" or data.win.eventdata.targetFilename:"*\\\\SECURITY" or data.win.eventdata.commandLine:"*reg*save*SAM*" or data.win.eventdata.commandLine:"*reg*save*SYSTEM*")
```

#### DQL: /etc/shadow Access (Linux)

```
rule.level >= 10 and (rule.groups:"syscheck" or rule.groups:"audit") and (syscheck.path:"/etc/shadow" or data.command:"*/etc/shadow*" or rule.description:"*shadow*")
```

### 6.2 Brute Force Analysis

**MITRE ATT&CK: T1110 - Brute Force**

#### DQL: Advanced Brute Force Detection
*Detects distributed and targeted brute force attacks*

```
rule.level >= 10 and (rule.groups:"authentication_failed" or rule.groups:"invalid_login") and (rule.id:"5710" or rule.id:"5711" or rule.id:"5712" or rule.id:"5720" or rule.id:"5758" or rule.id:"5759" or rule.id:"5760" or rule.id:"5761" or rule.id:"5762" or rule.id:"5763" or rule.id:"60122" or rule.id:"60204")
```

#### DSL: Brute Force Pattern Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ],
      "should": [
        { "match": { "rule.groups": "authentication_failed" } },
        { "match": { "rule.groups": "invalid_login" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": { "field": "data.srcip", "size": 50 },
      "aggs": {
        "targeted_users": {
          "terms": { "field": "data.dstuser", "size": 30 }
        },
        "targeted_hosts": {
          "terms": { "field": "agent.name", "size": 20 }
        },
        "attempt_timeline": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "10m" }
        },
        "total_attempts": { "value_count": { "field": "rule.id" } },
        "unique_users_targeted": { "cardinality": { "field": "data.dstuser" } },
        "attack_duration": {
          "stats": { "field": "@timestamp" }
        }
      }
    },
    "password_spray_detection": {
      "terms": { "field": "data.dstuser", "size": 100 },
      "aggs": {
        "source_ips": { "cardinality": { "field": "data.srcip" } }
      }
    }
  }
}
```

### 6.3 Kerberos Attacks

**MITRE ATT&CK: T1558 - Steal or Forge Kerberos Tickets**

#### DQL: Kerberoasting Detection

```
rule.level >= 10 and rule.groups:"windows" and (rule.id:"4769" or rule.id:"4768" or rule.id:"4771") and data.win.eventdata.ticketEncryptionType:"0x17"
```

#### DSL: Kerberos Attack Pattern Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "terms": { "rule.id": ["4768", "4769", "4770", "4771", "4772", "4773"] } }
      ]
    }
  },
  "aggs": {
    "by_encryption_type": {
      "terms": { "field": "data.win.eventdata.ticketEncryptionType", "size": 20 }
    },
    "by_service_name": {
      "terms": { "field": "data.win.eventdata.serviceName", "size": 50 },
      "aggs": {
        "requesters": {
          "terms": { "field": "data.win.eventdata.targetUserName", "size": 20 }
        }
      }
    },
    "anomalous_requests": {
      "filter": {
        "term": { "data.win.eventdata.ticketEncryptionType": "0x17" }
      },
      "aggs": {
        "by_user": {
          "terms": { "field": "data.win.eventdata.targetUserName", "size": 30 }
        }
      }
    }
  }
}
```

#### DQL: Golden/Silver Ticket Detection

```
rule.level >= 12 and rule.groups:"windows" and (rule.id:"4768" or rule.id:"4769") and (data.win.eventdata.ticketOptions:"*0x40810000*" or data.win.eventdata.serviceName:"krbtgt")
```

---

## Section 7: Lateral Movement

Detect attackers moving through the network to access additional systems.

### 7.1 RDP Lateral Movement

**MITRE ATT&CK: T1021.001 - Remote Desktop Protocol**

#### DQL: Suspicious RDP Activity

```
rule.level >= 7 and rule.groups:"windows" and (rule.id:"60019" or rule.id:"60020" or rule.id:"60021" or rule.id:"4624" or rule.id:"4625") and data.win.eventdata.logonType:"10"
```

#### DSL: RDP Session Analysis with Anomaly Detection

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "match": { "rule.groups": "windows" } },
        { "term": { "data.win.eventdata.logonType": "10" } }
      ]
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": { "field": "data.win.eventdata.ipAddress", "size": 30 },
      "aggs": {
        "destination_hosts": {
          "terms": { "field": "agent.name", "size": 20 }
        },
        "users_used": {
          "terms": { "field": "data.win.eventdata.targetUserName", "size": 20 }
        },
        "session_times": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" }
        },
        "unique_destinations": {
          "cardinality": { "field": "agent.name" }
        }
      }
    },
    "internal_rdp": {
      "filter": {
        "bool": {
          "should": [
            { "prefix": { "data.win.eventdata.ipAddress": "10." } },
            { "prefix": { "data.win.eventdata.ipAddress": "192.168." } },
            { "prefix": { "data.win.eventdata.ipAddress": "172.16." } }
          ]
        }
      },
      "aggs": {
        "by_source": {
          "terms": { "field": "data.win.eventdata.ipAddress", "size": 30 }
        }
      }
    }
  }
}
```

### 7.2 SSH Lateral Movement

**MITRE ATT&CK: T1021.004 - SSH**

#### DQL: Internal SSH Movement
*Detects SSH connections between internal systems*

```
rule.level >= 5 and rule.groups:"sshd" and rule.groups:"authentication_success" and (data.srcip:"10.*" or data.srcip:"192.168.*" or data.srcip:"172.16.*" or data.srcip:"172.17.*" or data.srcip:"172.18.*" or data.srcip:"172.19.*" or data.srcip:"172.20.*" or data.srcip:"172.21.*" or data.srcip:"172.22.*" or data.srcip:"172.23.*" or data.srcip:"172.24.*" or data.srcip:"172.25.*" or data.srcip:"172.26.*" or data.srcip:"172.27.*" or data.srcip:"172.28.*" or data.srcip:"172.29.*" or data.srcip:"172.30.*" or data.srcip:"172.31.*")
```

#### DSL: SSH Lateral Movement Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "match": { "rule.groups": "sshd" } },
        { "match": { "rule.groups": "authentication_success" } }
      ],
      "should": [
        { "prefix": { "data.srcip": "10." } },
        { "prefix": { "data.srcip": "192.168." } },
        { "prefix": { "data.srcip": "172." } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "lateral_movement_map": {
      "terms": { "field": "data.srcip", "size": 50 },
      "aggs": {
        "destinations": {
          "terms": { "field": "agent.name", "size": 30 }
        },
        "users": {
          "terms": { "field": "data.dstuser", "size": 20 }
        },
        "unique_destinations": {
          "cardinality": { "field": "agent.name" }
        },
        "movement_timeline": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" }
        }
      }
    }
  }
}
```

### 7.3 Pass-the-Hash / Pass-the-Ticket

**MITRE ATT&CK: T1550 - Use Alternate Authentication Material**

#### DQL: Pass-the-Hash Detection

```
rule.level >= 10 and rule.groups:"windows" and rule.id:"4624" and data.win.eventdata.logonType:"9" and data.win.eventdata.logonProcessName:"seclogo"
```

#### DSL: Anomalous Authentication Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "match": { "rule.groups": "windows" } },
        { "term": { "rule.id": "4624" } }
      ]
    }
  },
  "aggs": {
    "by_logon_type": {
      "terms": { "field": "data.win.eventdata.logonType", "size": 20 },
      "aggs": {
        "logon_processes": {
          "terms": { "field": "data.win.eventdata.logonProcessName", "size": 20 }
        },
        "users": {
          "terms": { "field": "data.win.eventdata.targetUserName", "size": 30 }
        }
      }
    },
    "suspicious_logons": {
      "filter": {
        "bool": {
          "should": [
            { "term": { "data.win.eventdata.logonType": "9" } },
            { "term": { "data.win.eventdata.logonType": "3" } }
          ],
          "must": [
            { "term": { "data.win.eventdata.logonProcessName": "seclogo" } }
          ]
        }
      },
      "aggs": {
        "by_user": {
          "terms": { "field": "data.win.eventdata.targetUserName", "size": 30 }
        },
        "by_source": {
          "terms": { "field": "data.win.eventdata.ipAddress", "size": 30 }
        }
      }
    }
  }
}
```

### 7.4 WMI/WinRM Lateral Movement

#### DQL: WMI Remote Execution

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.image:"*wmiprvse.exe" or data.win.eventdata.parentImage:"*wmiprvse.exe" or data.win.eventdata.commandLine:"*wmic*" or data.win.eventdata.commandLine:"*Invoke-WmiMethod*")
```

#### DQL: WinRM/PSRemoting

```
rule.level >= 7 and rule.groups:"sysmon" and (data.win.eventdata.image:"*wsmprovhost.exe" or data.win.eventdata.commandLine:"*Enter-PSSession*" or data.win.eventdata.commandLine:"*Invoke-Command*" or data.win.eventdata.commandLine:"*New-PSSession*")
```

### 7.5 SMB/Admin Share Access

#### DQL: Admin Share Access

```
rule.level >= 7 and rule.groups:"windows" and (rule.id:"5140" or rule.id:"5145") and (data.win.eventdata.shareName:"*ADMIN$*" or data.win.eventdata.shareName:"*C$*" or data.win.eventdata.shareName:"*IPC$*")
```

---

## Section 8: Collection & Exfiltration

Detect data collection and unauthorized data transfers.

### 8.1 Data Staging & Archive Creation

**MITRE ATT&CK: T1074 - Data Staged, T1560 - Archive Collected Data**

#### DQL: Archive Creation Detection
*Detects creation of compressed archives that may indicate data staging*

```
rule.level >= 5 and (rule.groups:"sysmon" or rule.groups:"syscheck") and (data.win.eventdata.targetFilename:"*.zip" or data.win.eventdata.targetFilename:"*.rar" or data.win.eventdata.targetFilename:"*.7z" or data.win.eventdata.targetFilename:"*.tar*" or data.win.eventdata.commandLine:"*compress*" or data.win.eventdata.commandLine:"*zip*" or data.win.eventdata.commandLine:"*rar*")
```

#### DSL: Data Staging Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } }
      ],
      "should": [
        { "wildcard": { "data.win.eventdata.targetFilename": "*.zip" } },
        { "wildcard": { "data.win.eventdata.targetFilename": "*.rar" } },
        { "wildcard": { "data.win.eventdata.targetFilename": "*.7z" } },
        { "wildcard": { "data.win.eventdata.targetFilename": "*.tar*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*compress*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*zip*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*tar *" } }
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {
    "by_host": {
      "terms": { "field": "agent.name", "size": 30 },
      "aggs": {
        "archive_files": {
          "terms": { "field": "data.win.eventdata.targetFilename.keyword", "size": 30 }
        },
        "creating_processes": {
          "terms": { "field": "data.win.eventdata.image", "size": 20 }
        },
        "users": {
          "terms": { "field": "data.win.eventdata.user", "size": 10 }
        }
      }
    },
    "staging_locations": {
      "filter": {
        "bool": {
          "should": [
            { "wildcard": { "data.win.eventdata.targetFilename": "*temp*" } },
            { "wildcard": { "data.win.eventdata.targetFilename": "*tmp*" } },
            { "wildcard": { "data.win.eventdata.targetFilename": "*public*" } },
            { "wildcard": { "data.win.eventdata.targetFilename": "*appdata*" } }
          ]
        }
      }
    }
  }
}
```

### 8.2 DNS Tunneling Detection

**MITRE ATT&CK: T1071.004 - DNS**

#### DQL: Suspicious DNS Activity
*Detects DNS queries that may indicate tunneling*

```
rule.level >= 7 and (rule.groups:"dns" or rule.groups:"named") and (rule.description:"*unusual*" or rule.description:"*suspicious*" or rule.description:"*tunnel*" or rule.description:"*long*query*")
```

#### DSL: DNS Anomaly Detection

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "exists": { "field": "data.query" } }
      ],
      "should": [
        { "match": { "rule.groups": "dns" } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "data.srcip", "size": 50 },
      "aggs": {
        "query_count": { "value_count": { "field": "data.query" } },
        "unique_queries": { "cardinality": { "field": "data.query" } },
        "query_types": {
          "terms": { "field": "data.type", "size": 20 }
        },
        "hourly_distribution": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" }
        }
      }
    }
  }
}
```

### 8.3 Unusual Data Transfers

**MITRE ATT&CK: T1041 - Exfiltration Over C2 Channel**

#### DQL: Large Data Transfer Detection

```
rule.level >= 7 and (rule.groups:"network" or rule.groups:"firewall") and (rule.description:"*large*transfer*" or rule.description:"*high*volume*" or rule.description:"*unusual*traffic*")
```

#### DSL: Network Traffic Volume Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "exists": { "field": "data.bytes" } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "data.srcip", "size": 50 },
      "aggs": {
        "total_bytes": { "sum": { "field": "data.bytes" } },
        "destinations": {
          "terms": { "field": "data.dstip", "size": 20 },
          "aggs": {
            "bytes_transferred": { "sum": { "field": "data.bytes" } }
          }
        },
        "ports_used": {
          "terms": { "field": "data.dstport", "size": 20 }
        }
      }
    },
    "external_transfers": {
      "filter": {
        "bool": {
          "must_not": [
            { "prefix": { "data.dstip": "10." } },
            { "prefix": { "data.dstip": "192.168." } },
            { "prefix": { "data.dstip": "172." } }
          ]
        }
      },
      "aggs": {
        "by_destination": {
          "terms": { "field": "data.dstip", "size": 30 },
          "aggs": {
            "total_bytes": { "sum": { "field": "data.bytes" } }
          }
        }
      }
    }
  }
}
```

### 8.4 Cloud Storage Exfiltration

#### DQL: Cloud Storage Upload Detection

```
rule.level >= 5 and (rule.groups:"sysmon" or rule.groups:"network") and (data.url:"*dropbox*" or data.url:"*drive.google*" or data.url:"*onedrive*" or data.url:"*box.com*" or data.url:"*mega.nz*" or data.url:"*wetransfer*" or data.url:"*pastebin*")
```

---

## Section 9: Command & Control

Detect communication between compromised systems and attacker infrastructure.

### 9.1 Beaconing Detection

**MITRE ATT&CK: T1071 - Application Layer Protocol**

#### DSL: Beaconing Pattern Detection
*Identifies regular interval connections indicative of C2 beaconing*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "exists": { "field": "data.dstip" } }
      ],
      "must_not": [
        { "prefix": { "data.dstip": "10." } },
        { "prefix": { "data.dstip": "192.168." } },
        { "prefix": { "data.dstip": "172." } }
      ]
    }
  },
  "aggs": {
    "by_source_destination": {
      "composite": {
        "size": 100,
        "sources": [
          { "src": { "terms": { "field": "data.srcip" } } },
          { "dst": { "terms": { "field": "data.dstip" } } }
        ]
      },
      "aggs": {
        "connection_count": { "value_count": { "field": "@timestamp" } },
        "hourly_distribution": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "10m" }
        },
        "time_stats": {
          "stats": { "field": "@timestamp" }
        },
        "ports_used": {
          "terms": { "field": "data.dstport", "size": 10 }
        }
      }
    }
  }
}
```

### 9.2 Non-Standard Port Communication

**MITRE ATT&CK: T1571 - Non-Standard Port**

#### DQL: Suspicious Port Usage
*Detects communication on uncommon ports*

```
rule.level >= 5 and (rule.groups:"firewall" or rule.groups:"network") and not (data.dstport:"80" or data.dstport:"443" or data.dstport:"22" or data.dstport:"53" or data.dstport:"25" or data.dstport:"110" or data.dstport:"143" or data.dstport:"993" or data.dstport:"995" or data.dstport:"587" or data.dstport:"123" or data.dstport:"389" or data.dstport:"636" or data.dstport:"3389")
```

#### DSL: Non-Standard Port Analysis

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "exists": { "field": "data.dstport" } }
      ],
      "must_not": [
        { "terms": { "data.dstport": [80, 443, 22, 53, 25, 110, 143, 993, 995, 587, 123, 389, 636, 3389, 445, 139, 88, 464, 3268, 3269] } }
      ]
    }
  },
  "aggs": {
    "unusual_ports": {
      "terms": { "field": "data.dstport", "size": 50 },
      "aggs": {
        "source_ips": {
          "terms": { "field": "data.srcip", "size": 20 }
        },
        "destination_ips": {
          "terms": { "field": "data.dstip", "size": 20 }
        },
        "connection_count": { "value_count": { "field": "@timestamp" } }
      }
    },
    "high_ports_external": {
      "filter": {
        "bool": {
          "must": [
            { "range": { "data.dstport": { "gte": 1024 } } }
          ],
          "must_not": [
            { "prefix": { "data.dstip": "10." } },
            { "prefix": { "data.dstip": "192.168." } },
            { "prefix": { "data.dstip": "172." } }
          ]
        }
      },
      "aggs": {
        "by_port": {
          "terms": { "field": "data.dstport", "size": 30 }
        }
      }
    }
  }
}
```

### 9.3 Known Malicious Indicators

**MITRE ATT&CK: T1090 - Proxy**

#### DQL: Known C2 Port Detection
*Detects communication on ports commonly used by malware*

```
rule.level >= 7 and (data.dstport:"4444" or data.dstport:"5555" or data.dstport:"6666" or data.dstport:"7777" or data.dstport:"8888" or data.dstport:"9999" or data.dstport:"1234" or data.dstport:"31337" or data.dstport:"12345" or data.dstport:"54321" or data.dstport:"6667" or data.dstport:"6697")
```

### 9.4 Encoded/Encrypted Communication

#### DQL: Base64 in Network Traffic

```
rule.level >= 7 and (rule.groups:"sysmon" or rule.groups:"network") and (data.url:"*base64*" or data.url:"*==" or data.win.eventdata.commandLine:"*[Convert]::FromBase64*")
```

---

## Section 10: Advanced Analytics & Correlation

Advanced queries for threat hunting and security analytics.

### 10.1 Multi-Stage Attack Detection

#### DSL: Attack Chain Correlation
*Correlates multiple attack stages from same source*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "range": { "rule.level": { "gte": 5 } } },
        { "exists": { "field": "data.srcip" } }
      ]
    }
  },
  "aggs": {
    "attack_chains": {
      "terms": { "field": "data.srcip", "size": 30, "min_doc_count": 3 },
      "aggs": {
        "attack_phases": {
          "filters": {
            "filters": {
              "reconnaissance": { "terms": { "rule.groups": ["scan", "reconnaissance", "discovery"] } },
              "initial_access": { "terms": { "rule.groups": ["exploit", "attack", "brute_force"] } },
              "execution": { "terms": { "rule.groups": ["process", "sysmon", "command"] } },
              "persistence": { "terms": { "rule.groups": ["registry", "service", "scheduled_task"] } },
              "privilege_escalation": { "terms": { "rule.groups": ["privilege_escalation", "sudo", "elevation"] } },
              "credential_access": { "terms": { "rule.groups": ["authentication_failed", "credential", "password"] } },
              "lateral_movement": { "terms": { "rule.groups": ["lateral_movement", "remote", "rdp", "ssh"] } },
              "exfiltration": { "terms": { "rule.groups": ["exfiltration", "transfer", "upload"] } }
            }
          }
        },
        "timeline": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "30m" },
          "aggs": {
            "attack_types": {
              "terms": { "field": "rule.groups", "size": 5 }
            }
          }
        },
        "targeted_hosts": {
          "terms": { "field": "agent.name", "size": 20 }
        },
        "severity_trend": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" },
          "aggs": {
            "avg_severity": { "avg": { "field": "rule.level" } },
            "max_severity": { "max": { "field": "rule.level" } }
          }
        }
      }
    }
  }
}
```

### 10.2 MITRE ATT&CK Coverage Analysis

#### DSL: MITRE Technique Distribution

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } },
        { "exists": { "field": "rule.mitre.id" } }
      ]
    }
  },
  "aggs": {
    "by_tactic": {
      "terms": { "field": "rule.mitre.tactic", "size": 20 },
      "aggs": {
        "techniques": {
          "terms": { "field": "rule.mitre.id", "size": 50 },
          "aggs": {
            "technique_name": {
              "terms": { "field": "rule.mitre.technique", "size": 1 }
            },
            "affected_hosts": {
              "cardinality": { "field": "agent.name" }
            },
            "severity_stats": {
              "stats": { "field": "rule.level" }
            }
          }
        }
      }
    },
    "top_techniques": {
      "terms": { "field": "rule.mitre.id", "size": 30 }
    },
    "timeline": {
      "date_histogram": { "field": "@timestamp", "fixed_interval": "1d" },
      "aggs": {
        "unique_techniques": {
          "cardinality": { "field": "rule.mitre.id" }
        }
      }
    }
  }
}
```

### 10.3 Statistical Anomaly Detection

#### DSL: Baseline Deviation Analysis
*Compares current activity against historical baseline*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "range": { "@timestamp": { "gte": "now-7d" } }
  },
  "aggs": {
    "daily_baseline": {
      "date_histogram": { "field": "@timestamp", "fixed_interval": "1d" },
      "aggs": {
        "alert_count": { "value_count": { "field": "rule.id" } },
        "unique_rules": { "cardinality": { "field": "rule.id" } },
        "unique_sources": { "cardinality": { "field": "data.srcip" } },
        "avg_severity": { "avg": { "field": "rule.level" } },
        "high_severity_count": {
          "filter": { "range": { "rule.level": { "gte": 10 } } }
        },
        "severity_percentiles": {
          "percentiles": { "field": "rule.level", "percents": [50, 75, 90, 95, 99] }
        }
      }
    },
    "hourly_pattern": {
      "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" },
      "aggs": {
        "alert_count": { "value_count": { "field": "rule.id" } }
      }
    },
    "agent_baseline": {
      "terms": { "field": "agent.name", "size": 50 },
      "aggs": {
        "daily_alerts": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "1d" },
          "aggs": {
            "count": { "value_count": { "field": "rule.id" } }
          }
        },
        "stats": {
          "stats": { "field": "rule.level" }
        }
      }
    }
  }
}
```

### 10.4 Rare Events Detection

#### DSL: Find Rare/Unusual Events

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "range": { "@timestamp": { "gte": "now-30d" } }
  },
  "aggs": {
    "rare_rules": {
      "terms": { "field": "rule.id", "size": 50, "order": { "_count": "asc" } }
    },
    "rare_sources": {
      "terms": { "field": "data.srcip", "size": 50, "order": { "_count": "asc" } }
    }
  }
}
```

---

## Section 11: Incident Response Queries

Queries for active incident investigation and response.

### 11.1 Compromise Assessment

#### DQL: Initial Compromise Indicators
*Broad search for indicators of compromise*

```
rule.level >= 10 and (rule.groups:"attack" or rule.groups:"exploit" or rule.groups:"malware" or rule.groups:"rootkit" or rule.groups:"backdoor" or rule.groups:"trojan" or rule.groups:"c2" or rule.groups:"lateral_movement" or rule.groups:"credential_access" or rule.groups:"exfiltration")
```

#### DSL: Full Compromise Assessment

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } },
        { "range": { "rule.level": { "gte": 7 } } }
      ]
    }
  },
  "aggs": {
    "compromise_indicators": {
      "filters": {
        "filters": {
          "malware": { "match": { "rule.groups": "malware" } },
          "rootkit": { "match": { "rule.groups": "rootkit" } },
          "backdoor": { "match": { "rule.groups": "backdoor" } },
          "exploit": { "match": { "rule.groups": "exploit" } },
          "credential_theft": { "match": { "rule.groups": "credential" } },
          "lateral_movement": { "match": { "rule.groups": "lateral_movement" } },
          "data_exfiltration": { "match": { "rule.groups": "exfiltration" } },
          "c2_communication": { "match": { "rule.groups": "c2" } }
        }
      }
    },
    "affected_hosts": {
      "terms": { "field": "agent.name", "size": 100 },
      "aggs": {
        "critical_alerts": {
          "filter": { "range": { "rule.level": { "gte": 12 } } }
        },
        "attack_types": {
          "terms": { "field": "rule.groups", "size": 20 }
        },
        "first_seen": { "min": { "field": "@timestamp" } },
        "last_seen": { "max": { "field": "@timestamp" } }
      }
    },
    "external_ips_involved": {
      "filter": {
        "bool": {
          "must_not": [
            { "prefix": { "data.srcip": "10." } },
            { "prefix": { "data.srcip": "192.168." } },
            { "prefix": { "data.srcip": "172." } }
          ]
        }
      },
      "aggs": {
        "ips": {
          "terms": { "field": "data.srcip", "size": 50 }
        }
      }
    }
  }
}
```

### 11.2 IOC Hunting

#### DQL: Hunt for Specific IP
*Replace IP_ADDRESS with your IOC*

```
data.srcip:"IP_ADDRESS" or data.dstip:"IP_ADDRESS" or data.win.eventdata.ipAddress:"IP_ADDRESS" or data.win.eventdata.destinationIp:"IP_ADDRESS"
```

#### DQL: Hunt for Specific File Hash
*Replace HASH_VALUE with your IOC (MD5, SHA1, or SHA256)*

```
data.win.eventdata.hashes:"*HASH_VALUE*" or syscheck.md5_after:"HASH_VALUE" or syscheck.sha1_after:"HASH_VALUE" or syscheck.sha256_after:"HASH_VALUE"
```

#### DQL: Hunt for Specific Domain/URL
*Replace DOMAIN with your IOC*

```
data.url:"*DOMAIN*" or data.query:"*DOMAIN*" or data.win.eventdata.queryName:"*DOMAIN*" or data.win.eventdata.destinationHostname:"*DOMAIN*"
```

#### DQL: Hunt for Specific Filename
*Replace FILENAME with your IOC*

```
syscheck.path:"*FILENAME*" or data.win.eventdata.targetFilename:"*FILENAME*" or data.win.eventdata.image:"*FILENAME*" or data.win.eventdata.commandLine:"*FILENAME*"
```

#### DSL: Multi-IOC Hunt
*Comprehensive IOC search across multiple fields*

```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "should": [
        { "terms": { "data.srcip": ["IOC_IP_1", "IOC_IP_2", "IOC_IP_3"] } },
        { "terms": { "data.dstip": ["IOC_IP_1", "IOC_IP_2", "IOC_IP_3"] } },
        { "wildcard": { "data.win.eventdata.hashes": "*IOC_HASH*" } },
        { "wildcard": { "syscheck.md5_after": "*IOC_HASH*" } },
        { "wildcard": { "data.url": "*IOC_DOMAIN*" } },
        { "wildcard": { "data.query": "*IOC_DOMAIN*" } },
        { "wildcard": { "data.win.eventdata.commandLine": "*IOC_FILENAME*" } },
        { "wildcard": { "syscheck.path": "*IOC_FILENAME*" } }
      ],
      "minimum_should_match": 1
    }
  },
  "sort": [{ "@timestamp": { "order": "desc" } }],
  "_source": ["@timestamp", "agent.name", "rule.description", "rule.level", "data.srcip", "data.dstip", "data.url", "syscheck.path"]
}
```

### 11.3 Timeline Reconstruction

#### DSL: Incident Timeline for Specific Host
*Replace HOSTNAME with the compromised system*

```json
GET wazuh-alerts-*/_search
{
  "size": 1000,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "term": { "agent.name": "HOSTNAME" } }
      ]
    }
  },
  "sort": [{ "@timestamp": { "order": "asc" } }],
  "_source": ["@timestamp", "rule.description", "rule.level", "rule.groups", "rule.mitre.id", "rule.mitre.technique", "data.srcip", "data.dstip", "data.srcuser", "data.dstuser", "data.command", "syscheck.path"]
}
```

#### DSL: Activity Timeline for Specific IP
*Replace ATTACKER_IP with the suspicious IP*

```json
GET wazuh-alerts-*/_search
{
  "size": 1000,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } }
      ],
      "should": [
        { "term": { "data.srcip": "ATTACKER_IP" } },
        { "term": { "data.dstip": "ATTACKER_IP" } },
        { "term": { "data.win.eventdata.ipAddress": "ATTACKER_IP" } }
      ],
      "minimum_should_match": 1
    }
  },
  "sort": [{ "@timestamp": { "order": "asc" } }],
  "_source": ["@timestamp", "agent.name", "rule.description", "rule.level", "rule.groups", "data.srcip", "data.dstip", "data.srcport", "data.dstport"]
}
```

### 11.4 Scope Determination

#### DSL: Determine Attack Scope
*Find all systems affected by specific attacker*

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-30d" } } },
        { "term": { "data.srcip": "ATTACKER_IP" } }
      ]
    }
  },
  "aggs": {
    "affected_systems": {
      "terms": { "field": "agent.name", "size": 100 },
      "aggs": {
        "attack_types": {
          "terms": { "field": "rule.groups", "size": 20 }
        },
        "first_contact": { "min": { "field": "@timestamp" } },
        "last_contact": { "max": { "field": "@timestamp" } },
        "severity_max": { "max": { "field": "rule.level" } },
        "users_targeted": {
          "terms": { "field": "data.dstuser", "size": 20 }
        }
      }
    },
    "attack_timeline": {
      "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" },
      "aggs": {
        "hosts_affected": {
          "cardinality": { "field": "agent.name" }
        }
      }
    }
  }
}
```

### 11.5 Evidence Collection

#### DSL: Export All Events for Specific Incident
*Comprehensive data export for forensics*

```json
GET wazuh-alerts-*/_search
{
  "size": 10000,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "2024-01-01T00:00:00Z", "lte": "2024-01-02T00:00:00Z" } } }
      ],
      "should": [
        { "term": { "agent.name": "AFFECTED_HOST" } },
        { "term": { "data.srcip": "ATTACKER_IP" } }
      ],
      "minimum_should_match": 1
    }
  },
  "sort": [{ "@timestamp": { "order": "asc" } }]
}
```

---

## Quick Reference - Wazuh Rule IDs

### SSH Rules (5xxx)
| Rule ID | Description |
|---------|-------------|
| 5701-5710 | SSH connection events |
| 5711 | SSH brute force attack |
| 5712 | SSH multiple authentication failures |
| 5720 | SSH authentication success |
| 5758-5763 | SSH related attacks |

### Web Attack Rules (31xxx)
| Rule ID | Description |
|---------|-------------|
| 31101-31110 | ModSecurity events |
| 31151-31154 | Apache DoS/flooding |
| 31161-31174 | Web attack patterns |
| 31501-31520 | SQL injection, XSS, RFI/LFI |

### Windows Security Rules (60xxx)
| Rule ID | Description |
|---------|-------------|
| 60001-60020 | Windows authentication |
| 60100-60120 | Windows security events |
| 60122 | Windows brute force |
| 60204 | Multiple Windows logon failures |

### Sysmon Rules
| Rule ID | Description |
|---------|-------------|
| 60003 | Process creation |
| 60004 | Registry modification |
| 60006 | Service installation |
| 60008 | Process access |
| 60010 | LSASS access |
| 60014 | Registry value set |
| 60103 | Scheduled task creation |

### File Integrity Rules (550-559)
| Rule ID | Description |
|---------|-------------|
| 550 | File added |
| 551 | File modified |
| 552 | File deleted |
| 553 | File integrity checksum changed |
| 554 | Registry modification |

### Rootcheck Rules (510-519)
| Rule ID | Description |
|---------|-------------|
| 510 | Rootkit detected |
| 511-519 | Various rootkit indicators |

### Common Rule Groups
```
attack, exploit, authentication_failed, invalid_login
brute_force, dos, ddos, sql_injection, xss, web
malware, rootkit, trojan, backdoor, virus
scan, reconnaissance, privilege_escalation
lateral_movement, credential_access, exfiltration
syscheck, fim, sysmon, windows, sshd, sudo
```

---

## DQL vs DSL Syntax Reference

### DQL Syntax (Threat Hunting Interface)

```
# Basic field matching
rule.level >= 7
rule.groups:"attack"
agent.name:"web-server-01"

# Wildcards
data.srcip:"192.168.*"
rule.description:"*injection*"

# Boolean operators (lowercase works)
rule.groups:"attack" and rule.level >= 7
rule.groups:"attack" or rule.groups:"exploit"
rule.groups:"attack" and not agent.name:"test-*"

# Grouping
(rule.groups:"attack" or rule.groups:"exploit") and rule.level >= 7

# Range
rule.level >= 5 and rule.level <= 10
```

### DSL Syntax (Dev Tools Interface)

```json
// Basic structure
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": { ... },
  "sort": [{ "@timestamp": { "order": "desc" } }],
  "_source": ["field1", "field2"],
  "aggs": { ... }
}

// Query types
{ "match": { "field": "value" } }
{ "term": { "field": "exact_value" } }
{ "terms": { "field": ["value1", "value2"] } }
{ "range": { "field": { "gte": 7, "lte": 10 } } }
{ "wildcard": { "field": "*pattern*" } }
{ "exists": { "field": "field_name" } }
{ "prefix": { "field": "prefix_" } }

// Boolean combinations
{
  "bool": {
    "must": [ ... ],
    "should": [ ... ],
    "must_not": [ ... ],
    "filter": [ ... ],
    "minimum_should_match": 1
  }
}

// Aggregations
{
  "aggs": {
    "name": {
      "terms": { "field": "field_name", "size": 20 }
    }
  }
}
```

---

## Severity Levels Reference

| Level | Severity | Description |
|-------|----------|-------------|
| 0-3 | Informational | Normal activity, no action needed |
| 4-6 | Low | Minor issues, monitor |
| 7-9 | Medium | Potential security issue, investigate |
| 10-11 | High | Security incident, immediate investigation |
| 12-15 | Critical | Active attack, immediate response |

---

## Common Fields Reference

| Field | Description | Example |
|-------|-------------|---------|
| `@timestamp` | Event timestamp | `"gte": "now-24h"` |
| `agent.name` | Agent hostname | `agent.name:"web-server-01"` |
| `agent.id` | Agent ID | `agent.id:"001"` |
| `rule.id` | Wazuh rule ID | `rule.id:"5711"` |
| `rule.level` | Severity (0-15) | `rule.level >= 7` |
| `rule.groups` | Rule categories | `rule.groups:"attack"` |
| `rule.description` | Rule text | `rule.description:"*brute*"` |
| `rule.mitre.id` | MITRE technique | `rule.mitre.id:"T1110"` |
| `data.srcip` | Source IP | `data.srcip:"192.168.1.100"` |
| `data.dstip` | Destination IP | `data.dstip:"10.0.0.1"` |
| `data.srcport` | Source port | `data.srcport:22` |
| `data.dstport` | Destination port | `data.dstport:443` |
| `data.srcuser` | Source user | `data.srcuser:"admin"` |
| `data.dstuser` | Destination user | `data.dstuser:"root"` |
| `syscheck.path` | FIM file path | `syscheck.path:"/etc/passwd"` |
| `syscheck.event` | FIM event type | `syscheck.event:"modified"` |
| `data.win.eventdata.*` | Windows event data | Various Windows fields |

---

## Performance Tips

1. **Always use time ranges** - Limit queries to relevant time periods
2. **Avoid leading wildcards** - `*attack*` is slower than `attack*`
3. **Use specific fields** - Query specific fields rather than full-text search
4. **Limit result size** - Use `"size": 100` instead of unlimited
5. **Use filters for exact matches** - Filters are cached and faster
6. **Aggregate efficiently** - Set reasonable `size` values in aggregations

---

## License

This query reference guide is provided for educational and operational use in security operations.

---

## Contributing

Feel free to submit additional queries, improvements, or corrections.

---

**Created for Wazuh SIEM v4.11.2**
