<img width="1791" height="763" alt="image" src="https://github.com/user-attachments/assets/974d84b7-9abd-4018-9266-a5063d676bac" />

<img width="1732" height="686" alt="image" src="https://github.com/user-attachments/assets/8295451b-3b22-4a6e-b2b7-8afce0d80210" />

# Practical Implementation Guide: Advanced Wazuh Queries on v4.11.2

<img width="2355" height="948" alt="image" src="https://github.com/user-attachments/assets/b44b077b-59a4-4084-a850-8b9ec87c3244" />

This guide translates the queries from your "Advanced Wazuh Security Analytics Professional Guide" into practical, actionable steps for Wazuh 4.11.2.

---

## Understanding Query Interfaces in Wazuh 4.11.2

Wazuh 4.11.2 has **three main query interfaces**, each using different syntax:

| Interface | Location | Query Syntax | Use Case |
|-----------|----------|--------------|----------|
| **Threat Hunting / Discover** | Threat Intelligence → Threat Hunting | DQL (Lucene-based) | Security event investigation |
| **WQL Search Bars** | Agents, Rules, MITRE tabs | WQL (Wazuh Query Language) | Filtering dashboard data |
| **Dev Tools** | Indexer Management → Dev Tools | Elasticsearch DSL (JSON) | Advanced/API queries |

---

## 1. Accessing the Query Interfaces

### 1.1 Threat Hunting (Primary Investigation Interface)

**Navigation Path:**
```
Wazuh Dashboard → Threat Intelligence → Threat Hunting
```

Or directly from:
```
Overview → Events tab
```

This interface uses **DQL (Dashboard Query Language)** which is Lucene-based syntax - the same syntax shown in your PDF document.

### 1.2 Discover (Raw Log Search)

**Navigation Path:**
```
Hamburger Menu (☰) → Discover
```

Select the appropriate index pattern:
- `wazuh-alerts-*` for alerts
- `wazuh-archives-*` for all events (if enabled)

### 1.3 Dev Tools (Advanced Queries)

**Navigation Path:**
```
Hamburger Menu (☰) → Indexer Management → Dev Tools
```

---

## 2. Executing Queries from Your Document

### 2.1 Basic Query Syntax (Threat Hunting/Discover)

The queries in your PDF use Lucene syntax. Here's how to execute them:

**Step 1:** Navigate to Threat Hunting or Discover

**Step 2:** Locate the search bar at the top

**Step 3:** Ensure the query language is set correctly:
- Click the language selector (often shows "DQL" or "Lucene")
- Select "DQL" or "Lucene" (both work similarly)

**Step 4:** Paste your query and press Enter

---

## 3. Query Examples - Practical Implementation

### 3.1 Boolean Logic Queries

**From your document (Section 2.1):**
```
(rule.groups:"web_application_attack" AND rule.level:>=7) OR (rule.groups:"exploit" AND agent.status:"active")
```

**Wazuh 4.11.2 Implementation:**

1. Open Threat Hunting
2. Set time range (top right) - e.g., "Last 24 hours"
3. Paste query in search bar
4. Press Enter or click "Refresh"

**Alternative using filters:**
- Click "+ Add filter"
- Field: `rule.groups`
- Operator: `is`
- Value: `web_application_attack`
- Save filter, then add additional filters

### 3.2 Negation Queries (Section 2.3)

**From your document:**
```
rule.groups:"web_application_attack" NOT agent.name:"internal-*" NOT data.srcip:"10.*" NOT data.srcip:"172.16.*"
```

**Practical Steps:**
1. Navigate to Threat Hunting
2. Paste the query exactly as shown
3. The NOT operator excludes internal sources

### 3.3 Time-Based Queries (Section 4)

**Rolling Time Windows:**
```
timestamp:[now-24h TO now] AND rule.level:>=7
```

**In Wazuh 4.11.2:**
1. You can use the time picker in the top-right instead
2. Click the time picker → select "Last 24 hours"
3. Then use: `rule.level:>=7`

**Specific Assessment Window:**
```
timestamp:[2024-01-15T08:00:00Z TO 2024-01-15T18:00:00Z] AND (rule.groups:"attack" OR rule.groups:"exploit")
```

For this, use the time picker's "Absolute" option to set specific dates.

### 3.4 Agent-Based Queries (Section 6)

**Server Group Queries:**
```
agent.name:"web-*" AND rule.groups:"web_application_attack"
```

**Attack Correlation:**
```
(agent.name:"web-01" OR agent.name:"web-02" OR agent.name:"app-01") AND data.srcip:"192.168.1.100" AND rule.groups:"attack"
```
```
rule.level >= 7 and (rule.groups:"attack" or rule.groups:"exploit" or rule.groups:"authentication_failed" or rule.groups:"invalid_login" or rule.groups:"brute_force" or rule.groups:"dos" or rule.groups:"ddos" or rule.groups:"sql_injection" or rule.groups:"web" or rule.groups:"intrusion_detection" or rule.groups:"rootkit" or rule.groups:"malware" or rule.groups:"trojan" or rule.groups:"backdoor" or rule.groups:"scan" or rule.groups:"reconnaissance")
```

```
rule.level >= 10 and (rule.groups:"attack" or rule.groups:"exploit" or rule.groups:"authentication_failed" or rule.groups:"brute_force" or rule.groups:"rootkit" or rule.groups:"malware" or rule.groups:"trojan" or rule.groups:"backdoor" or rule.groups:"intrusion_detection")
```

```
rule.level >= 5 and (rule.groups:"authentication_failed" or rule.groups:"invalid_login" or rule.groups:"brute_force" or rule.groups:"authentication_success" or rule.groups:"login" or rule.groups:"pam" or rule.groups:"sshd" or rule.groups:"win_authentication_failed")
```

```
rule.level >= 5 and (rule.groups:"web" or rule.groups:"attack" or rule.groups:"sql_injection" or rule.groups:"xss" or rule.groups:"csrf" or rule.groups:"web_application_attack" or rule.groups:"apache" or rule.groups:"nginx" or rule.groups:"accesslog")
```

```
rule.level >= 5 and (rule.groups:"malware" or rule.groups:"rootkit" or rule.groups:"trojan" or rule.groups:"backdoor" or rule.groups:"virus" or rule.groups:"worm" or rule.groups:"ransomware" or rule.groups:"suspicious_file")
```

```
rule.level >= 5 and (rule.groups:"scan" or rule.groups:"reconnaissance" or rule.groups:"network_scan" or rule.groups:"port_scan" or rule.groups:"nmap" or rule.groups:"discovery" or rule.groups:"enumeration")
```

```
rule.level >= 7 and (rule.groups:"privilege_escalation" or rule.groups:"lateral_movement" or rule.groups:"sudo" or rule.groups:"su" or rule.groups:"admin" or rule.groups:"root" or rule.groups:"elevation")
```

```
rule.level >= 7 and (rule.groups:"syscheck" or rule.groups:"fim" or rule.groups:"file_integrity" or rule.groups:"file_modified" or rule.groups:"file_added" or rule.groups:"file_deleted")
```

```
rule.level >= 5 and (rule.groups:"windows" or rule.groups:"win_authentication_failed" or rule.groups:"windows_security" or rule.groups:"powershell" or rule.groups:"sysmon" or rule.groups:"win_eventlog")
```

```
rule.level >= 5 and (rule.groups:"firewall" or rule.groups:"iptables" or rule.groups:"drop" or rule.groups:"deny" or rule.groups:"block" or rule.groups:"reject" or rule.groups:"connection_refused")
```

```
rule.level >= 5 and (rule.groups:"policy_violation" or rule.groups:"anomaly" or rule.groups:"suspicious" or rule.groups:"violation" or rule.groups:"compliance" or rule.groups:"audit")
```

```
rule.level >= 5 and (rule.groups:"config_changed" or rule.groups:"system_audit" or rule.groups:"service" or rule.groups:"process" or rule.groups:"package" or rule.groups:"user_management")
```

```
rule.level >= 7 and (rule.groups:"data_exfiltration" or rule.groups:"exfiltration" or rule.groups:"suspicious_connection" or rule.groups:"outbound" or rule.groups:"upload" or rule.groups:"transfer")
```

```
rule.level >= 5 and (rule.groups:"dos" or rule.groups:"ddos" or rule.groups:"flood" or rule.groups:"rate_limit" or rule.groups:"connection_flood" or rule.groups:"syn_flood")
```

```
rule.level >= 5 and (rule.groups:"sshd" or rule.groups:"ssh" or rule.groups:"ssh_authentication" or rule.groups:"invalid_login" or rule.groups:"ssh_brute_force")
```

```
rule.level >= 12
```

**Practical Tip:** To find your agent names:
1. Go to Endpoints → Endpoint Summary
2. Note the exact agent names
3. Substitute them in your queries

### 3.5 Severity Level Queries (Section 7)

**Critical Alerts:**
```
rule.level:[13 TO 15]
```

**High-Risk Attacks:**
```
rule.level:[7 TO 12] AND (rule.groups:"exploit" OR rule.groups:"malware" OR rule.groups:"backdoor" OR rule.groups:"trojan")
```

---

## 4. Using Dev Tools for Elasticsearch DSL Queries

For complex queries or API integration, use Dev Tools with JSON syntax.

### 4.1 Accessing Dev Tools

```
Hamburger Menu → Indexer Management → Dev Tools
```

### 4.2 Converting Lucene to Elasticsearch DSL

**Lucene Query:**
```
rule.level:>=10 AND rule.groups:"exploit"
```

**Elasticsearch DSL Equivalent:**
```json
GET wazuh-alerts-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "rule.level": { "gte": 10 } } },
        { "match": { "rule.groups": "exploit" } }
      ]
    }
  },
  "size": 100,
  "sort": [{ "@timestamp": { "order": "desc" } }]
}
```

### 4.3 Aggregation Queries (For Statistics)

**Count attacks by rule group:**
```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h",
        "lte": "now"
      }
    }
  },
  "aggs": {
    "by_rule_group": {
      "terms": {
        "field": "rule.groups",
        "size": 20
      }
    }
  }
}
```

**Top attacker IPs:**
```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "rule.level": { "gte": 7 } } }
      ],
      "must_not": [
        { "prefix": { "data.srcip": "10." } },
        { "prefix": { "data.srcip": "192.168." } },
        { "prefix": { "data.srcip": "172.16." } }
      ]
    }
  },
  "aggs": {
    "top_attackers": {
      "terms": {
        "field": "data.srcip",
        "size": 10
      }
    }
  }
}
```

---

## 5. Assessment-Specific Query Templates

### 5.1 Web Application Penetration Test

**Step-by-Step:**

1. **Set the assessment time window:**
   - Use time picker → Absolute → Set start/end dates

2. **Run the query:**
```
agent.name:"web-*" AND (rule.groups:"web_application_attack" OR rule.groups:"sql_injection" OR rule.groups:"xss" OR rule.groups:"csrf") AND rule.level:>=5
```

3. **Add columns for analysis:**
   - Click on a result to expand
   - Click "+" next to fields like `rule.description`, `data.srcip`, `data.url`

### 5.2 Network Penetration Test

```
(rule.groups:"scan" OR rule.groups:"exploit" OR rule.groups:"network_attack" OR rule.groups:"privilege_escalation") AND rule.level:>=7
```

### 5.3 Lateral Movement Detection

```
(data.srcip:"10.*" AND data.dstip:"10.*") AND (rule.groups:"authentication_failed" OR rule.groups:"lateral_movement" OR rule.groups:"exploit")
```

### 5.4 Data Exfiltration Detection

```
(data.dstport:443 OR data.dstport:53 OR data.dstport:8080 OR data.dstport:4444) AND rule.level:>=5 NOT agent.name:"approved-*"
```

### 5.5 Persistence Mechanism Detection

```
(rule.groups:"backdoor" OR rule.groups:"persistence" OR rule.groups:"rootkit" OR rule.groups:"scheduled_task") AND rule.level:>=6
```

---

## 6. Saving and Reusing Queries

### 6.1 Saving Searches in Discover

1. Run your query
2. Click "Save" in the top toolbar
3. Name your search (e.g., "Web_App_SQL_Injection_Detection")
4. Click "Save"

### 6.2 Loading Saved Searches

1. Click "Open" in the toolbar
2. Select your saved search
3. The query and filters are restored

### 6.3 Creating Dashboards

1. Go to Dashboard → Create new dashboard
2. Click "Add" → "Add from library"
3. Select saved searches to add as visualizations

---

## 7. Performance Optimization Tips for Wazuh 4.11.2

### 7.1 Always Use Time Ranges

**Slow (scans all history):**
```
rule.groups:"attack"
```

**Fast (limited scope):**
```
rule.groups:"attack"
```
+ Set time picker to "Last 24 hours" or specific dates

### 7.2 Avoid Leading Wildcards

**Slow:**
```
rule.description:*injection*
```

**Faster:**
```
rule.groups:"sql_injection"
```

### 7.3 Use Specific Fields

**Less efficient:**
```
SQL injection
```

**More efficient:**
```
rule.description:"SQL injection" OR rule.groups:"sql_injection"
```

---

## 8. Common Field Reference for Wazuh 4.11.2

| Field | Type | Example |
|-------|------|---------|
| `agent.name` | keyword | `agent.name:"web-server-01"` |
| `agent.id` | keyword | `agent.id:"001"` |
| `rule.id` | keyword | `rule.id:"5710"` |
| `rule.level` | number | `rule.level:[7 TO 15]` |
| `rule.groups` | keyword | `rule.groups:"authentication_failed"` |
| `rule.description` | text | `rule.description:"brute force"` |
| `data.srcip` | IP | `data.srcip:"192.168.1.*"` |
| `data.dstip` | IP | `data.dstip:"10.0.0.1"` |
| `data.srcport` | number | `data.srcport:22` |
| `data.dstport` | number | `data.dstport:443` |
| `@timestamp` | date | Use time picker |

---

## 9. Troubleshooting

### 9.1 No Results Returned

1. **Check time range** - Extend it (Last 7 days, Last 30 days)
2. **Verify field names** - Click search bar to see autocomplete suggestions
3. **Check agent names** - Go to Endpoints → Endpoint Summary
4. **Simplify query** - Start with one condition, add more

### 9.2 Query Syntax Errors

- Ensure quotes match: `"value"` not `"value`
- Check parentheses balance
- Use uppercase for operators: `AND`, `OR`, `NOT`

### 9.3 Performance Issues

- Add time range constraints
- Reduce wildcard usage
- Use Discover's "Toggle New Discover" option if the new interface is slow

---

## 10. Quick Reference Card

**Basic Search:**
```
rule.groups:"attack"
```

**Multiple Conditions (AND):**
```
rule.groups:"attack" AND rule.level:>=7
```

**Either Condition (OR):**
```
rule.groups:"attack" OR rule.groups:"exploit"
```

**Exclude Results (NOT):**
```
rule.groups:"attack" NOT agent.name:"test-*"
```

**Range:**
```
rule.level:[5 TO 10]
```

**Wildcard:**
```
agent.name:"web-*"
```

**Grouped Conditions:**
```
(rule.groups:"attack" OR rule.groups:"exploit") AND rule.level:>=7
```
