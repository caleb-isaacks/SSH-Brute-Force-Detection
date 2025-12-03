# SSH-Brute-Force-Detection
# Splunk Detection Rule: SSH Brute Force Attempt  
Author: Caleb Isaacks  

## Overview  
This project demonstrates how to build a Splunk detection rule that identifies SSH brute-force activity against a Linux host.  
The detection logic aggregates failed authentication attempts from a single source IP and correlates them with any successful login that follows.  
This rule is implemented as a scheduled alert in Splunk, running every minute for testing, with a recommended production interval of five minutes.

---

## Objective  
- Detect brute-force SSH activity using Splunk SPL  
- Aggregate failed login attempts in a defined time window  
- Correlate brute-force activity with successful logins  
- Implement the logic as a scheduled Splunk alert  
- Produce documentation suitable for a SOC or detection engineering role  

---

## Data Source  
- Linux authentication log (auth.log)  
- Index: `auth_logs`  
- Source Type: `linux_secure`  

---

## Detection Logic (SPL)  
This SPL assumes that Splunk field extractions were created for:
- `username`  
- `src_ip`  

```spl
index=auth_logs ("Failed password" OR "Accepted password")
| eval event_type=case(
    searchmatch("Failed password"), "failed",
    searchmatch("Accepted password"), "success"
)
| bin _time span=5m
| stats 
    count(eval(event_type="failed")) AS failed_attempts
    count(eval(event_type="success")) AS success_count
    values(username) AS targeted_users
BY src_ip, _time
| where failed_attempts >= 5 OR success_count > 0
| sort _time
```
<img width="798" height="839" alt="Pasted Graphic 1" src="https://github.com/user-attachments/assets/edef7ba7-31ac-4676-9b95-d77d803d1c43" />
<img width="1705" height="613" alt="Pasted Graphic 2" src="https://github.com/user-attachments/assets/614d6205-090e-41db-83b0-cadc00a15323" />
<img width="1708" height="552" alt="Pasted Graphic 3" src="https://github.com/user-attachments/assets/f73c9afc-962d-4834-8956-ceea82363ec6" />

